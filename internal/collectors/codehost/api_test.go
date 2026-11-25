package codehost

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/MIERAI/security-platform/internal/collectors/roclient"
)

func TestFnmatchCase(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, pat string
		want      bool
	}{
		{"main", "main", true}, {"release/v1", "release/*", true}, {"release/a/b", "release/*", true},
		{"release", "release/*", false}, {"dev1", "dev?", true}, {"dev", "dev?", false}, {"b", "[abc]", true},
		{"d", "[!abc]", true}, {"a", "[!abc]", false}, {"m", "[a-z]", true}, {"M", "[a-z]", false}, {"[", "[", true},
		{"]", "[]]", true}, {"x", "[]", false}, {"", "*", true}, {"abc", "a*c*", true}, {"abd", "a*c", false},
		{"a*b", "a[*]b", true}, {"main", "", false}, {"", "", true}, {"aaa", "*a*a*a*", true},
	}
	for _, tt := range tests {
		t.Run(tt.name+"~"+tt.pat, func(t *testing.T) {
			t.Parallel()
			if got := FnmatchCase(tt.name, tt.pat); got != tt.want {
				t.Errorf("FnmatchCase(%q, %q) = %v", tt.name, tt.pat, got)
			}
		})
	}
}

func TestNextLink(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   []string
		want string
	}{
		{[]string{`<https://a/x?page=2>; rel="next", <https://a/x?page=5>; rel="last"`}, "https://a/x?page=2"},
		{[]string{`<https://a/x?page=1>; rel="prev", <https://a/x?page=3>; rel="next"`}, "https://a/x?page=3"},
		{[]string{`<https://a/x?page=5>; rel="last"`}, ""},
		{[]string{"", `<u>;rel=next`}, "u"},
		{nil, ""},
	}
	for _, tt := range tests {
		if got := NextLink(tt.in); got != tt.want {
			t.Errorf("NextLink(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestQuote(t *testing.T) {
	t.Parallel()
	if got := Quote("a b/c?d#é~_.-"); got != "a%20b/c%3Fd%23%C3%A9~_.-" {
		t.Error(got)
	}
}

// TestReadOnly: a non-GET request never reaches the transport.
func TestReadOnly(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	rt := roclient.ReadOnly(roundTrip(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("unreachable")
	}))
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		req, err := http.NewRequestWithContext(context.Background(), m, "http://127.0.0.1/x", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		res, err := rt.RoundTrip(req)
		if res != nil {
			if cerr := res.Body.Close(); cerr != nil {
				t.Error(cerr)
			}
		}
		if !errors.Is(err, roclient.ErrMutating) {
			t.Errorf("%s: %v", m, err)
		}
	}
	if calls.Load() != 0 {
		t.Errorf("%d mutating requests sent", calls.Load())
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newClient(t *testing.T, base string) *Client {
	t.Helper()
	c, err := New(Options{Base: base, Header: http.Header{"Authorization": {"token secret-canary-1"}}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestGetAll(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		headers func(base string, page int) map[string]string
		want    int
	}{
		{"link", func(base string, page int) map[string]string {
			if page < 3 {
				return map[string]string{"Link": fmt.Sprintf(`<%s/x?page=%d>; rel="next"`, base, page+1)}
			}
			return map[string]string{"Link": fmt.Sprintf(`<%s/x?page=1>; rel="first"`, base)}
		}, 6},
		{"total-count", func(string, int) map[string]string { return map[string]string{"X-Total-Count": "6"} }, 6},
		{"short-page", func(string, int) map[string]string { return nil }, 2}, // 2 < page size 50: the last page
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			srv := pageServer(t, tt.headers)
			c := newClient(t, srv.URL)
			items, err := c.GetAll(context.Background(), "/x?page=1", 50, func(p int) string { return fmt.Sprintf("/x?page=%d", p) })
			if err != nil || len(items) != tt.want {
				t.Fatalf("%d items, %v; want %d", len(items), err, tt.want)
			}
		})
	}
}

// TestPageLinkToAnotherServer: a Link that points elsewhere is not followed (the token would go with it).
func TestPageLinkToAnotherServer(t *testing.T) {
	t.Parallel()
	var other atomic.Int32
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { other.Add(1) }))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Link", "<"+elsewhere.URL+`/x?page=2>; rel="next"`)
		_, _ = w.Write([]byte(`[1]`))
	}))
	defer srv.Close()
	_, err := newClient(t, srv.URL).GetAll(context.Background(), "/x", 50, nil)
	if !errors.Is(err, ErrOtherOrigin) || other.Load() != 0 {
		t.Fatalf("err %v, %d requests elsewhere", err, other.Load())
	}
	if strings.Contains(err.Error(), "secret-canary") {
		t.Error("token in the error")
	}
}

func TestHTTPError(t *testing.T) {
	t.Parallel()
	tests := []struct {
		status  int
		headers map[string]string
		limited bool
	}{
		{403, map[string]string{"X-RateLimit-Remaining": "0"}, true}, {403, map[string]string{"Retry-After": "5"}, true},
		{429, nil, true}, {403, nil, false}, {404, nil, false}, {502, nil, false},
	}
	for _, tt := range tests {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			for k, v := range tt.headers {
				w.Header().Set(k, v)
			}
			w.WriteHeader(tt.status)
			_, _ = w.Write([]byte(`{"message": "nope"}`))
		}))
		_, err := newClient(t, srv.URL).Get(context.Background(), "/x")
		srv.Close()
		var he *HTTPError
		if !errors.As(err, &he) || he.Status != tt.status || he.RateLimited != tt.limited || he.Message != "nope" {
			t.Errorf("%d %v: %#v", tt.status, tt.headers, err)
		}
	}
}

func TestNewRejectsNonHTTP(t *testing.T) {
	t.Parallel()
	for _, u := range []string{"file:///etc", "ftp://x", "", "http://"} {
		if _, err := New(Options{Base: u}); err == nil {
			t.Errorf("%q accepted", u)
		}
	}
}

// pageServer serves three pages of two items (then empty pages) with the headers the test gives per page.
func pageServer(t *testing.T, headers func(base string, page int) map[string]string) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method %s", r.Method)
		}
		page := 1
		_, _ = fmt.Sscan(r.URL.Query().Get("page"), &page) // absent: 1
		for k, v := range headers(srv.URL, page) {
			w.Header().Set(k, v)
		}
		if page > 3 {
			_, _ = w.Write([]byte(`[]`))
			return
		}
		_, _ = w.Write([]byte(`[{"n": 1}, {"n": 2}]`))
	}))
	t.Cleanup(srv.Close)
	return srv
}
