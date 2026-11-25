package roclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// server fails the test on any method but GET/HEAD reaching it and counts the requests.
func server(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			t.Errorf("a %s request reached the server", r.Method)
		}
		h(w, r)
	}))
	t.Cleanup(s.Close)
	return s, &n
}

func TestOnlyGetAndHeadLeave(t *testing.T) {
	t.Parallel()
	s, n := server(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	c, err := New(Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, "PROPFIND"} {
		if _, err := c.Do(context.Background(), m, s.URL+"/x", nil); !errors.Is(err, ErrMutating) {
			t.Errorf("%s: %v, want ErrMutating", m, err)
		}
	}
	if n.Load() != 0 {
		t.Fatalf("%d requests reached the server", n.Load())
	}
	for _, m := range []string{http.MethodGet, http.MethodHead} {
		if _, err := c.Do(context.Background(), m, s.URL+"/x", nil); err != nil {
			t.Errorf("%s: %v", m, err)
		}
	}
}

func TestRedirects(t *testing.T) {
	t.Parallel()
	var other string
	s, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/same":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/other":
			http.Redirect(w, r, other+"/final", http.StatusFound)
		case "/final":
			_, _ = w.Write([]byte(r.Header.Get("Authorization")))
		}
	})
	leak, hits := server(t, func(_ http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("the credential followed a redirect to another origin")
		}
	})
	other = leak.URL
	c, err := New(Options{Header: http.Header{"Authorization": {"token canary-0123"}}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Get(context.Background(), s.URL+"/same")
	if err != nil || string(res.Body) != "token canary-0123" {
		t.Fatalf("same origin: %v %v", res, err)
	}
	if _, err := c.Get(context.Background(), s.URL+"/other"); !errors.Is(err, ErrRedirect) {
		t.Fatalf("other origin: %v, want ErrRedirect", err)
	}
	if hits.Load() != 0 {
		t.Fatal("the other origin was contacted")
	}
}

func TestBodyLimitAndErrorsHideQuery(t *testing.T) {
	t.Parallel()
	s, _ := server(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 100))) })
	c, err := New(Options{MaxBody: 10})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Get(context.Background(), s.URL+"/big?access_token=canary-0123")
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("%v, want ErrBodyTooLarge", err)
	}
	if strings.Contains(err.Error(), "canary") {
		t.Fatalf("the query is in the error: %v", err)
	}
}

func TestCAFile(t *testing.T) {
	t.Parallel()
	if _, err := New(Options{CAFile: "/nonexistent/ca.pem"}); err == nil {
		t.Error("a missing CA file is an error")
	}
}
