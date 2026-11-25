package events

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/roclient"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const (
	maxBody      = 32 << 20
	apiTimeout   = 20 * time.Second
	tokenTimeout = 30 * time.Second
	maxRedirects = 5
)

// errPostRefused is returned for a POST to anything but the push URL or the OAuth token endpoint.
var errPostRefused = errors.New("refused: the shipper POSTs only to the push URL and the OAuth token endpoint")

// methodGuard sends GET and HEAD anywhere (through roclient.ReadOnly) and POST only to the URLs it was given.
type methodGuard struct {
	next  http.RoundTripper
	posts map[string]bool
}

func (g methodGuard) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method == http.MethodPost {
		if g.posts[req.URL.String()] {
			return g.next.RoundTrip(req)
		}
		err := fmt.Errorf("POST %s: %w", redact(req.URL), errPostRefused)
		if req.Body != nil {
			if cerr := req.Body.Close(); cerr != nil {
				return nil, errors.Join(err, cerr)
			}
		}
		return nil, err
	}
	return roclient.ReadOnly(g.next).RoundTrip(req)
}

func redact(u *url.URL) string { return u.Scheme + "://" + u.Host + u.Path }

// newHTTP is the shipper's client: credentials never follow a redirect to another origin (the 3xx answer is
// returned instead), only the given URLs may be POSTed to.
func newHTTP(base http.RoundTripper, posts ...string) *http.Client {
	if base == nil {
		base = http.DefaultTransport
	}
	allowed := map[string]bool{}
	for _, p := range posts {
		allowed[p] = true
	}
	return &http.Client{Transport: methodGuard{next: base, posts: allowed}, CheckRedirect: sameOrigin}
}

func sameOrigin(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects || req.URL.Scheme != via[0].URL.Scheme || req.URL.Host != via[0].URL.Host ||
		via[0].Method != http.MethodGet {
		return http.ErrUseLastResponse
	}
	return nil
}

// response is a whole (bounded) answer.
type response struct {
	status int
	reason string
	header http.Header
	body   []byte
}

func send(ctx context.Context, c *http.Client, req *http.Request, timeout time.Duration) (res *response, err error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resp, err := c.Do(req.WithContext(ctx))
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return nil, pyErr("URLError", "<urlopen error "+err.Error()+">")
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			res, err = nil, pyErr("URLError", "<urlopen error "+cerr.Error()+">")
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, pyErr("URLError", "<urlopen error "+err.Error()+">")
	}
	if len(body) > maxBody {
		return nil, pyErr("URLError", "<urlopen error response over the size limit>")
	}
	reason := strings.TrimSpace(strings.TrimPrefix(resp.Status, fmt.Sprint(resp.StatusCode)))
	return &response{status: resp.StatusCode, reason: reason, header: resp.Header, body: body}, nil
}

// httpError is urllib's HTTPError text.
func httpError(r *response) error {
	return pyErr("HTTPError", fmt.Sprintf("HTTP Error %d: %s", r.status, r.reason))
}

// apiClient is ship.py's HTTP: a JSON GET client with conditional requests, the ETag cache kept in the source state.
type apiClient struct {
	base, token, agent string
	cache              *pyvalue.Map // url -> {etag, body, link}
	http               *http.Client
	calls              int64
}

// apiAnswer is an API answer: 200 with the body and Link for any 2xx and for a 304 answered from the cache,
// (status, nil, "") otherwise.
type apiAnswer struct {
	status int
	body   any
	link   string
}

// get sends one GET (conditional on the cached ETag when asked) and returns the answer, never nil.
func (a *apiClient) get(ctx context.Context, p string, conditional bool) (*apiAnswer, error) {
	u := p
	if !strings.HasPrefix(p, "http") {
		u = a.base + p
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return &apiAnswer{}, pyErr("ValueError", "unknown url type: "+pyvalue.Repr(u))
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", a.agent)
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	var cached *pyvalue.Map
	if conditional {
		cached, _ = a.cache.Value(u).(*pyvalue.Map) // absent or malformed: no conditional request
		if etag := textOf(cached.Value("etag")); etag != "" {
			req.Header.Set("If-None-Match", etag)
		}
	}
	a.calls++
	r, err := send(ctx, a.http, req, apiTimeout)
	if err != nil {
		return &apiAnswer{}, err
	}
	return a.answer(r, u, cached, conditional)
}

func (a *apiClient) answer(r *response, u string, cached *pyvalue.Map, conditional bool) (*apiAnswer, error) {
	if r.status == http.StatusNotModified && pyvalue.Truthy(cached) {
		return &apiAnswer{http.StatusOK, cached.Value("body"), textOf(cached.Value("link"))}, nil
	}
	if r.status < 200 || r.status > 299 {
		return &apiAnswer{status: r.status}, nil
	}
	body, err := decodeBody(r.body)
	if err != nil {
		return &apiAnswer{}, err
	}
	link := r.header.Get("Link")
	if etag := r.header.Get("ETag"); conditional && etag != "" {
		entry := pyvalue.NewMap()
		entry.Set("etag", etag)
		entry.Set("body", body)
		entry.Set("link", link)
		a.cache.Set(u, entry)
	}
	return &apiAnswer{http.StatusOK, body, link}, nil
}

// decodeBody is json.loads(body or b"null").
func decodeBody(b []byte) (any, error) {
	if len(b) == 0 {
		return nil, nil
	}
	v, err := pyvalue.DecodeJSON(b)
	if err != nil {
		return nil, pyErr("JSONDecodeError", err.Error())
	}
	return v, nil
}

// postForm sends an application/x-www-form-urlencoded POST (the OAuth token exchange) and decodes the JSON answer.
func postForm(ctx context.Context, c *http.Client, u, form string) (any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader([]byte(form)))
	if err != nil {
		return nil, pyErr("ValueError", "unknown url type: "+pyvalue.Repr(u))
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := send(ctx, c, req, tokenTimeout)
	if err != nil {
		return nil, err
	}
	if r.status < 200 || r.status > 299 {
		return nil, httpError(r)
	}
	return decodeBody(r.body)
}
