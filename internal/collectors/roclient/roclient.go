// Package roclient is the HTTP client of the Go collectors: read-only by construction. Only GET and HEAD leave the
// process (any other method is refused before anything is sent, ErrMutating); a redirect to another origin, or from
// https to http, is not followed (the credential headers would go with it); response bodies are read through a size
// limit; every request carries a context with a deadline.
package roclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// Defaults.
const (
	DefaultTimeout = 30 * time.Second
	DefaultMaxBody = 32 << 20
	maxRedirects   = 5
	maxCAFile      = 1 << 20
)

// Errors a caller tells apart.
var (
	ErrMutating     = errors.New("refused: a collector sends only GET/HEAD requests")
	ErrRedirect     = errors.New("redirect to another origin not followed")
	ErrBodyTooLarge = errors.New("response body over the size limit")
)

// Options configure a client.
type Options struct {
	Timeout   time.Duration     // per request; DefaultTimeout when 0
	MaxBody   int64             // DefaultMaxBody when 0
	Header    http.Header       // sent with every request (Accept, Authorization, User-Agent)
	CAFile    string            // extra trusted CA certificates (PEM)
	Transport http.RoundTripper // tests; http.DefaultTransport's settings otherwise
}

// Client sends read-only requests.
type Client struct {
	http    *http.Client
	header  http.Header
	timeout time.Duration
	maxBody int64
}

// Response is a read response: status, headers and the whole (bounded) body.
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// New builds a client.
func New(o Options) (*Client, error) {
	base := o.Transport
	if base == nil {
		t, err := transport(o.CAFile)
		if err != nil {
			return nil, err
		}
		base = t
	}
	c := &Client{header: o.Header.Clone(), timeout: o.Timeout, maxBody: o.MaxBody}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	if c.maxBody <= 0 {
		c.maxBody = DefaultMaxBody
	}
	c.http = &http.Client{Transport: guard{next: base}, CheckRedirect: sameOrigin}
	return c, nil
}

func transport(caFile string) (*http.Transport, error) {
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default transport is not an *http.Transport")
	}
	t = t.Clone()
	if caFile == "" {
		return t, nil
	}
	pem, err := readCA(caFile)
	if err != nil {
		return nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("ca_file %s: no PEM certificate", caFile)
	}
	t.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return t, nil
}

func readCA(path string) (data []byte, err error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			data, err = nil, fmt.Errorf("ca_file: close: %w", cerr)
		}
	}()
	data, err = io.ReadAll(io.LimitReader(f, maxCAFile))
	if err != nil {
		return nil, fmt.Errorf("ca_file: %w", err)
	}
	return data, nil
}

// ReadOnly wraps a transport so that only GET and HEAD requests are sent; any other method fails with ErrMutating
// before anything leaves the process.
func ReadOnly(next http.RoundTripper) http.RoundTripper { return guard{next: next} }

// guard refuses every method but GET and HEAD before the request leaves the process.
type guard struct{ next http.RoundTripper }

func (g guard) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		err := fmt.Errorf("%s %s: %w", req.Method, req.URL.Path, ErrMutating)
		if req.Body != nil { // never sent; RoundTrip must close it
			if cerr := req.Body.Close(); cerr != nil {
				return nil, errors.Join(err, cerr)
			}
		}
		return nil, err
	}
	return g.next.RoundTrip(req)
}

// sameOrigin follows a redirect only to the same scheme, host and port.
func sameOrigin(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	first := via[0].URL
	if req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
		return fmt.Errorf("%w (to %s)", ErrRedirect, origin(req.URL))
	}
	return nil
}

func origin(u *url.URL) string { return u.Scheme + "://" + u.Host }

// Get sends GET url and reads the whole response (any status).
func (c *Client) Get(ctx context.Context, rawURL string) (*Response, error) {
	return c.Do(ctx, http.MethodGet, rawURL, nil)
}

// Do sends a request with the client's headers plus extra. Only GET and HEAD are ever sent (ErrMutating).
func (c *Client) Do(ctx context.Context, method, rawURL string, extra http.Header) (res *Response, err error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, rawURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}
	for k, vs := range c.header {
		req.Header[k] = append([]string(nil), vs...)
	}
	for k, vs := range extra {
		req.Header[k] = append([]string(nil), vs...)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, redact(req.URL), unwrapURL(err))
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			res, err = nil, fmt.Errorf("%s %s: close body: %w", method, redact(req.URL), cerr)
		}
	}()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("%s %s: read body: %w", method, redact(req.URL), err)
	}
	if int64(len(body)) > c.maxBody {
		return nil, fmt.Errorf("%s %s: %w", method, redact(req.URL), ErrBodyTooLarge)
	}
	return &Response{Status: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

// redact is the URL without its query and user information (a query may carry anything the caller built).
func redact(u *url.URL) string {
	return u.Scheme + "://" + u.Host + u.Path
}

// unwrapURL drops *url.Error (its text repeats the full URL) and keeps the cause.
func unwrapURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
