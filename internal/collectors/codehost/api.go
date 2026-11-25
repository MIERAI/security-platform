// Package codehost is what the codehost-github and codehost-gitea collectors share: a read-only JSON client for a
// code host's REST API (internal/collectors/roclient: GET only, no redirect to another origin), page following that
// never leaves the configured server, API error texts, Python's urllib.parse.quote and fnmatch.fnmatchcase.
package codehost

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/roclient"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// MaxPages bounds how many pages one listing reads (a server that always says "next" cannot keep a run going).
const MaxPages = 1000

// Errors a caller tells apart.
var (
	ErrOtherOrigin = errors.New("a page link points to another server: not followed")
	ErrNotJSON     = errors.New("the answer is not JSON")
	ErrTooManyPage = fmt.Errorf("more than %d pages", MaxPages)
)

// HTTPError is an answer that is not 2xx.
type HTTPError struct {
	Status      int
	Message     string // the API's "message", if any
	RateLimited bool   // 429, or 403 with X-RateLimit-Remaining: 0 or Retry-After
}

func (e *HTTPError) Error() string {
	if e.Message == "" {
		return "HTTP " + strconv.Itoa(e.Status)
	}
	return "HTTP " + strconv.Itoa(e.Status) + ": " + e.Message
}

// Status returns the HTTP status of err (0 when it is not an HTTP answer).
func Status(err error) int {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

// Client reads one API (base URL without a trailing slash).
type Client struct {
	rc     *roclient.Client
	base   *url.URL
	prefix string
}

// Options configure a client.
type Options struct {
	Base      string // e.g. https://api.github.com, https://git.example.com/api/v1
	Header    http.Header
	CAFile    string
	Timeout   time.Duration
	Transport http.RoundTripper // tests
}

// New builds a client for one API.
func New(o Options) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(o.Base, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("API URL %q: not an http(s) URL", o.Base)
	}
	rc, err := roclient.New(roclient.Options{Timeout: o.Timeout, Header: o.Header, CAFile: o.CAFile, Transport: o.Transport})
	if err != nil {
		return nil, fmt.Errorf("API client: %w", err)
	}
	return &Client{rc: rc, base: u, prefix: u.String()}, nil
}

// Page is one answer: the JSON value and the headers that say where the next page is.
type Page struct {
	Value  any
	Header http.Header
}

// Get reads path (relative to the base URL; or an absolute URL of the same origin, as page links are).
func (c *Client) Get(ctx context.Context, path string) (*Page, error) {
	target := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		target = c.prefix + path
	} else if err := c.sameOrigin(path); err != nil {
		return nil, err
	}
	res, err := c.rc.Get(ctx, target)
	if err != nil {
		return nil, err
	}
	var v any
	if strings.TrimSpace(string(res.Body)) != "" {
		if v, err = pyvalue.DecodeJSON(res.Body); err != nil && res.Status/100 == 2 {
			return nil, fmt.Errorf("%s: %w", redact(target), ErrNotJSON)
		}
	}
	if res.Status/100 != 2 {
		return nil, &HTTPError{Status: res.Status, Message: rundoc.Cut(rundoc.Str(rundoc.Get(v, "message")), 160),
			RateLimited: res.Status == http.StatusTooManyRequests || res.Status == http.StatusForbidden &&
				(res.Header.Get("X-RateLimit-Remaining") == "0" || res.Header.Get("Retry-After") != "")}
	}
	return &Page{Value: v, Header: res.Header}, nil
}

func (c *Client) sameOrigin(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != c.base.Scheme || u.Host != c.base.Host {
		return fmt.Errorf("%w (%s)", ErrOtherOrigin, redact(raw))
	}
	return nil
}

func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<url>"
	}
	return u.Scheme + "://" + u.Host + u.Path
}

// GetAll reads a listing page by page: first, then every Link rel="next" (same origin only). When the server sends no
// Link, X-Total-Count decides (more pages while fewer items were read), else a page shorter than pageSize is the last;
// next(page) builds the path of page n for those two cases ("" = no such path: stop).
func (c *Client) GetAll(ctx context.Context, first string, pageSize int, next func(page int) string) ([]any, error) {
	var out []any
	path := first
	for page := 1; ; page++ {
		if page > MaxPages {
			return nil, ErrTooManyPage
		}
		p, err := c.Get(ctx, path)
		if err != nil {
			return nil, err
		}
		items := rundoc.List(p.Value)
		out = append(out, items...)
		if link := NextLink(p.Header.Values("Link")); link != "" {
			path = link
			continue
		}
		if lastPage(p, len(items), len(out), pageSize) || next == nil {
			return out, nil
		}
		if path = next(page + 1); path == "" {
			return out, nil
		}
	}
}

// linkNext is never written after initialisation.
var linkNext = regexp.MustCompile(`<([^<>]*)>\s*;[^,<]*\brel="?next"?`)

// NextLink is the rel="next" target of Link header values ("" when there is none).
func NextLink(values []string) string {
	for _, v := range values {
		if m := linkNext.FindStringSubmatch(v); m != nil {
			return m[1]
		}
	}
	return ""
}

// Quote is Python's urllib.parse.quote(s) (safe "/"): every byte but letters, digits and _.-~/ percent-encoded.
func Quote(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_.-~/", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// lastPage decides, for a page without a Link next, whether the listing is complete: a server that paginates by Link
// has no next page; else X-Total-Count says, else a page shorter than the page size is the last.
func lastPage(p *Page, items, read, pageSize int) bool {
	if len(p.Header.Values("Link")) > 0 || items == 0 {
		return true
	}
	if total, err := strconv.Atoi(p.Header.Get("X-Total-Count")); err == nil {
		return read >= total
	}
	return items < pageSize
}
