package vulnintel

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

const (
	userAgent      = "security-platform-feeds/0.3.0" // as adapters/feeds.py: mirrors see one client
	requestTimeout = 300 * time.Second
	maxMetaFile    = 1 << 20
	maxRedirects   = 5
)

var errNotModified = errors.New("not modified")

// fetcher downloads feeds into the cache (adapters/feeds.py fetch(), same files): a copy younger than its maximum
// age is used without asking; otherwise a conditional GET (If-None-Match / If-Modified-Since); a 304 keeps the copy.
// A new payload is checked (size limit, then the feed's own parser) BEFORE it replaces the cached copy, and when a
// refresh fails or is rejected a cached copy stays in use, with a warning (VULN-D2, VULN-D3).
type fetcher struct {
	client *http.Client
	now    func() time.Time
}

type fetchSpec struct {
	url, path string
	maxAgeH   float64
	maxBytes  int64
	headers   map[string]string
}

// fetched is where a feed's copy came from.
type fetched struct {
	checkedAt float64 // when the copy was last confirmed current (epoch seconds)
	warn      string  // non-empty: the refresh failed or was rejected; this is the older copy
}

func newFetcher(client *http.Client, now func() time.Time) *fetcher {
	if client == nil {
		tr, _ := http.DefaultTransport.(*http.Transport) // the standard library's own type
		tr = tr.Clone()
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		client = &http.Client{Transport: tr}
	}
	c := *client
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return errors.New("too many redirects")
		}
		return checkURL(req.URL)
	}
	return &fetcher{client: &c, now: now}
}

// checkURL allows HTTPS, and plain HTTP only to a loopback address (a local mirror): feeds decide priorities, so
// nobody on the path may change them.
func checkURL(u *url.URL) error {
	if u.Scheme == "https" && u.Host != "" {
		return nil
	}
	if u.Scheme == "http" && isLoopback(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("refused %s URL of host %q: https required (plain http only to a loopback address)", u.Scheme, u.Hostname())
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

type cacheMeta struct {
	obj       *pyjson.Object // the meta file as written ({etag, last_modified, url, checked_at})
	checkedAt float64
}

func readMeta(path string) (*cacheMeta, bool) {
	if _, err := os.Stat(path); err != nil {
		return nil, false
	}
	data, err := rundoc.ReadLimited(path+".meta.json", maxMetaFile)
	if err != nil {
		return nil, false
	}
	v, err := pyjson.Decode(data)
	o := obj(v)
	if err != nil || o == nil || o.Len() == 0 {
		return nil, false
	}
	f, _ := pyjson.Float(get(o, "checked_at")) // absent: 0, as meta.get("checked_at", 0)
	return &cacheMeta{obj: o, checkedAt: f}, true
}

func (f *fetcher) epoch() float64 { return float64(f.now().UnixNano()) / 1e9 }

func writeMeta(path string, o *pyjson.Object) error {
	data, err := pyjson.Marshal(o, pyjson.Compact())
	if err != nil {
		return fmt.Errorf("encode cache metadata: %w", err)
	}
	return rundoc.WriteFile(path+".meta.json", data)
}

// fetchParse returns the feed parsed from its newest acceptable copy.
func fetchParse[T any](ctx context.Context, f *fetcher, s *fetchSpec, parse func(string) (T, error)) (T, fetched, error) {
	var zero T
	meta, cached := readMeta(s.path)
	if cached && f.epoch()-meta.checkedAt < s.maxAgeH*3600 {
		v, err := parse(s.path)
		return v, fetched{checkedAt: meta.checkedAt}, err
	}
	v, at, err := refresh(ctx, f, s, meta, parse)
	if err == nil {
		return v, fetched{checkedAt: at}, nil
	}
	if _, serr := os.Stat(s.path); serr != nil {
		return zero, fetched{}, err
	}
	old := fileTime(s.path)
	if meta != nil {
		old = meta.checkedAt
	}
	v, perr := parse(s.path)
	if perr != nil {
		return zero, fetched{}, err
	}
	return v, fetched{checkedAt: old, warn: fmt.Sprintf("%v: using the copy confirmed at %s", err, isoEpoch(old))}, nil
}

func fileTime(p string) float64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return float64(fi.ModTime().UnixNano()) / 1e9
}

func isoEpoch(t float64) string { return rundoc.ISO(time.Unix(int64(math.Floor(t)), 0)) }

// errRejected marks a download that arrived but is not acceptable (too large, does not parse).
var errRejected = errors.New("download rejected")

// refresh asks the source and returns the new (or revalidated) copy, parsed, and when it was confirmed.
func refresh[T any](ctx context.Context, f *fetcher, s *fetchSpec, meta *cacheMeta, parse func(string) (T, error)) (T, float64, error) {
	var zero T
	resp, err := f.request(ctx, s, meta)
	if errors.Is(err, errNotModified) {
		now := f.epoch()
		meta.obj.Set("checked_at", now)
		if werr := writeMeta(s.path, meta.obj); werr != nil {
			return zero, 0, werr
		}
		v, perr := parse(s.path)
		return v, now, perr
	}
	if err != nil {
		return zero, 0, err
	}
	v, perr := parse(s.path + ".tmp")
	if perr != nil {
		_ = os.Remove(s.path + ".tmp") // #nosec G104 -- the rejected payload is not kept; the reason is reported
		return zero, 0, fmt.Errorf("%w: %w", errRejected, perr)
	}
	if err := os.Rename(s.path+".tmp", s.path); err != nil {
		return zero, 0, fmt.Errorf("replace cached feed: %w", err)
	}
	now := f.epoch()
	m := pyjson.ObjectOf("etag", headerOrNone(resp, "ETag"), "last_modified", headerOrNone(resp, "Last-Modified"),
		"url", s.url, "checked_at", now)
	return v, now, writeMeta(s.path, m)
}

func headerOrNone(h http.Header, key string) pyjson.Value {
	if v := h.Values(key); len(v) > 0 {
		return v[0]
	}
	return nil
}

// request sends the conditional GET and stores a 2xx body at <path>.tmp (bounded). It returns the response headers,
// errNotModified for a 304, or why the refresh failed.
func (f *fetcher) request(ctx context.Context, s *fetchSpec, meta *cacheMeta) (http.Header, error) {
	u, err := url.Parse(s.url)
	if err != nil {
		return nil, fmt.Errorf("refresh failed: bad URL: %w", err)
	}
	if uerr := checkURL(u); uerr != nil {
		return nil, fmt.Errorf("refresh failed: %w", uerr)
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("refresh failed: %w", err)
	}
	req.Header.Set("User-Agent", userAgent)
	for k, v := range s.headers {
		req.Header.Set(k, v)
	}
	if meta != nil {
		if et := sget(meta.obj, "etag"); et != "" {
			req.Header.Set("If-None-Match", et)
		}
		if lm := sget(meta.obj, "last_modified"); lm != "" {
			req.Header.Set("If-Modified-Since", lm)
		}
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // #nosec G104 -- a read error below is what matters
	return f.save(resp, s, meta != nil)
}

func (f *fetcher) save(resp *http.Response, s *fetchSpec, cached bool) (http.Header, error) {
	switch {
	case resp.StatusCode == http.StatusNotModified && cached:
		return resp.Header, errNotModified
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return nil, fmt.Errorf("refresh failed: HTTP %d from %s", resp.StatusCode, resp.Request.URL.Host)
	}
	if err := rundoc.MkdirPrivate(filepath.Dir(s.path)); err != nil {
		return nil, err
	}
	out, err := os.OpenFile(s.path+".tmp", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- the cache path
	if err != nil {
		return nil, fmt.Errorf("refresh failed: %w", err)
	}
	n, err := io.Copy(out, io.LimitReader(resp.Body, s.maxBytes+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	switch {
	case err != nil:
		_ = os.Remove(s.path + ".tmp") // #nosec G104 -- incomplete download
		return nil, fmt.Errorf("refresh failed: %w", err)
	case n > s.maxBytes:
		_ = os.Remove(s.path + ".tmp") // #nosec G104 -- over the limit
		return nil, fmt.Errorf("%w: larger than %d bytes (max_bytes)", errRejected, s.maxBytes)
	}
	return resp.Header, nil
}
