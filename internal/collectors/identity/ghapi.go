package identity

import (
	"context"
	"crypto/sha1" // #nosec G505 -- the cache file name, as the Python adapter names it; not a security use
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

const (
	maxPages     = 100      // pages of one listing (100 entries each by default)
	maxCacheFile = 64 << 20 // one cached answer
)

var linkNextRE = regexp.MustCompile(`<([^>]*)>\s*;\s*rel="?next"?`)

// ghAPI reads the code host's REST API for one account: conditional requests with the Python adapter's ETag cache
// (<cache>/<user>/<sha1(path)>.json: {"etag", "body", "headers"}), pages through Link headers, and stops calling
// once the API said the rate limit is exhausted. The token goes into the Authorization header only.
type ghAPI struct {
	base    *url.URL
	token   string
	cache   string // "" = no cache
	client  *http.Client
	limited string // the rate-limit reason, once hit
	agent   string
}

// ghAnswer is one answer: data is nil with err set when the call failed (err is the gap reason).
type ghAnswer struct {
	data    pyjson.Value
	err     string
	headers map[string]string // x-oauth-scopes, github-authentication-token-expiration
	link    string            // the Link header (pagination)
	partial bool              // a listing cut at maxPages
}

func (g *ghAPI) cachePath(path string) string {
	if g.cache == "" {
		return ""
	}
	sum := sha1.Sum([]byte(path)) // #nosec G401 -- see the import
	return filepath.Join(g.cache, hex.EncodeToString(sum[:])+".json")
}

type cached struct {
	etag    string
	body    pyjson.Value
	headers map[string]string
}

func readCache(p string) *cached {
	if p == "" {
		return nil
	}
	data, err := rundoc.ReadLimited(p, maxCacheFile)
	if err != nil {
		return nil
	}
	v, err := pyjson.Decode(data)
	if err != nil {
		return nil
	}
	etag, _ := get(v, "etag").(string) // a cache file without an ETag is never sent as a condition
	return &cached{etag: etag, body: get(v, "body"), headers: stringMap(get(v, "headers"))}
}

func stringMap(v pyjson.Value) map[string]string {
	out := map[string]string{}
	if o, ok := v.(*pyjson.Object); ok && o != nil {
		for _, k := range o.Keys() {
			x, _ := o.Get(k)
			if s, isStr := x.(string); isStr {
				out[k] = s
			}
		}
	}
	return out
}

func (g *ghAPI) writeCache(p, etag string, body pyjson.Value, headers map[string]string) {
	if p == "" {
		return
	}
	h := pyjson.NewObject()
	for _, k := range []string{"x-oauth-scopes", "github-authentication-token-expiration", "link"} {
		if v, ok := headers[k]; ok {
			h.Set(k, v)
		}
	}
	data, err := pyjson.Marshal(object("etag", etag, "body", body, "headers", h), pyjson.Compact())
	if err != nil || rundoc.MkdirPrivate(filepath.Dir(p)) != nil {
		return // the cache is an optimisation: without it the next run asks again
	}
	if err := rundoc.WriteFile(p, data); err != nil {
		return // same: a failed cache write only costs a full request next time
	}
}

// get is one GET of path (relative to the API base, with its query), as the Python adapter's GitHubAPI.get.
func (g *ghAPI) get(ctx context.Context, path string) ghAnswer {
	if g.limited != "" {
		return ghAnswer{err: g.limited}
	}
	cp := g.cachePath(path)
	c := readCache(cp)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.base.String()+path, http.NoBody)
	if err != nil {
		return ghAnswer{err: "request: " + err.Error()}
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", g.agent)
	if g.token != "" {
		req.Header.Set("Authorization", "Bearer "+g.token)
	}
	if c != nil && c.etag != "" {
		req.Header.Set("If-None-Match", c.etag)
	}
	resp, err := do(ctx, g.client, req)
	if err != nil {
		return ghAnswer{err: "HTTP 0: " + rundoc.Cut(err.Error(), 160)}
	}
	return g.answer(resp, path, c, cp)
}

func (g *ghAPI) answer(resp *response, path string, c *cached, cp string) ghAnswer {
	headers := keptHeaders(resp.header)
	if resp.status == http.StatusNotModified && c != nil {
		return fromCache(resp, c)
	}
	if reason, limited := rateLimited(resp); limited {
		g.limited = reason
		return ghAnswer{err: reason, headers: headers}
	}
	if resp.status != http.StatusOK {
		return ghAnswer{err: "HTTP " + strconv.Itoa(resp.status) + ": " + rundoc.Cut(errMessage(resp), 160) +
			scopeHint(resp.header), headers: headers}
	}
	var data pyjson.Value
	if strings.TrimSpace(string(resp.body)) != "" {
		v, err := pyjson.Decode(resp.body)
		if err != nil {
			return ghAnswer{err: fmt.Sprintf("JSONDecodeError: %s answered no JSON", path), headers: headers}
		}
		data = v
	}
	link := resp.header.Get("Link")
	if etag := resp.header.Get("Etag"); etag != "" {
		g.writeCache(cp, etag, data, withLink(headers, link))
	}
	return ghAnswer{data: data, headers: headers, link: link}
}

// fromCache answers a 304 from the cached body; the Link header is the answer's, else the cached one.
func fromCache(resp *response, c *cached) ghAnswer {
	link := resp.header.Get("Link")
	if link == "" {
		link = c.headers["link"]
	}
	kept := map[string]string{}
	for k, v := range c.headers {
		if k != "link" {
			kept[k] = v
		}
	}
	return ghAnswer{data: c.body, headers: kept, link: link}
}

func withLink(headers map[string]string, link string) map[string]string {
	out := map[string]string{}
	for k, v := range headers {
		out[k] = v
	}
	if link != "" {
		out["link"] = link
	}
	return out
}

func keptHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for _, k := range []string{"x-oauth-scopes", "github-authentication-token-expiration"} {
		if v := h.Values(k); len(v) > 0 {
			out[k] = strings.TrimSpace(v[0])
		}
	}
	return out
}

// errMessage is the API's "message", or the body's text.
func errMessage(resp *response) string {
	if v, err := pyjson.Decode(resp.body); err == nil {
		if o, ok := v.(*pyjson.Object); ok {
			return pyStr(get(o, "message"))
		}
	}
	return strings.TrimSpace(strings.ToValidUTF8(string(resp.body), "�"))
}

// scopeHint names the OAuth scope a 403/404 asked for (X-Accepted-OAuth-Scopes) and what the token has.
func scopeHint(h http.Header) string {
	want := strings.TrimSpace(h.Get("X-Accepted-OAuth-Scopes"))
	if want == "" {
		return ""
	}
	have := strings.TrimSpace(h.Get("X-OAuth-Scopes"))
	if have == "" {
		have = "none"
	}
	return " (needs scope " + want + "; the token has " + have + ")"
}

// rateLimited recognises an exhausted rate limit: 403/429 with X-RateLimit-Remaining 0 or Retry-After.
func rateLimited(resp *response) (string, bool) {
	if resp.status != http.StatusForbidden && resp.status != http.StatusTooManyRequests {
		return "", false
	}
	remaining, retry := resp.header.Get("X-RateLimit-Remaining"), resp.header.Get("Retry-After")
	if remaining != "0" && retry == "" {
		return "", false
	}
	if reset, err := strconv.ParseInt(resp.header.Get("X-RateLimit-Reset"), 10, 64); err == nil && reset > 0 {
		return "rate limited until " + time.Unix(reset, 0).UTC().Format("2006-01-02T15:04:05Z"), true
	}
	if secs, err := strconv.Atoi(retry); err == nil {
		return "rate limited (retry after " + strconv.Itoa(secs) + " s)", true
	}
	return "rate limited", true
}

// getAll reads a listing to its end: the first page at path, then every Link rel="next" on the same host.
func (g *ghAPI) getAll(ctx context.Context, path string) ghAnswer {
	first := g.get(ctx, path)
	items, isList := first.data.([]pyjson.Value)
	if first.err != "" || !isList {
		return first
	}
	next := g.nextPage(first.link)
	for pages := 1; next != ""; pages++ {
		if pages >= maxPages {
			return ghAnswer{data: items, headers: first.headers, partial: true}
		}
		a := g.get(ctx, next)
		if a.err != "" {
			return ghAnswer{err: a.err, headers: first.headers}
		}
		items = append(items, list(a.data)...)
		next = g.nextPage(a.link)
	}
	return ghAnswer{data: items, headers: first.headers}
}

// nextPage is the path of the next page named by a Link header ("" when there is none, or when it points to
// another host: the token is never sent anywhere but the configured API).
func (g *ghAPI) nextPage(link string) string {
	m := linkNextRE.FindStringSubmatch(link)
	if m == nil {
		return ""
	}
	u, err := url.Parse(m[1])
	if err != nil || u.Scheme != g.base.Scheme || u.Host != g.base.Host || !strings.HasPrefix(u.Path, g.base.Path) {
		return ""
	}
	return strings.TrimPrefix(u.RequestURI(), g.base.Path)
}
