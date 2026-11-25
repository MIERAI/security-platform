package vulnintel

import (
	"context"
	"crypto/sha1" // #nosec G505 -- a cache file name, as adapters/feeds.py names it; not a security use
	"encoding/hex"
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// The public sources (adapters/feeds.py SOURCES). A feed's `url` replaces its source (a mirror); the cache file
// keeps the name of the default source, so a data directory works with either.
const (
	srcKEV      = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	srcEPSS     = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
	srcOSV      = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
	srcAndroid  = "https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip"
	srcApple    = "https://support.apple.com/en-us/100100"
	srcMSRCList = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
	srcMSRCDoc  = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{id}"

	defaultSmall    = 64 << 20 // KEV, EPSS (compressed), Apple pages, MSRC documents
	defaultArchive  = 2 << 30  // OSV / Android exports
	defaultInflated = 4 << 30  // inflated content of one export
	maxEPSSInflated = 1 << 30
)

// intel holds the loaded feed indexes.
type intel struct {
	kev     *kevIndex
	epss    map[string]float64
	osv     osvIndex
	android []*androidEntry
	apple   []*appleRelease
	msrc    *msrcIndex
}

// feedResult is one feed's load: when its copy was confirmed and a warning when it is an older copy.
type feedResult struct {
	fetched
}

type feedConfig struct {
	m       *pyvalue.Map
	typ     string
	dataDir string
}

func (fc *feedConfig) str(key, def string) string {
	if s := rundoc.Str(fc.m.Value(key)); s != "" {
		return s
	}
	return def
}

func (fc *feedConfig) maxAge() float64 { return rundoc.Float(fc.m.Value("max_age_hours"), 24) }

func (fc *feedConfig) maxBytes(def int64) int64 {
	if n := rundoc.Float(fc.m.Value("max_bytes"), 0); n > 0 {
		return int64(n)
	}
	return def
}

func (fc *feedConfig) cache(rel ...string) string {
	return filepath.Join(append([]string{fc.dataDir, "cache", "feeds"}, rel...)...)
}

// loadFeed loads one configured feed into in.
func (c *collector) loadFeed(ctx context.Context, fc *feedConfig, in *intel) (feedResult, error) {
	switch fc.typ {
	case "cisa-kev":
		return c.loadKEV(ctx, fc, in)
	case "epss":
		return c.loadEPSS(ctx, fc, in)
	case "osv":
		return c.loadOSV(ctx, fc, in)
	case "android-bulletins":
		return c.loadAndroid(ctx, fc, in)
	case "apple-security-releases":
		return c.loadApple(ctx, fc, in)
	case "msrc-cvrf":
		return c.loadMSRC(ctx, fc, in)
	case "nvd", "vendor":
		return feedResult{}, fmt.Errorf("NotImplementedError: feed %s is a documented future adapter", pyvalue.Repr(fc.typ))
	default:
		return feedResult{}, fmt.Errorf("KeyError: %s", pyvalue.Repr(fc.typ))
	}
}

func (c *collector) loadKEV(ctx context.Context, fc *feedConfig, in *intel) (feedResult, error) {
	s := &fetchSpec{url: fc.str("url", srcKEV), path: fc.cache(path.Base(srcKEV)), maxAgeH: fc.maxAge(),
		maxBytes: fc.maxBytes(defaultSmall)}
	idx, f, err := fetchParse(ctx, c.fetch, s, func(p string) (*kevIndex, error) {
		data, err := readAll(p, s.maxBytes)
		if err != nil {
			return nil, err
		}
		idx, err := parseKEV(data)
		return idx, err
	})
	if err != nil {
		return feedResult{}, err
	}
	in.kev = idx
	return feedResult{fetched: f}, nil
}

func (c *collector) loadEPSS(ctx context.Context, fc *feedConfig, in *intel) (feedResult, error) {
	s := &fetchSpec{url: fc.str("url", srcEPSS), path: fc.cache(path.Base(srcEPSS)), maxAgeH: fc.maxAge(),
		maxBytes: fc.maxBytes(defaultSmall)}
	idx, f, err := fetchParse(ctx, c.fetch, s, func(p string) (map[string]float64, error) {
		data, err := readAll(p, s.maxBytes)
		if err != nil {
			return nil, err
		}
		raw, err := gunzip(data, maxEPSSInflated)
		if err != nil {
			return nil, err
		}
		idx, err := parseEPSS(raw)
		return idx, err
	})
	if err != nil {
		return feedResult{}, err
	}
	in.epss = idx
	return feedResult{fetched: f}, nil
}

// safeName refuses an ecosystem name that would leave the cache directory.
func safeName(s string) error {
	if s == "" || s == "." || s == ".." || strings.ContainsAny(s, `/\`) {
		return fmt.Errorf("ValueError: unusable ecosystem name %s", pyvalue.Repr(s))
	}
	return nil
}

func (c *collector) loadOSV(ctx context.Context, fc *feedConfig, in *intel) (feedResult, error) {
	ecos := []string{"Go"}
	if v, ok := fc.m.Get("ecosystems"); ok {
		ecos = rundoc.Strings(v)
	}
	idx := osvIndex{}
	res := feedResult{}
	for i, eco := range ecos {
		if err := safeName(eco); err != nil {
			return feedResult{}, err
		}
		s := &fetchSpec{url: strings.ReplaceAll(fc.str("url", srcOSV), "{ecosystem}", eco),
			path: fc.cache("osv", eco, "all.zip"), maxAgeH: fc.maxAge(), maxBytes: fc.maxBytes(defaultArchive)}
		pk, f, err := fetchParse(ctx, c.fetch, s, func(p string) (map[string][]*osvAdv, error) {
			pk := map[string][]*osvAdv{}
			return pk, zipJSON(p, defaultInflated, func(o *pyjson.Object) error { return osvEntry(pk, eco, o) })
		})
		if err != nil {
			return feedResult{}, err
		}
		idx[eco] = pk
		res = mergeFetched(res, f, i == 0)
	}
	if len(ecos) == 0 {
		res.checkedAt = c.epoch()
	}
	in.osv = idx
	return res, nil
}

// mergeFetched keeps the oldest confirmation time and the first warning (osv: min(fetched)).
func mergeFetched(r feedResult, f fetched, firstOne bool) feedResult {
	if firstOne || f.checkedAt < r.checkedAt {
		r.checkedAt = f.checkedAt
	}
	if r.warn == "" {
		r.warn = f.warn
	}
	return r
}

func (c *collector) loadAndroid(ctx context.Context, fc *feedConfig, in *intel) (feedResult, error) {
	s := &fetchSpec{url: fc.str("url", srcAndroid), path: fc.cache("android", "all.zip"), maxAgeH: fc.maxAge(),
		maxBytes: fc.maxBytes(defaultArchive)}
	out, f, err := fetchParse(ctx, c.fetch, s, func(p string) ([]*androidEntry, error) {
		var out []*androidEntry
		return out, zipJSON(p, defaultInflated, func(o *pyjson.Object) error {
			es, err := androidEntries(o)
			out = append(out, es...)
			return err
		})
	})
	if err != nil {
		return feedResult{}, err
	}
	in.android = out
	return feedResult{fetched: f}, nil
}

func (c *collector) loadApple(ctx context.Context, fc *feedConfig, in *intel) (feedResult, error) {
	s := &fetchSpec{url: fc.str("url", srcApple), path: fc.cache("apple", "index.html"), maxAgeH: fc.maxAge(),
		maxBytes: fc.maxBytes(defaultSmall)}
	rows, f, err := fetchParse(ctx, c.fetch, s, func(p string) ([]*appleRelease, error) {
		data, err := readAll(p, s.maxBytes)
		if err != nil {
			return nil, err
		}
		return parseAppleIndex(data)
	})
	if err != nil {
		return feedResult{}, err
	}
	in.apple = rows
	return feedResult{fetched: f}, nil
}

// appleReleaseCVEs is the CVE ids of one Apple release page (cached a week).
func (c *collector) appleReleaseCVEs(ctx context.Context, url string) ([]string, error) {
	sum := sha1.Sum([]byte(url)) // #nosec G401 -- see the import
	s := &fetchSpec{url: url, path: filepath.Join(c.appleDir, "release-"+hex.EncodeToString(sum[:])[:16]+".html"),
		maxAgeH: 168, maxBytes: defaultSmall}
	cves, _, err := fetchParse(ctx, c.fetch, s, func(p string) ([]string, error) {
		data, err := readAll(p, s.maxBytes)
		if err != nil {
			return nil, err
		}
		return appleCVEs(data), nil
	})
	return cves, err
}

// loadCVRF is one monthly MSRC CVRF document: product name -> its fixed builds.
func (c *collector) loadCVRF(ctx context.Context, fc *feedConfig, u msrcUpdate, hdr map[string]string) (map[string][]*msrcItem, fetched, error) {
	if err := safeName(u.id); err != nil {
		return nil, fetched{}, err
	}
	ds := &fetchSpec{url: strings.ReplaceAll(fc.str("cvrf_url", srcMSRCDoc), "{id}", u.id),
		path: fc.cache("msrc", u.id+".json"), maxAgeH: fc.maxAge(), maxBytes: fc.maxBytes(defaultSmall), headers: hdr}
	return fetchParse(ctx, c.fetch, ds, func(p string) (map[string][]*msrcItem, error) {
		data, err := readAll(p, ds.maxBytes)
		if err != nil {
			return nil, err
		}
		return cvrfItems(data, u)
	})
}

func (c *collector) loadMSRC(ctx context.Context, fc *feedConfig, in *intel) (feedResult, error) {
	hdr := map[string]string{"Accept": "application/json"}
	s := &fetchSpec{url: fc.str("url", srcMSRCList), path: fc.cache("msrc", "updates.json"), maxAgeH: fc.maxAge(),
		maxBytes: fc.maxBytes(defaultSmall), headers: hdr}
	months := int(rundoc.Float(fc.m.Value("months"), 3))
	ups, f, err := fetchParse(ctx, c.fetch, s, func(p string) ([]msrcUpdate, error) {
		data, err := readAll(p, s.maxBytes)
		if err != nil {
			return nil, err
		}
		return parseMSRCUpdates(data, months)
	})
	if err != nil {
		return feedResult{}, err
	}
	res := feedResult{fetched: f}
	idx := &msrcIndex{products: map[string][]*msrcItem{}}
	for _, u := range ups {
		items, df, err := c.loadCVRF(ctx, fc, u, hdr)
		if err != nil {
			return feedResult{}, err
		}
		if res.warn == "" {
			res.warn = df.warn
		}
		idx.releases = append(idx.releases, msrcRelease{u.id, cut(u.date, 10)})
		for name, l := range items {
			idx.products[name] = append(idx.products[name], l...)
		}
	}
	in.msrc = idx
	return res, nil
}
