package vulnintel

import (
	"regexp"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// osvAdv is one advisory of the OSV index (adapters/feeds.py osv(): the compact form).
type osvAdv struct {
	ID, Published, Modified, Severity, Summary string
	Aliases, Versions                          []string
	Ranges                                     []osvRange
}

type osvRange struct {
	Type   string
	Events []*pyjson.Object // {"introduced": v} ... in the advisory's order
}

// osvIndex is ecosystem -> package -> advisories.
type osvIndex map[string]map[string][]*osvAdv

type component struct{ eco, name, version string }

var purlRE = regexp.MustCompile(`^pkg:([a-z]+)/(.+)@([^?#]+)`)

func purlEcosystems() map[string]string {
	return map[string]string{"golang": "Go", "pypi": "PyPI", "npm": "npm", "maven": "Maven", "cargo": "crates.io",
		"gem": "RubyGems", "nuget": "NuGet"}
}

// components lists the (ecosystem, name, version) of a CycloneDX document's purls (osvmatch.components).
func components(cdx *pyjson.Object) []component {
	ecos := purlEcosystems()
	var out []component
	for _, c := range lget(cdx, "components") {
		m := purlRE.FindStringSubmatch(sget(obj(c), "purl"))
		if len(m) < 4 || ecos[m[1]] == "" {
			continue
		}
		name := strings.ReplaceAll(strings.ReplaceAll(m[2], "%2F", "/"), "%40", "@")
		if m[1] == "maven" {
			name = strings.Replace(name, "/", ":", 1)
		}
		out = append(out, component{ecos[m[1]], name, m[3]})
	}
	return out
}

// semverKey is osvmatch.semver_key: numeric release parts (as canonical digit strings, so any size compares
// right), then either "release" or the pre-release identifiers.
type semverKey struct {
	nums    []string
	release bool
	pre     []preID
}

type preID struct {
	num bool
	s   string
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func canon(d string) string {
	d = strings.TrimLeft(d, "0")
	if d == "" {
		return "0"
	}
	return d
}

func newSemverKey(v string) semverKey {
	v = strings.TrimLeft(v, "v")
	if v == "0" || v == "" {
		return semverKey{nums: []string{"0"}, release: true}
	}
	main, pre, _ := strings.Cut(v, "-")
	main, _, _ = strings.Cut(main, "+")
	var nums []string
	for _, x := range strings.Split(main, ".") {
		if isDigits(x) {
			nums = append(nums, canon(x))
		} else {
			nums = append(nums, "0")
		}
	}
	for len(nums) < 3 {
		nums = append(nums, "0")
	}
	if pre == "" {
		return semverKey{nums: nums, release: true}
	}
	k := semverKey{nums: nums}
	for _, p := range strings.Split(pre, ".") {
		if isDigits(p) {
			k.pre = append(k.pre, preID{num: true, s: canon(p)})
		} else {
			k.pre = append(k.pre, preID{s: p})
		}
	}
	return k
}

func cmpDigits(a, b string) int {
	if len(a) != len(b) {
		if len(a) < len(b) {
			return -1
		}
		return 1
	}
	return strings.Compare(a, b)
}

func cmpLen(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func (k semverKey) compare(o semverKey) int {
	for i := 0; i < len(k.nums) && i < len(o.nums); i++ {
		if c := cmpDigits(k.nums[i], o.nums[i]); c != 0 {
			return c
		}
	}
	if c := cmpLen(len(k.nums), len(o.nums)); c != 0 {
		return c
	}
	if k.release != o.release {
		if k.release {
			return 1
		}
		return -1
	}
	return comparePre(k.pre, o.pre)
}

func comparePre(a, b []preID) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		x, y := a[i], b[i]
		switch {
		case x.num != y.num: // (0, int) < (1, str)
			if x.num {
				return -1
			}
			return 1
		case x.num:
			if c := cmpDigits(x.s, y.s); c != 0 {
				return c
			}
		default:
			if c := strings.Compare(x.s, y.s); c != 0 {
				return c
			}
		}
	}
	return cmpLen(len(a), len(b))
}

type rangeEvent struct {
	key  semverKey
	kind string
}

func eventOrder(kind string) int {
	switch kind {
	case "introduced":
		return 0
	case "fixed":
		return 1
	case "last_affected":
		return 2
	case "limit":
		return 3
	}
	return 9
}

// inRange is osvmatch.in_range: walk the events in version order and track whether the version is affected.
func inRange(version string, events []*pyjson.Object) bool {
	key := newSemverKey(version)
	var evs []rangeEvent
	for _, e := range events {
		for _, k := range e.Keys() {
			v, _ := e.Get(k)
			evs = append(evs, rangeEvent{newSemverKey(pystr(v)), k})
		}
	}
	sort.SliceStable(evs, func(i, j int) bool {
		if c := evs[i].key.compare(evs[j].key); c != 0 {
			return c < 0
		}
		return eventOrder(evs[i].kind) < eventOrder(evs[j].kind)
	})
	affected := false
	for _, e := range evs {
		c := e.key.compare(key)
		switch e.kind {
		case "introduced":
			affected = affected || c <= 0
		case "fixed", "limit":
			affected = affected && c > 0
		case "last_affected":
			affected = affected && c >= 0
		}
	}
	return affected
}

// fixedVersion is the first "fixed" event of an advisory ("" when none).
func fixedVersion(a *osvAdv) string {
	for _, r := range a.Ranges {
		for _, e := range r.Events {
			if v, ok := e.Get("fixed"); ok {
				return pystr(v)
			}
		}
	}
	return ""
}

type osvHit struct {
	comp component
	adv  *osvAdv
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// osvMatch is osvmatch.match: exact listed versions, then SEMVER ranges (ECOSYSTEM ranges for Go, whose versions
// are semver); other version schemes never match by range.
func osvMatch(comps []component, idx osvIndex) []osvHit {
	var hits []osvHit
	for _, c := range comps {
		for _, a := range idx[c.eco][c.name] {
			if advHit(c, a) {
				hits = append(hits, osvHit{c, a})
			}
		}
	}
	return hits
}

func advHit(c component, a *osvAdv) bool {
	if contains(a.Versions, c.version) || contains(a.Versions, strings.TrimLeft(c.version, "v")) {
		return true
	}
	for _, r := range a.Ranges {
		if (r.Type == "SEMVER" || (r.Type == "ECOSYSTEM" && c.eco == "Go")) && inRange(c.version, r.Events) {
			return true
		}
	}
	return false
}
