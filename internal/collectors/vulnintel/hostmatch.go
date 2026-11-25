package vulnintel

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// Deterministic host / platform matching (collectors/vuln-intel/hostmatch.py). Inputs are the inventory contracts
// (host-package / host-platform) and the feed indexes; outputs are what the collector turns into findings.

var (
	kernelRE    = regexp.MustCompile(`^linux-(image|modules|headers|tools|buildinfo|cloud-tools|objects|signatures)(-extra)?-\d`)
	kernelSrcRE = regexp.MustCompile(`^linux(-signed|-meta|-hwe|-oem|-lowlatency|-generic|-aws|-azure|-gcp|-oracle|-raspi|-kvm` +
		`|-restricted-modules|-lts)?([-.][0-9a-z.]+)*$`)
	flavourRE = regexp.MustCompile(`-(generic|lowlatency|aws|azure|gcp|oracle|raspi|kvm)$`)
	digitsRE  = regexp.MustCompile(`\d+`)
	splRE     = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}`)
	numericRE = regexp.MustCompile(`^\d`)
)

func distros() map[string]string {
	return map[string]string{"ubuntu": "ubuntu", "debian": "debian", "raspbian": "debian", "alpine": "alpine",
		"rocky": "rocky", "almalinux": "alma", "rhel": "redhat", "centos": "centos", "fedora": "fedora", "amzn": "amazon"}
}

func osEcosystem(eco string) bool { return eco == "deb" || eco == "apk" || eco == "rpm" }

// vtuple is hostmatch.vtuple: every run of digits, compared as numbers.
type vtuple []string

func newVtuple(v string) vtuple {
	var t vtuple
	for _, d := range digitsRE.FindAllString(v, -1) {
		t = append(t, canon(d))
	}
	return t
}

func (t vtuple) compare(o vtuple) int {
	for i := 0; i < len(t) && i < len(o); i++ {
		if c := cmpDigits(t[i], o[i]); c != 0 {
			return c
		}
	}
	return cmpLen(len(t), len(o))
}

// quote is Python's urllib.parse.quote(s, safe="").
func quote(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("_.-~", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// osSBOM is hostmatch.os_sbom: a CycloneDX document of the distro packages Trivy's DB can match, or nil.
func osSBOM(plat *pyjson.Object, pkgs []*pyjson.Object) *pyjson.Object {
	distro := distros()[strings.ToLower(sget(plat, "os_family"))]
	var pk []*pyjson.Object
	for _, p := range pkgs {
		if osEcosystem(sget(p, "ecosystem")) {
			pk = append(pk, p)
		}
	}
	if distro == "" || len(pk) == 0 {
		return nil
	}
	ver := sget(plat, "os_version")
	comps := []pyjson.Value{pyjson.ObjectOf("bom-ref", "os", "type", "operating-system", "name", distro, "version", ver)}
	var refs []string
	for _, p := range pk {
		purl := fmt.Sprintf("pkg:%s/%s/%s@%s?distro=%s-%s", sget(p, "ecosystem"), distro, quote(sget(p, "name")),
			quote(sget(p, "version")), distro, ver)
		if truthy(p, "arch") {
			purl += "&arch=" + pystr(get(p, "arch"))
		}
		if contains(refs, purl) {
			continue
		}
		props := []pyjson.Value{
			pyjson.ObjectOf("name", "aquasecurity:trivy:SrcName", "value", or(get(p, "source_name"), get(p, "name"))),
			pyjson.ObjectOf("name", "aquasecurity:trivy:SrcVersion", "value", or(get(p, "source_version"), get(p, "version"))),
			pyjson.ObjectOf("name", "aquasecurity:trivy:PkgType", "value", distro)}
		comps = append(comps, pyjson.ObjectOf("bom-ref", purl, "type", "library", "name", get(p, "name"),
			"version", get(p, "version"), "purl", purl, "properties", props))
		refs = append(refs, purl)
	}
	return pyjson.ObjectOf("bomFormat", "CycloneDX", "specVersion", "1.5", "version", int64(1),
		"metadata", pyjson.ObjectOf("component", pyjson.ObjectOf("bom-ref", "host", "type", "application", "name", "host")),
		"components", comps, "dependencies", []pyjson.Value{
			pyjson.ObjectOf("ref", "host", "dependsOn", []pyjson.Value{"os"}),
			pyjson.ObjectOf("ref", "os", "dependsOn", list(refs))})
}

// or is Python's `a or b`.
func or(a, b pyjson.Value) pyjson.Value {
	if pyjson.Truthy(a) {
		return a
	}
	return b
}

// isKernelPkg: binary packages built from a kernel source; only the RUNNING kernel's CVEs matter.
func isKernelPkg(name, source string) bool {
	return kernelRE.MatchString(name) || (source != "" && source != "linux-firmware" && kernelSrcRE.MatchString(source))
}

// kernelRunningPkg: a kernel package of the running release (its name carries the release).
func kernelRunningPkg(name, running string) bool {
	base := flavourRE.ReplaceAllString(running, "")
	return base != "" && (strings.Contains(name, running) || strings.HasSuffix(name, base) || strings.Contains(name, base+"-"))
}

// androidEntry is one bulletin entry of the android-bulletins index.
type androidEntry struct {
	ID, SPL, Severity, Component string
	Aliases, Versions            []string
}

type bulletin struct {
	spl     string
	entries []*androidEntry
}

// androidMissed: the bulletins newer than the device's security patch level, for its platform release; ok=false
// when the patch level is unknown.
func androidMissed(plat *pyjson.Object, entries []*androidEntry) ([]bulletin, bool) {
	spl := cut(sget(plat, "patch_level"), 10)
	rel, _, _ := strings.Cut(sget(plat, "os_version"), ".")
	if !splRE.MatchString(spl) {
		return nil, false
	}
	by := map[string][]*androidEntry{}
	for _, e := range entries {
		if e.SPL <= spl || !forRelease(e.Versions, rel) {
			continue
		}
		by[e.SPL] = append(by[e.SPL], e)
	}
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]bulletin, 0, len(keys))
	for _, k := range keys {
		out = append(out, bulletin{k, by[k]})
	}
	return out, true
}

func forRelease(versions []string, rel string) bool {
	numeric := false
	for _, v := range versions {
		if numericRE.MatchString(v) {
			numeric = true
			if v == rel || strings.HasPrefix(v, rel+"-") {
				return true
			}
		}
	}
	return !numeric
}

// appleRelease is one row of Apple's security releases index.
type appleRelease struct {
	Name, Product, Version, Date string
	URL                          string
	HasURL                       bool
}

func (r *appleRelease) json() *pyjson.Object {
	return pyjson.ObjectOf("name", r.Name, "product", r.Product, "version", r.Version, "date", r.Date,
		"url", noneOr(r.URL, r.HasURL))
}

// appleMissed: macOS releases of the host's major line newer than its version, oldest first; ok=false when the
// host's version is unknown.
func appleMissed(plat *pyjson.Object, releases []*appleRelease) ([]*appleRelease, bool) {
	cur := newVtuple(sget(plat, "os_version"))
	if len(cur) == 0 {
		return nil, false
	}
	var out []*appleRelease
	for _, r := range releases {
		if r.Product != "macOS" || r.Version == "" {
			continue
		}
		v := newVtuple(r.Version)
		if len(v) > 0 && v[0] == cur[0] && v.compare(cur) > 0 {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return newVtuple(out[i].Version).compare(newVtuple(out[j].Version)) < 0 })
	return out, true
}

// msrcItem is one (update, CVE, product) fix of the MSRC index.
type msrcItem struct {
	Release, Date, FixedBuild, KB, Severity string
	CVE                                     pyjson.Value
	Exploited                               bool
}

type msrcIndex struct {
	releases []msrcRelease
	products map[string][]*msrcItem
}

type msrcRelease struct{ id, date string }

type missedUpdate struct {
	release, date string
	items         []*msrcItem
}

// windowsProduct is the MSRC product name of a Windows host ("" when the build is unknown).
func windowsProduct(plat *pyjson.Object) string {
	b := newVtuple(sget(plat, "os_build"))
	if len(b) < 3 {
		return ""
	}
	gen := "10"
	if cmpDigits(b[2], "22000") >= 0 {
		gen = "11"
	}
	arch := map[string]string{"AMD64": "x64", "ARM64": "ARM64", "X86": "32-bit"}[strings.ToUpper(sget(plat, "arch"))]
	if arch == "" {
		arch = "x64"
	}
	return fmt.Sprintf("Windows %s Version %s for %s-based Systems", gen, pystr(get(plat, "os_version")), arch)
}

// windowsMissed: monthly updates whose fixed build (same base build) is newer than the host's; ok=false when the
// product is not in the MSRC documents.
func windowsMissed(plat *pyjson.Object, idx *msrcIndex) ([]missedUpdate, string, bool) {
	prod := windowsProduct(plat)
	items, ok := idx.products[prod]
	if prod == "" || !ok {
		return nil, prod, false
	}
	cur := newVtuple(sget(plat, "os_build"))
	by := map[string][]*msrcItem{}
	var order []string
	for _, it := range items {
		fb := newVtuple(it.FixedBuild)
		n := min(3, len(cur))
		if len(fb) == len(cur) && fb[:n].compare(cur[:n]) == 0 && fb.compare(cur) > 0 {
			if _, seen := by[it.Release]; !seen {
				order = append(order, it.Release)
			}
			by[it.Release] = append(by[it.Release], it)
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return by[order[i]][0].Date < by[order[j]][0].Date })
	out := make([]missedUpdate, 0, len(order))
	for _, r := range order {
		out = append(out, missedUpdate{r, by[r][0].Date, by[r]})
	}
	return out, prod, true
}

// kevEntry is one KEV catalogue entry (the index form: date_added, ransomware, vendor, product).
type kevEntry struct {
	cve string
	obj *pyjson.Object
}

// kevIndex keeps the catalogue order.
type kevIndex struct {
	order []string
	byCVE map[string]*kevEntry
}

func (k *kevIndex) has(cve string) bool { return k != nil && k.byCVE[cve] != nil }

// vendorKEV: KEV entries of the firmware vendor added on or after the firmware build date.
func vendorKEV(plat *pyjson.Object, kev *kevIndex, vendorNames []string) []*pyjson.Object {
	fw := oget(plat, "firmware")
	since := sget(fw, "build_date")
	if !truthy(fw, "build_date") {
		since = "0000-00-00"
	}
	names := make([]string, len(vendorNames))
	for i, n := range vendorNames {
		names[i] = strings.ToLower(n)
	}
	var out []*pyjson.Object
	for _, cve := range kev.order {
		e := kev.byCVE[cve]
		if contains(names, strings.ToLower(sget(e.obj, "vendor"))) && sget(e.obj, "date_added") >= since {
			o := pyjson.ObjectOf("cve", cve)
			for _, k := range e.obj.Keys() {
				v, _ := e.obj.Get(k)
				o.Set(k, v)
			}
			out = append(out, o)
		}
	}
	return out
}
