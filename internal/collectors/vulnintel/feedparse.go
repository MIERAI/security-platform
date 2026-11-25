package vulnintel

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/csv"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// Parsers of the feeds (adapters/feeds.py), from bytes or a cached file. Each one rejects what the Python adapter
// would fail on, so a payload that does not parse never replaces a good cached copy.

const (
	maxZipEntries   = 2_000_000
	maxZipEntrySize = 64 << 20 // one advisory
)

var errFeed = errors.New("malformed feed")

func feedErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errFeed, fmt.Sprintf(format, a...))
}

func decodeObject(data []byte, what string) (*pyjson.Object, error) {
	v, err := pyjson.Decode(data)
	if err != nil {
		return nil, feedErr("%s: %v", what, err)
	}
	o := obj(v)
	if o == nil {
		return nil, feedErr("%s: not a JSON object", what)
	}
	return o, nil
}

// parseKEV is the CISA KEV catalogue -> index (cve -> date_added, ransomware, vendor, product).
func parseKEV(data []byte) (*kevIndex, error) {
	d, err := decodeObject(data, "cisa-kev")
	if err != nil {
		return nil, err
	}
	vulns, ok := get(d, "vulnerabilities").([]pyjson.Value)
	if !ok {
		return nil, feedErr("cisa-kev: no vulnerabilities list")
	}
	idx := &kevIndex{byCVE: map[string]*kevEntry{}}
	for _, x := range vulns {
		v := obj(x)
		cve, ok1 := get(v, "cveID").(string)
		added, ok2 := getOK(v, "dateAdded")
		if !ok1 || !ok2 {
			return nil, feedErr("cisa-kev: an entry without cveID/dateAdded")
		}
		e := &kevEntry{cve: cve, obj: pyjson.ObjectOf("date_added", added, "ransomware", get(v, "knownRansomwareCampaignUse"),
			"vendor", get(v, "vendorProject"), "product", get(v, "product"))}
		if idx.byCVE[cve] == nil {
			idx.order = append(idx.order, cve)
		}
		idx.byCVE[cve] = e
	}
	return idx, nil
}

func getOK(o *pyjson.Object, key string) (pyjson.Value, bool) {
	if o == nil {
		return nil, false
	}
	return o.Get(key)
}

// gunzip inflates at most limit bytes.
func gunzip(data []byte, limit int64) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, feedErr("gzip: %v", err)
	}
	out, err := rundoc.ReadAllLimited(zr, limit)
	if err != nil {
		return nil, feedErr("gzip: %v", err)
	}
	return out, nil
}

// pySplitLines is str.splitlines() for the line breaks feeds use.
func pySplitLines(s string) []string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\r", "\n")
	lines := strings.Split(s, "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// parseEPSS is the EPSS daily CSV (already inflated) -> cve -> probability.
func parseEPSS(raw []byte) (map[string]float64, error) {
	if !utf8.Valid(raw) {
		return nil, feedErr("epss: not UTF-8")
	}
	all := pySplitLines(string(raw))
	if len(all) == 0 {
		return nil, feedErr("epss: empty")
	}
	var rows []string
	for _, l := range all {
		if !strings.HasPrefix(l, "#") {
			rows = append(rows, l)
		}
	}
	r := csv.NewReader(strings.NewReader(strings.Join(rows, "\n")))
	r.FieldsPerRecord = -1
	recs, err := r.ReadAll()
	if err != nil || len(recs) == 0 {
		return nil, feedErr("epss: not CSV")
	}
	cveCol, epssCol := column(recs[0], "cve"), column(recs[0], "epss")
	if cveCol < 0 || epssCol < 0 {
		return nil, feedErr("epss: no cve/epss columns")
	}
	idx := make(map[string]float64, len(recs))
	for _, rec := range recs[1:] {
		if len(rec) <= max(cveCol, epssCol) {
			return nil, feedErr("epss: short row")
		}
		f, err := strconv.ParseFloat(strings.TrimSpace(rec[epssCol]), 64)
		if err != nil {
			return nil, feedErr("epss: score %q", cut(rec[epssCol], 20))
		}
		idx[rec[cveCol]] = f
	}
	return idx, nil
}

func column(header []string, name string) int {
	idx := -1
	for i, h := range header {
		if h == name {
			idx = i // DictReader: the last column of that name wins
		}
	}
	return idx
}

// zipJSON calls fn for every entry of an OSV-style export (one JSON document per entry), bounded.
func zipJSON(path string, limit int64, fn func(*pyjson.Object) error) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return feedErr("zip: %v", err)
	}
	defer func() { _ = zr.Close() }() // #nosec G104 -- read-only
	if len(zr.File) > maxZipEntries {
		return feedErr("zip: %d entries (more than %d)", len(zr.File), maxZipEntries)
	}
	var total int64
	for _, f := range zr.File {
		data, err := readZipEntry(f)
		if err != nil {
			return err
		}
		if total += int64(len(data)); total > limit {
			return feedErr("zip: more than %d bytes inflated", limit)
		}
		o, err := decodeObject(data, "zip entry "+f.Name)
		if err != nil {
			return err
		}
		if err := fn(o); err != nil {
			return err
		}
	}
	return nil
}

func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, feedErr("zip entry %s: %v", f.Name, err)
	}
	defer func() { _ = rc.Close() }() // #nosec G104 -- read-only
	data, err := rundoc.ReadAllLimited(rc, maxZipEntrySize)
	if err != nil {
		return nil, feedErr("zip entry %s: %v", f.Name, err)
	}
	return data, nil
}

// osvEntry adds one OSV advisory to the index of ecosystem eco (withdrawn ones are left out).
func osvEntry(idx map[string][]*osvAdv, eco string, v *pyjson.Object) error {
	if truthy(v, "withdrawn") {
		return nil
	}
	id, ok := get(v, "id").(string)
	if !ok {
		return feedErr("osv: an advisory without id")
	}
	sev := strings.ToLower(sget(oget(v, "database_specific"), "severity"))
	for _, x := range lget(v, "affected") {
		a := obj(x)
		pkg := oget(a, "package")
		if e, _, _ := strings.Cut(sget(pkg, "ecosystem"), ":"); e != eco {
			continue
		}
		adv := &osvAdv{ID: id, Aliases: strs(lget(v, "aliases")), Published: sget(v, "published"),
			Modified: sget(v, "modified"), Severity: sev, Summary: cut(sget(v, "summary"), 160), Versions: strs(lget(a, "versions"))}
		for _, r := range lget(a, "ranges") {
			rg := osvRange{Type: sget(obj(r), "type")}
			for _, e := range lget(obj(r), "events") {
				if eo := obj(e); eo != nil {
					rg.Events = append(rg.Events, eo)
				}
			}
			adv.Ranges = append(adv.Ranges, rg)
		}
		name := sget(pkg, "name")
		idx[name] = append(idx[name], adv)
	}
	return nil
}

// androidEntries is the Android bulletin entries of one OSV record (per affected entry with a patch level;
// device-specific entries excluded).
func androidEntries(v *pyjson.Object) ([]*androidEntry, error) {
	if truthy(v, "withdrawn") {
		return nil, nil
	}
	id, ok := get(v, "id").(string)
	if !ok {
		return nil, feedErr("android: a record without id")
	}
	var out []*androidEntry
	for _, x := range lget(v, "affected") {
		a := obj(x)
		es := oget(a, "ecosystem_specific")
		vers := strs(lget(a, "versions"))
		if !truthy(es, "spl") || deviceSpecific(vers) {
			continue
		}
		out = append(out, &androidEntry{ID: id, Aliases: strs(lget(v, "aliases")), SPL: cut(sget(es, "spl"), 10),
			Severity: strings.ToLower(sget(es, "severity")), Versions: vers, Component: sget(oget(a, "package"), "name")})
	}
	return out, nil
}

func deviceSpecific(vers []string) bool {
	for _, x := range vers {
		if strings.Contains(strings.ToLower(x), "specific") {
			return true
		}
	}
	return false
}

// pyWS is the whitespace of Python's str methods and \s in str patterns.
const pyWS = `\s\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{1c}-\x{1f}`

var (
	trRE    = regexp.MustCompile(`(?s)<tr>(.*?)</tr>`)
	tdRE    = regexp.MustCompile(`(?s)<td[^>]*>(.*?)</td>`)
	tagRE   = regexp.MustCompile(`(?s)<[^>]+>`)
	wsRE    = regexp.MustCompile(`[` + pyWS + `]+`)
	hrefRE  = regexp.MustCompile(`href="([^"]+)"`)
	appleRE = regexp.MustCompile(`^(macOS|iOS|iPadOS|watchOS|tvOS|visionOS|Safari|Xcode)\b(?:[` + pyWS +
		`]+[A-Za-z][A-Za-z ]*?)?[` + pyWS + `]+(\d+(?:\.\d+)*)`)
	cveRE = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)
)

func pyStrip(s string) string {
	return strings.TrimFunc(s, func(r rune) bool { return wsRE.MatchString(string(r)) })
}

// decodeReplace is bytes.decode("utf-8", errors="replace").
func decodeReplace(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for len(b) > 0 {
		r, n := utf8.DecodeRune(b)
		sb.WriteRune(r)
		b = b[n:]
	}
	return sb.String()
}

// parseAppleIndex is Apple's security releases table -> releases (name, product, version, date, page).
func parseAppleIndex(page []byte) ([]*appleRelease, error) {
	html := decodeReplace(page)
	var rows []*appleRelease
	for _, tr := range trRE.FindAllStringSubmatch(html, -1) {
		cells := tdRE.FindAllStringSubmatch(tr[1], -1)
		if len(cells) < 3 {
			continue
		}
		name := pyStrip(wsRE.ReplaceAllString(tagRE.ReplaceAllString(cells[0][1], " "), " "))
		date, err := time.Parse("2 Jan 2006", wsRE.ReplaceAllString(pyStrip(tagRE.ReplaceAllString(cells[2][1], "")), " "))
		if err != nil {
			continue
		}
		r := &appleRelease{Date: date.Format("2006-01-02")}
		if h := hrefRE.FindStringSubmatch(cells[0][1]); h != nil {
			r.URL, r.HasURL = h[1], true
		}
		if m := appleRE.FindStringSubmatch(name); m != nil {
			r.Product, r.Version = m[1], m[2]
		}
		before, _, _ := strings.Cut(name, "This update")
		r.Name = cut(pyStrip(before), 120)
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		return nil, feedErr("apple security releases: no rows parsed (page layout changed?)")
	}
	return rows, nil
}

// appleCVEs is the CVE ids listed on one release page, sorted.
func appleCVEs(page []byte) []string {
	return sortedSet(cveRE.FindAllString(decodeReplace(page), -1))
}

// msrcUpdate is one entry of the MSRC update list.
type msrcUpdate struct{ id, date string }

// parseMSRCUpdates is the update list -> the last `months` updates by release date.
func parseMSRCUpdates(data []byte, months int) ([]msrcUpdate, error) {
	d, err := decodeObject(data, "msrc updates")
	if err != nil {
		return nil, err
	}
	vals, ok := get(d, "value").([]pyjson.Value)
	if !ok {
		return nil, feedErr("msrc updates: no value list")
	}
	ups := make([]msrcUpdate, 0, len(vals))
	for _, x := range vals {
		id, ok1 := get(obj(x), "ID").(string)
		date, ok2 := get(obj(x), "InitialReleaseDate").(string)
		if !ok1 || !ok2 {
			return nil, feedErr("msrc updates: an entry without ID/InitialReleaseDate")
		}
		ups = append(ups, msrcUpdate{id, date})
	}
	sort.SliceStable(ups, func(i, j int) bool { return ups[i].date < ups[j].date })
	return lastN(ups, months), nil
}

// lastN is Python's l[-n:].
func lastN[T any](l []T, n int) []T {
	switch {
	case n == 0:
		return l
	case n > 0:
		return l[max(len(l)-n, 0):]
	default:
		return l[min(-n, len(l)):]
	}
}

// cvrfItems is one CVRF document -> product name -> fixes.
func cvrfItems(data []byte, up msrcUpdate) (map[string][]*msrcItem, error) {
	d, err := decodeObject(data, "msrc cvrf "+up.id)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, x := range lget(oget(d, "ProductTree"), "FullProductName") {
		names[pystr(get(obj(x), "ProductID"))] = pystr(get(obj(x), "Value"))
	}
	out := map[string][]*msrcItem{}
	for _, x := range lget(d, "Vulnerability") {
		v := obj(x)
		exploited, sev := threats(v)
		for _, r := range lget(v, "Remediations") {
			addRemediation(out, names, obj(r), &msrcItem{Release: up.id, Date: cut(up.date, 10), CVE: get(v, "CVE"),
				Exploited: exploited, Severity: sev})
		}
	}
	return out, nil
}

func threats(v *pyjson.Object) (exploited bool, severity string) {
	var desc []string
	found := false
	for _, t := range lget(v, "Threats") {
		typ, _ := pyjson.Float(get(obj(t), "Type"))
		val := sget(oget(obj(t), "Description"), "Value")
		if typ == 1 {
			desc = append(desc, val)
		}
		if typ == 3 && !found {
			severity, found = strings.ToLower(val), true
		}
	}
	return strings.Contains(strings.Join(desc, " "), "Exploited:Yes"), severity
}

func addRemediation(out map[string][]*msrcItem, names map[string]string, r *pyjson.Object, base *msrcItem) {
	if !truthy(r, "FixedBuild") {
		return
	}
	for _, pid := range lget(r, "ProductID") {
		name, ok := names[pystr(pid)]
		if !ok {
			continue
		}
		it := *base
		it.FixedBuild, it.KB = pystr(get(r, "FixedBuild")), sget(oget(r, "Description"), "Value")
		out[name] = append(out[name], &it)
	}
}

// readAll reads a cached feed file, bounded.
func readAll(path string, limit int64) ([]byte, error) {
	data, err := rundoc.ReadLimited(path, limit)
	if err != nil {
		return nil, feedErr("%v", err)
	}
	return data, nil
}
