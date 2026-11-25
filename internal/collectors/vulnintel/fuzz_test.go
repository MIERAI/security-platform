package vulnintel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// FuzzFeeds: every structured feed parser (KEV JSON, EPSS CSV, OSV / Android records, Apple's index page, MSRC
// update list and CVRF document) answers data or an error for any payload, never a panic.
func FuzzFeeds(f *testing.F) {
	f.Add([]byte(`{"catalogVersion": "1", "vulnerabilities": [{"cveID": "CVE-1", "dateAdded": "2026-01-01", "vendorProject": "V"}]}`))
	f.Add([]byte("#model_version:v1\ncve,epss,percentile\nCVE-1,0.5,0.9\n"))
	f.Add([]byte(`{"id": "GO-1", "aliases": ["CVE-1"], "affected": [{"package": {"ecosystem": "Go", "name": "x"},
	 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2"}]}],
	 "ecosystem_specific": {"spl": "2026-01-01", "severity": "Critical"}, "versions": ["14"]}]}`))
	f.Add([]byte(`<tr><td><a href="/x">macOS Sequoia 15.1</a></td><td>macOS</td><td>28 Oct 2026</td></tr> CVE-2026-12345`))
	f.Add([]byte(`{"value": [{"ID": "2026-Nov", "InitialReleaseDate": "2026-11-11T08:00:00Z"}]}`))
	f.Add([]byte(`{"ProductTree": {"FullProductName": [{"ProductID": "1", "Value": "Windows 11"}]}, "Vulnerability": [{"CVE": "CVE-1",
	 "Threats": [{"Type": 1, "Description": {"Value": "Exploited:Yes"}}], "Remediations": [{"FixedBuild": "10.0.1.2", "ProductID": ["1"]}]}]}`))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = parseKEV(data)
		_, _ = parseEPSS(data)
		if v, err := pyjson.Decode(data); err == nil {
			if o := obj(v); o != nil {
				_ = osvEntry(map[string][]*osvAdv{}, "Go", o)
				_, _ = androidEntries(o)
			}
		}
		_, _ = parseAppleIndex(data)
		_ = appleCVEs(data)
		_, _ = parseMSRCUpdates(data, 3)
		_, _ = cvrfItems(data, msrcUpdate{id: "2026-Nov", date: "2026-11-11"})
		_, _ = gunzip(data, 1<<20)
	})
}

// FuzzTrivyAndSBOM: trivy's JSON report and CycloneDX components (purls).
func FuzzTrivyAndSBOM(f *testing.F) {
	f.Add(`{"Results": [{"Target": "t", "Vulnerabilities": [{"VulnerabilityID": "CVE-1", "Severity": "CRITICAL",
	 "PkgName": "p", "InstalledVersion": "1", "FixedVersion": "2", "CVSS": {"nvd": {"V3Score": 9.8}}}]}]}`)
	f.Add(`{"components": [{"purl": "pkg:golang/x@v1"}, {"purl": "pkg:maven/a/b@1?x"}, {"purl": 3}]}`)
	f.Add(`null`)
	f.Fuzz(func(_ *testing.T, s string) {
		if rep, _ := parseReport(s); rep != nil {
			_ = components(rep)
		}
	})
}

// FuzzVersions: semver keys (OSV ranges) and version tuples (kernel / platform builds).
func FuzzVersions(f *testing.F) {
	f.Add("v1.2.3-rc.1+meta", "1.4.2")
	f.Add("0", "")
	f.Add("10.0.26100.1234", "10.0.26100.999")
	f.Fuzz(func(t *testing.T, a, b string) {
		ka, kb := newSemverKey(a), newSemverKey(b)
		if ka.compare(kb) != -kb.compare(ka) {
			t.Fatalf("semver compare of %q and %q is not antisymmetric", a, b)
		}
		ta, tb := newVtuple(a), newVtuple(b)
		if ta.compare(tb) != -tb.compare(ta) {
			t.Fatalf("vtuple compare of %q and %q is not antisymmetric", a, b)
		}
		_ = inRange(a, []*pyjson.Object{pyjson.ObjectOf("introduced", b)})
	})
}

// FuzzInventory: inventory/v1 files in the input directory.
func FuzzInventory(f *testing.F) {
	f.Add(`{"schema": "security-platform/inventory/v1", "kind": "container-image", "complete": true,
	 "sources": {"k8s-cluster:a": "complete"}, "items": [{"cluster": "a", "image": "r/x:1", "exposed": true}]}`)
	f.Add(`{"schema": "security-platform/inventory/v1", "kind": "host-platform", "items": [{"host": "h", "os_family": "ubuntu"}]}`)
	f.Fuzz(func(t *testing.T, s string) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "inventory.x.json"), []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		inv, err := readInventories(dir)
		if err != nil {
			return
		}
		_, _ = imageCompleteness(inv)
		_ = items(inv, "container-image")
	})
}
