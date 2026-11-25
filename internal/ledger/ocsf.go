package ledger

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/MIERAI/security-platform/internal/ledger/fileio"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// OCSF maps a ledger entry to an OCSF 1.x Finding event (contracts/findings §4), with the reference's key
// order.
func OCSF(e *pyjson.Object) *pyjson.Object {
	kind, ok := e.Get("kind")
	if !ok {
		kind = "detection"
	}
	uid, name := ocsfClass(pyjson.Str(kind))
	get := func(k string) pyjson.Value { v, _ := e.Get(k); return v }
	version, ok := e.Get("collector_version")
	if !ok {
		version = ""
	}
	typ, rest, _ := strings.Cut(e.Str("asset"), ":")
	ev := pyjson.ObjectOf("class_uid", uid, "class_name", name, "category_uid", int64(2), "activity_id", int64(1),
		"severity_id", severityID(e.Str("severity")), "status_id", statusID(e.Str("status")), "status", get("status"),
		"time", get("last_seen"),
		"metadata", pyjson.ObjectOf("version", "1.3.0", "product",
			pyjson.ObjectOf("name", "security-platform/"+e.Str("collector"), "version", version)),
		"finding_info", pyjson.ObjectOf("uid", get("id"), "title", get("title"), "first_seen_time", get("first_seen"),
			"last_seen_time", get("last_seen"), "types", []pyjson.Value{get("check")}),
		"resources", []pyjson.Value{pyjson.ObjectOf("type", typ, "name", rest)},
		"remediation", pyjson.ObjectOf("desc", get("remediation")))
	switch uid {
	case 2003:
		ev.Set("compliance", pyjson.ObjectOf("control", get("check"), "standards", cisRefs(e.List("refs"))))
	case 2002:
		ev.Set("vulnerabilities", []pyjson.Value{vulnerability(e.Obj("attributes"))})
	}
	return ev
}

func ocsfClass(kind string) (int64, string) {
	switch kind {
	case "vulnerability":
		return 2002, "Vulnerability Finding"
	case "compliance":
		return 2003, "Compliance Finding"
	default:
		return 2004, "Detection Finding"
	}
}

func severityID(sev string) int64 {
	return map[string]int64{"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}[sev]
}

func statusID(st string) int64 {
	if id, ok := map[string]int64{"open": 1, "fixed": 4, "accepted": 3, "false_positive": 3}[st]; ok {
		return id
	}
	return 99
}

func cisRefs(refs []pyjson.Value) []pyjson.Value {
	out := []pyjson.Value{}
	for _, r := range stringList(refs) {
		if strings.HasPrefix(r, "cis:") || strings.HasPrefix(r, "cis-") {
			out = append(out, r)
		}
	}
	return out
}

func vulnerability(a *pyjson.Object) *pyjson.Object {
	if a == nil {
		a = pyjson.NewObject()
	}
	get := func(k string) pyjson.Value { v, _ := a.Get(k); return v }
	cvss := []pyjson.Value{}
	if a.Truthy("cvss") {
		cvss = append(cvss, pyjson.ObjectOf("base_score", get("cvss")))
	}
	var epss pyjson.Value
	if get("epss") != nil {
		epss = pyjson.ObjectOf("score", get("epss"))
	}
	return pyjson.ObjectOf(
		"cve", pyjson.ObjectOf("uid", get("cve"), "cvss", cvss, "epss", epss),
		"is_exploit_available", a.Truthy("kev"),
		"affected_packages", []pyjson.Value{pyjson.ObjectOf("name", get("package"), "version", get("installed"),
			"fixed_in_version", get("fixed"))})
}

// writeReport writes DATA/reports/latest-auto.md (private; its format is not part of the contract).
func (m *merger) writeReport() error {
	dir := filepath.Join(m.opt.Data, "reports")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	var b strings.Builder
	b.WriteString("# Ledger (auto) " + m.ledger.Str("updated_at") + "\n\nPRIVATE - attacker intelligence. Do not publish.\n\n" +
		"## SLIs\n\n| SLI | value | objective | state |\n|---|---|---|---|\n")
	sli := m.ledger.Obj("sli")
	for _, k := range sli.Keys() {
		v := sli.Obj(k)
		state := "**BREACH**"
		if v.Truthy("ok") {
			state = "OK"
		}
		val, _ := v.Get("value")
		target, _ := v.Get("target")
		b.WriteString("| " + k + " | " + pyjson.Str(val) + " | <= " + pyjson.Str(target) + " | " + state + " |\n")
	}
	b.WriteString("\n## Open findings\n\n| sev | layer | asset | title | needs human | id |\n|---|---|---|---|---|---|\n")
	for _, e := range m.reportRows() {
		human := ""
		if e.Truthy("needs_human") {
			human = "yes"
		}
		title := strings.ReplaceAll(runes(e.Str("title"), 120), "|", "/")
		b.WriteString("| " + e.Str("severity") + " | " + e.Str("layer") + " | `" + runes(e.Str("asset"), 80) + "` | " +
			title + " | " + human + " | " + e.Str("id") + " |\n")
	}
	return fileio.Write(filepath.Join(dir, "latest-auto.md"), []byte(b.String()))
}

func (m *merger) reportRows() []*pyjson.Object {
	rows := m.byStatus(statusOpen)
	order := map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
	rank := func(s string) int {
		if r, ok := order[s]; ok {
			return r
		}
		return len(order)
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if ra, rb := rank(a.Str("severity")), rank(b.Str("severity")); ra != rb {
			return ra < rb
		}
		if a.Str("layer") != b.Str("layer") {
			return a.Str("layer") < b.Str("layer")
		}
		return a.Str("asset") < b.Str("asset")
	})
	return rows
}

// runes is s[:n] in characters (Python slicing).
func runes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}
