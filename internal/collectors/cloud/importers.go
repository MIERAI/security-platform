package cloud

import (
	"regexp"
	"strings"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

// importer parses an export of a provider's own posture service.
type importer struct {
	provider string
	parse    func(doc any) []Result
}

// importers are the native posture services, by import type.
func importers() map[string]importer {
	return map[string]importer{"securityhub": {"aws", ParseSecurityHub}, "scc": {"gcp", ParseSCC},
		"defender": {"azure", ParseDefender}}
}

func importerNames() string { return "securityhub, scc, defender" }

// rowsOf is `doc.get(key, doc) if isinstance(doc, dict) else doc` as a list.
func rowsOf(doc any, keys ...string) []any {
	m, ok := doc.(map[string]any)
	if !ok {
		return dyn.List(doc)
	}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			return dyn.List(v)
		}
	}
	return nil
}

var cisAWSRequirement = regexp.MustCompile(`^CIS AWS Foundations Benchmark v([0-9.]+)/([0-9.]+)`)

// ParseSecurityHub reads AWS Security Hub findings in ASFF (`aws securityhub get-findings`, or a list).
func ParseSecurityHub(doc any) []Result {
	var out []Result
	for _, row := range rowsOf(doc, "Findings") {
		f := dyn.Map(row)
		if dyn.Str(f["RecordState"]) == "ARCHIVED" || dyn.Str(dyn.Map(f["Workflow"])["Status"]) == "SUPPRESSED" {
			continue
		}
		comp := dyn.Map(f["Compliance"])
		status, ok := asffStatus(comp)
		if !ok {
			continue
		}
		out = append(out, asffResult(f, comp, status))
	}
	return out
}

func asffStatus(comp map[string]any) (string, bool) {
	switch dyn.Str(comp["Status"]) {
	case "FAILED":
		return "FAIL", true
	case "PASSED":
		return "PASS", true
	}
	if len(comp) == 0 {
		return "FAIL", true
	}
	return "", false
}

func asffResult(f, comp map[string]any, status string) Result {
	cid := dyn.Or(dyn.Text(comp, "SecurityControlId"), dyn.Text(dyn.Map(f["ProductFields"]), "ControlId"))
	resources := dyn.List(f["Resources"])
	res := map[string]any{}
	if len(resources) > 0 {
		res = dyn.Map(resources[0])
	}
	rid := dyn.Str(res["Id"])
	svc := dyn.Or(dyn.Lower(dyn.Cut(strings.ReplaceAll(dyn.Str(res["Type"]), "Aws", ""), 20)), "other")
	if strings.HasPrefix(rid, "arn:") {
		if parts := strings.Split(rid, ":"); len(parts) > 2 {
			svc = parts[2]
		}
	}
	refs := []string{}
	for _, req := range dyn.Strings(comp["RelatedRequirements"]) {
		if m := cisAWSRequirement.FindStringSubmatch(req); m != nil {
			refs = append(refs, "cis-aws:"+m[1]+"/"+m[2])
		}
	}
	title := cid
	if v, ok := f["Title"]; ok {
		title = dyn.Str(v)
	}
	return Result{Source: "securityhub", Provider: "aws", Account: dyn.Str(f["AwsAccountId"]),
		Service: svc, Region: dyn.Or(dyn.Text(res, "Region"), dyn.Text(f, "Region"), "global"),
		Resource: rid, Check: dyn.Or(cid, dyn.Str(f["GeneratorId"])), Control: ControlFor("securityhub", cid),
		Status: status, Severity: sev(dyn.Str(dyn.Map(f["Severity"])["Label"])), Title: title,
		Detail: dyn.Cut(dyn.Text(f, "Description"), 200), Refs: refs,
		Remediation: dyn.Cut(dyn.Str(dyn.Map(dyn.Map(f["Remediation"])["Recommendation"])["Text"]), 300)}
}

// ParseSCC reads GCP Security Command Center findings (`gcloud scc findings list --format=json`:
// [{finding, resource}]).
func ParseSCC(doc any) []Result {
	var out []Result
	for _, row := range rowsOf(doc, "listFindingsResults") {
		rm := dyn.Map(row)
		f := rm
		if v, ok := rm["finding"]; ok {
			f = dyn.Map(v)
		}
		res := dyn.Map(rm["resource"])
		if st, ok := f["state"]; (ok && st != nil && dyn.Str(st) != "ACTIVE") || dyn.Str(f["mute"]) == "MUTED" {
			continue
		}
		out = append(out, sccResult(f, res))
	}
	return out
}

func sccResult(f, res map[string]any) Result {
	cat, rname := dyn.Str(f["category"]), dyn.Str(f["resourceName"])
	svc := "other"
	if strings.HasPrefix(rname, "//") {
		svc, _, _ = strings.Cut(rname[2:], ".")
	}
	refs := []string{}
	for _, c := range dyn.List(f["compliances"]) {
		cm := dyn.Map(c)
		if dyn.Str(cm["standard"]) == "cis" {
			for _, id := range dyn.Strings(cm["ids"]) {
				refs = append(refs, "cis-gcp:"+pyStrOrNone(cm["version"])+"/"+id)
			}
		}
	}
	last := rname[strings.LastIndex(rname, "/")+1:]
	return Result{Source: "scc", Provider: "gcp",
		Account: dyn.Or(dyn.Text(res, "projectDisplayName"), dyn.Text(res, "project_display_name")),
		Service: svc, Region: dyn.Or(dyn.Text(res, "location"), "global"), Resource: last, Name: last, Check: cat,
		Control: ControlFor("scc", cat), Status: "FAIL", Severity: sev(dyn.Str(f["severity"])),
		Title: dyn.Lower(strings.ReplaceAll(cat, "_", " ")), Detail: dyn.Cut(rname, 200), Refs: refs,
		Remediation: dyn.Cut(dyn.Text(f, "nextSteps"), 300)}
}

var (
	azureSubscription = regexp.MustCompile(`(?i)^/subscriptions/([^/]+)`)
	azureNamespace    = regexp.MustCompile(`(?i)/providers/Microsoft\.([A-Za-z]+)/`)
)

// ParseDefender reads Microsoft Defender for Cloud assessments (an Azure Resource Graph export of
// microsoft.security/assessments, or the REST list {value: [...]}).
func ParseDefender(doc any) []Result {
	var out []Result
	for _, row := range rowsOf(doc, "data", "value") {
		a := dyn.Map(row)
		p := dyn.Map(a["properties"])
		code := dyn.Str(dyn.Map(p["status"])["code"])
		if code != "Unhealthy" && code != "Healthy" {
			continue
		}
		out = append(out, defenderResult(a, p, code))
	}
	return out
}

func defenderResult(a, p map[string]any, code string) Result {
	details := dyn.Map(p["resourceDetails"])
	id, _, _ := strings.Cut(dyn.Str(a["id"]), "/providers/Microsoft.Security/")
	rid := dyn.Or(dyn.Text(details, "Id"), dyn.Text(details, "ResourceId"), id)
	sub, svc := "", "other"
	if m := azureSubscription.FindStringSubmatch(rid); m != nil {
		sub = dyn.Lower(m[1])
	}
	if m := azureNamespace.FindStringSubmatch(rid); m != nil {
		svc = dyn.Lower(m[1])
	}
	name := dyn.Str(p["displayName"])
	status := "PASS"
	if code == "Unhealthy" {
		status = "FAIL"
	}
	meta := dyn.Map(p["metadata"])
	return Result{Source: "defender", Provider: "azure", Account: sub, Service: svc, Region: "global", Resource: rid,
		Name: rid[strings.LastIndex(rid, "/")+1:], Check: name, Control: ControlFor("defender", name), Status: status,
		Severity: sev(dyn.Str(meta["severity"])), Title: name,
		Detail: dyn.Cut(dyn.Str(dyn.Map(p["status"])["description"]), 200), Refs: []string{},
		Remediation: dyn.Cut(dyn.Text(meta, "remediationDescription"), 300)}
}
