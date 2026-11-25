package cloud

import (
	"context"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

// scoutARNType is the ARN resource type of a ScoutSuite collection ("None" where ScoutSuite's id is the name).
func scoutARNType() map[string]string {
	return map[string]string{"security_groups": "security-group", "volumes": "volume", "snapshots": "snapshot",
		"instances": "instance", "buckets": "None", "users": "user", "roles": "role", "trails": "trail",
		"firewalls": "None", "storage_accounts": "None", "network_security_groups": "None"}
}

// ScoutItem is where a flagged ScoutSuite item lives.
type ScoutItem struct {
	Provider, Service, Region, Account, Collection, ID string
}

// ARN is, for AWS, the ARN other engines report for the same resource (so findings merge); else the id.
func (it ScoutItem) ARN() string {
	typ, known := scoutARNType()[it.Collection]
	if it.Provider != "aws" || !known {
		return it.ID
	}
	switch it.Service {
	case "s3":
		return "arn:aws:s3:::" + it.ID
	case "iam":
		return "arn:aws:iam::" + it.Account + ":" + typ + "/" + it.ID
	}
	region := it.Region
	if region == "global" {
		region = ""
	}
	return "arn:aws:" + it.Service + ":" + region + ":" + it.Account + ":" + typ + "/" + it.ID
}

var scoutItemID = regexp.MustCompile(`^(?P<svc>[a-z0-9]+)\.(?:regions\.(?P<region>[^.]+)\.)?(?:.*\.)?(?P<coll>[a-z_]+)\.(?P<id>[^.]+)`)

// scoutResource is the resource object an item path points into: services.<svc>...<collection>.<id>.
func scoutResource(doc map[string]any, parts []string) (coll, id string, obj map[string]any) {
	node := any(dyn.Map(doc["services"]))
	types := scoutARNType()
	for i, p := range parts {
		m, ok := node.(map[string]any)
		if !ok {
			break
		}
		child, ok := m[p]
		if !ok {
			break
		}
		if _, known := types[p]; known && i+1 < len(parts) {
			if cm, ok := child.(map[string]any); ok {
				if o, ok := cm[parts[i+1]]; ok {
					return p, parts[i+1], dyn.Map(o)
				}
			}
		}
		node = child
	}
	return "", parts[len(parts)-1], map[string]any{}
}

func pyStrOrNone(v any) string {
	if v == nil {
		return "None"
	}
	return dyn.Str(v)
}

func scoutRefs(provider string, f map[string]any) []string {
	refs := []string{}
	for _, c := range dyn.List(f["compliance"]) {
		cm := dyn.Map(c)
		if strings.Contains(dyn.Str(cm["name"]), "CIS") {
			refs = append(refs, "cis-"+provider+":"+pyStrOrNone(cm["version"])+"/"+pyStrOrNone(cm["reference"]))
		}
	}
	return refs
}

func sortedMapKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// ParseScoutSuite reads ScoutSuite's results object (the JSON in scoutsuite_results_<provider>-<id>.js): the
// flagged items of every finding rule. Item paths point into the object; the resource's own `arn`/`name` there
// gives the canonical id other engines use.
func ParseScoutSuite(doc map[string]any, provider, account string) []Result {
	var out []Result
	sc := scoutDoc{doc: doc, provider: provider, account: account}
	services := dyn.Map(doc["services"])
	for _, svc := range sortedMapKeys(services) {
		findings := dyn.Map(dyn.Map(services[svc])["findings"])
		for _, rule := range sortedMapKeys(findings) {
			out = append(out, sc.rule(svc, rule, dyn.Map(findings[rule]))...)
		}
	}
	return out
}

// scoutDoc is one ScoutSuite results object and the account it describes.
type scoutDoc struct {
	doc               map[string]any
	provider, account string
}

func (sc scoutDoc) rule(svc, rule string, f map[string]any) []Result {
	provider, account := sc.provider, sc.account
	items := dyn.Strings(f["items"])
	refs := scoutRefs(provider, f)
	title := rule
	if v, ok := f["description"]; ok {
		title = dyn.Str(v)
	}
	control := ControlFor("scoutsuite", rule)
	var out []Result
	if len(items) == 0 && dyn.Truthy(f["checked_items"]) {
		out = append(out, Result{Source: "scoutsuite", Provider: provider, Account: account, Service: svc, Region: "global",
			Check: rule, Control: control, Status: "PASS", Severity: "info", Title: title, Refs: refs, CoverageOnly: true})
	}
	for _, it := range items {
		region := "global"
		if m := scoutItemID.FindStringSubmatch(it); len(m) > 2 && m[2] != "" {
			region = m[2]
		}
		coll, rid, obj := scoutResource(sc.doc, strings.Split(it, "."))
		name := dyn.Or(dyn.Text(obj, "name"), rid)
		resource := ScoutItem{Provider: provider, Service: svc, Region: region, Account: account, Collection: coll, ID: name}.ARN()
		if arn := dyn.Str(obj["arn"]); strings.HasPrefix(arn, "arn:") && svc != "s3" {
			resource = arn
		}
		out = append(out, Result{Source: "scoutsuite", Provider: provider, Account: account, Service: svc, Region: region,
			Resource: resource, Name: name, Check: rule, Control: control, Status: "FAIL",
			Severity: sev(dyn.Str(f["level"])), Title: title, Detail: dyn.Cut(it, 200), Refs: refs,
			Remediation: dyn.Cut(dyn.Text(f, "remediation"), 300)})
	}
	return out
}

// ScoutBlindServices are services in which ScoutSuite checked nothing at all (it could not list them, or they are
// empty).
func ScoutBlindServices(doc map[string]any) []string {
	var out []string
	services := dyn.Map(doc["services"])
	for _, svc := range sortedMapKeys(services) {
		findings := dyn.Map(dyn.Map(services[svc])["findings"])
		if len(findings) == 0 {
			continue
		}
		checked := false
		for _, f := range findings {
			if dyn.Truthy(dyn.Map(f)["checked_items"]) {
				checked = true
			}
		}
		if !checked {
			out = append(out, svc)
		}
	}
	return out
}

func scoutArgv(e *engineCall, out string, run *Run) []string {
	argv := []string{e.path("scout"), e.prov.Kind(), "--no-browser", "--report-dir", out, "--force", "--quiet"}
	switch e.prov.Kind() {
	case "aws":
		argv = append(append(argv, "--profile", e.args.Profile, "--regions"), e.args.Regions...)
	case "gcp":
		argv = append(argv, "--user-account", "--project-id", dynFirst(e.args.Projects))
	case "azure":
		argv = append(append(argv, "--msi", "--subscriptions"), e.args.Subscriptions...)
	}
	if svcs := e.ecfg.List("services"); len(svcs) > 0 {
		argv = append(append(argv, "--services"), svcs...)
		for _, s := range svcs {
			run.Scope[s] = true
		}
	}
	return append(argv, e.ecfg.List("extra_args")...)
}

func dynFirst(l []string) string {
	if len(l) > 0 {
		return l[0]
	}
	return ""
}

// runScoutSuite runs ScoutSuite READ-ONLY and parses its results object. With GCP source adc it does not run:
// ScoutSuite can neither impersonate nor take an access token, so it would scan AS THE OPERATOR.
func runScoutSuite(ctx context.Context, e *engineCall) *Run {
	run := newRun("scoutsuite")
	if e.args.GCPSource == "adc" {
		run.Reason = "scoutsuite cannot act as the audit service account with gcp source adc (use prowler)"
		return run
	}
	out := filepath.Join(e.workdir, "scoutsuite")
	pr := runProcess(ctx, scoutArgv(e, out, run), e.env, e.workdir, time.Duration(Seconds(e.ecfg["timeout"], 3*3600))*time.Second)
	files, err := filepath.Glob(filepath.Join(out, "scoutsuite-results", "scoutsuite_results_*.js"))
	if err != nil || len(files) == 0 {
		run.Reason = "scoutsuite rc=" + strconv.Itoa(pr.rc) + ": " + dyn.Cut(lastLine(dyn.Or(pr.stderr, pr.stdout)), 200)
		return run
	}
	data, err := readLimited(files[0], maxEngineOutput)
	if err != nil {
		run.Reason = "scoutsuite: results unreadable"
		return run
	}
	text := string(data)
	v, err := dyn.Decode([]byte(text[max(strings.Index(text, "{"), 0):]))
	doc, ok := v.(map[string]any)
	if err != nil || !ok {
		run.Reason = "scoutsuite: results are not JSON"
		return run
	}
	run.Results = ParseScoutSuite(doc, e.prov.Kind(), e.prov.Account())
	run.Version = dyn.Str(dyn.Map(doc["last_run"])["version"])
	for _, svc := range ScoutBlindServices(doc) {
		run.error(svc, "scoutsuite checked no "+svc+" resources")
	}
	run.OK = true
	return run
}
