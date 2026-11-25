package cloud

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/cloud"
	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

// engineCall is what an engine run gets: the account, its environment (no secret), the engine's arguments, its
// configuration and the run's private working directory.
type engineCall struct {
	prov    cloud.Provider
	env     map[string]string
	args    cloud.EngineArgs
	ecfg    cloud.Account
	workdir string
	home    string
	warn    io.Writer // warnings (stderr)
}

func (e *engineCall) path(def string) string {
	return cloud.ExpandUser(e.ecfg.StrOr("path", def), e.home)
}

var cisFramework = regexp.MustCompile(`^CIS-([0-9.]+)$`)

// CISRefs turns Prowler's `unmapped.compliance` {"CIS-3.0": ["5.2"], ...} into ["cis-aws:3.0/5.2", ...].
func CISRefs(provider string, compliance map[string]any) []string {
	fws := make([]string, 0, len(compliance))
	for fw := range compliance {
		fws = append(fws, fw)
	}
	sort.Strings(fws)
	out := []string{}
	for _, fw := range fws {
		if m := cisFramework.FindStringSubmatch(fw); m != nil {
			for _, id := range dyn.Strings(compliance[fw]) {
				out = append(out, "cis-"+provider+":"+m[1]+"/"+id)
			}
		}
	}
	return out
}

// ParseProwlerOCSF reads Prowler's json-ocsf output (a list of OCSF Detection Finding events). MANUAL and muted
// verdicts are skipped. provider "" takes the provider from each event.
func ParseProwlerOCSF(doc any, provider string) []Result {
	var out []Result
	for _, item := range dyn.List(doc) {
		x := dyn.Map(item)
		status := dyn.Str(x["status_code"])
		if (status != "FAIL" && status != "PASS") || dyn.Str(x["status"]) == "Suppressed" {
			continue
		}
		out = append(out, prowlerResult(x, status, provider))
	}
	return out
}

func prowlerResult(x map[string]any, status, provider string) Result {
	resources := dyn.List(x["resources"])
	res := map[string]any{}
	if len(resources) > 0 {
		res = dyn.Map(resources[0])
	}
	cl, unmapped, info := dyn.Map(x["cloud"]), dyn.Map(x["unmapped"]), dyn.Map(x["finding_info"])
	prov := dyn.Or(provider, dyn.Text(cl, "provider"), dyn.Str(unmapped["provider"]))
	check := dyn.Or(dyn.Text(dyn.Map(x["metadata"]), "event_code"), dyn.Str(info["uid"]))
	service, _, _ := strings.Cut(check, "_")
	title := check
	if v, ok := info["title"]; ok {
		title = dyn.Str(v)
	}
	return Result{Source: "prowler", Provider: prov, Account: dyn.Text(dyn.Map(cl["account"]), "uid"),
		Service: dyn.Or(dyn.Text(dyn.Map(res["group"]), "name"), service), Region: dyn.Or(dyn.Text(res, "region"), "global"),
		Resource: dyn.Or(dyn.Text(res, "uid"), dyn.Text(res, "name")), Name: dyn.Text(res, "name"), Check: check,
		Control: ControlFor("prowler", check), Status: status, Severity: sev(dyn.Str(x["severity"])),
		Title: title, Detail: dyn.Or(dyn.Text(x, "status_detail"), dyn.Text(x, "message")),
		Refs: CISRefs(prov, dyn.Map(unmapped["compliance"])), Remediation: dyn.Cut(dyn.Text(dyn.Map(x["remediation"]), "desc"), 300)}
}

var whitespaceRE = regexp.MustCompile(`\s+`)

// ProwlerErrors reads Prowler's --log-file (JSON lines): service -> messages of errors raised by a service client.
func ProwlerErrors(logText string) *orderedErrors {
	errs := &orderedErrors{m: map[string][]string{}}
	for _, line := range strings.Split(logText, "\n") {
		v, err := dyn.Decode([]byte(line))
		if err != nil {
			continue
		}
		d := dyn.Map(v)
		mod, level := dyn.Str(d["module"]), dyn.Str(d["level"])
		if (level == "ERROR" || level == "CRITICAL") && strings.HasSuffix(mod, "_service") {
			msg := whitespaceRE.ReplaceAllString(dyn.Str(d["message"]), " ")
			errs.add(strings.TrimSuffix(mod, "_service"), dyn.Cut(msg, 200))
		}
	}
	return errs
}

// prowlerArgv is Prowler's command line for one account.
func prowlerArgv(e *engineCall, out string, run *Run) []string {
	argv := []string{e.path("prowler"), e.prov.Kind()}
	switch e.prov.Kind() {
	case "aws":
		argv = append(append(argv, "--profile", e.args.Profile, "--region"), e.args.Regions...)
	case "gcp":
		argv = append(append(argv, "--project-id"), e.args.Projects...)
		if e.args.ImpersonateServiceAccount != "" {
			argv = append(argv, "--impersonate-service-account", e.args.ImpersonateServiceAccount)
		}
	case "azure":
		argv = append(append(argv, "--managed-identity-auth", "--subscription-ids"), e.args.Subscriptions...)
	}
	if checks := e.ecfg.List("checks"); len(checks) > 0 {
		argv = append(append(argv, "--checks"), checks...)
		for _, c := range checks {
			svc, _, _ := strings.Cut(c, "_")
			run.Scope[svc] = true
		}
	} else if svcs := e.ecfg.List("services"); len(svcs) > 0 {
		argv = append(append(argv, "--services"), svcs...)
		for _, s := range svcs {
			run.Scope[s] = true
		}
	}
	if ex := e.ecfg.List("excluded_checks"); len(ex) > 0 {
		argv = append(append(argv, "--excluded-checks"), ex...)
	}
	if e.ecfg.Bool("scan_unused_services", true) {
		argv = append(argv, "--scan-unused-services")
	}
	argv = append(argv, "--output-formats", "json-ocsf", "-o", out, "-F", "scan", "--no-banner", "--log-level", "ERROR",
		"--log-file", filepath.Join(out, "prowler.log"), "--ignore-exit-code-3")
	return append(argv, e.ecfg.List("extra_args")...)
}

// runProwler runs Prowler READ-ONLY and parses its json-ocsf output.
func runProwler(ctx context.Context, e *engineCall) *Run {
	run := newRun("prowler")
	out := filepath.Join(e.workdir, "prowler")
	if err := os.MkdirAll(out, 0o700); err != nil {
		run.Reason = "prowler: cannot create its output directory"
		return run
	}
	argv := prowlerArgv(e, out, run)
	pr := runProcess(ctx, argv, e.env, e.workdir, time.Duration(Seconds(e.ecfg["timeout"], 3*3600))*time.Second)
	data, err := readLimited(filepath.Join(out, "scan.ocsf.json"), maxEngineOutput)
	if pr.rc != 0 || err != nil {
		run.Reason = "prowler rc=" + strconv.Itoa(pr.rc) + ": " + dyn.Cut(lastLine(pr.stderr, pr.stdout), 200)
		return run
	}
	doc, err := dyn.Decode(data)
	if err != nil {
		run.Reason = "prowler: output is not JSON"
		return run
	}
	run.Results = ParseProwlerOCSF(doc, e.prov.Kind())
	if l := dyn.List(doc); len(l) > 0 {
		run.Version = dyn.Str(dyn.Map(dyn.Map(dyn.Map(l[0])["metadata"])["product"])["version"])
	}
	if lg, err := readLimited(filepath.Join(out, "prowler.log"), maxEngineOutput); err == nil {
		run.Errors = ProwlerErrors(string(lg))
	}
	run.OK = true
	return run
}
