package cloud

import (
	"context"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/cloud"
	"github.com/MIERAI/security-platform/internal/cloud/dyn"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// Version is the collector's version (collectors/cloud/VERSION; TestVersionMatchesTree keeps them equal).
const Version = "0.3.0"

// engineFunc runs one check engine.
type engineFunc func(ctx context.Context, e *engineCall) *Run

func engines() map[string]engineFunc {
	return map[string]engineFunc{"prowler": runProwler, "steampipe": runSteampipe, "scoutsuite": runScoutSuite}
}

func engineNames() string { return "prowler, steampipe, scoutsuite" }

type evKey struct{ provider, account string }

// evidence is what raw/<name>/<provider>-<account>.json holds about one account.
type evidence struct {
	engines   map[string]any
	imports   []any
	identity  map[string]any
	selfCheck map[string]any
}

type stats struct {
	scanned, gap, refused int
	engines               map[[2]string]int
}

// collector is one run of the cloud collector.
type collector struct {
	deps     cloud.Deps
	tmpBase  string
	environ  []string
	stderr   io.Writer
	doc      *rundoc.Document
	pool     *Pool
	evidence map[evKey]*evidence
	stats    stats
}

func (c *collector) ev(provider, account string) *evidence {
	k := evKey{provider, account}
	if c.evidence[k] == nil {
		c.evidence[k] = &evidence{engines: map[string]any{}, imports: []any{}}
	}
	return c.evidence[k]
}

// scanAccount authenticates, self-verifies and scans one account.
func (c *collector) scanAccount(ctx context.Context, acct cloud.Account, cfg *instanceConfig, defaultRefuse bool) {
	prov, err := cloud.New(acct, c.deps)
	if err != nil {
		ident := dyn.Or(acct.Str("account_id"), acct.Str("project_id"), acct.Str("subscription_id"), acct.Str("name"), "?")
		kind := "unknown"
		if v, ok := acct["provider"]; ok {
			kind = pyStrOrNone(v)
		}
		c.doc.Gap("cloud:"+kind+"/"+ident, cloud.Reason(err), nil)
		c.stats.gap++
		return
	}
	ev := c.ev(prov.Kind(), prov.Account())
	tmp, err := os.MkdirTemp(c.tmpBase, "sp-cloud-")
	if err != nil {
		c.doc.Gap(prov.Asset(), "no private temporary directory: "+err.Error(), nil)
		c.stats.gap++
		return
	}
	defer removeAll(tmp, c.stderr)
	id, err := prov.Identity(ctx)
	if err != nil {
		c.doc.Gap(prov.Asset(), "authentication failed: "+cloud.Reason(err), nil)
		c.stats.gap++
		return
	}
	ev.identity = id.Evidence()
	if !c.selfCheck(ctx, prov, acct, ev, defaultRefuse) {
		return
	}
	names := cfg.engineOrder
	if acct.Has("engines") {
		names = acct.List("engines")
	} else if len(names) == 0 {
		names = []string{"prowler"}
	}
	if len(names) == 0 { // authentication + self-verification only (posture comes from an import, if any)
		return
	}
	c.runEngines(ctx, prov, names, dyn.Map(cfg.cloud["engines"]), tmp)
}

// selfCheck verifies the platform's own permissions; false when the account must not be scanned.
func (c *collector) selfCheck(ctx context.Context, prov cloud.Provider, acct cloud.Account, ev *evidence, defaultRefuse bool) bool {
	perm, err := prov.Permissions(ctx)
	if err != nil {
		reason := cloud.Reason(err)
		if strings.Contains(reason, "does not exist") {
			c.doc.Gap(prov.Asset(), reason, nil)
			c.stats.gap++
			return false
		}
		ev.selfCheck = map[string]any{"error": "could not verify own permissions: " + reason}
		return true
	}
	ev.selfCheck = perm.Evidence()
	if len(perm.WriteCapable) == 0 {
		return true
	}
	ctl := Controls()["cloud.platform_credential_over_privileged"]
	c.doc.AddFinding(finding(&Finding{Layer: "identity", Asset: prov.Asset(), Check: "cloud.platform_credential_over_privileged",
		Title: "the platform's credential for " + prov.Kind() + " " + prov.Account() + " can write: " +
			dyn.Cut(strings.Join(perm.WriteCapable, ", "), 200),
		Severity: "high", Evidence: "raw/" + c.doc.Name + "/" + prov.Kind() + "-" + prov.Account() + ".json#self_check",
		Remediation: ctl.Remediation, NeedsHuman: true,
		Attributes: map[string]any{"pillar": "people", "provider": prov.Kind(), "account": prov.Account()}}))
	if acct.Bool("refuse_over_privileged", defaultRefuse) {
		c.doc.Gap(prov.Asset(), "refused to scan: the platform's credential is over-privileged (read-only expected)", nil)
		c.stats.refused++
		return false
	}
	return true
}

// runEngines runs the configured engines against one account and merges their verdicts.
func (c *collector) runEngines(ctx context.Context, prov cloud.Provider, names []string, ecfgs map[string]any, tmp string) {
	envAdd, args, err := prov.EngineEnv(ctx, tmp)
	if err != nil {
		c.doc.Gap(prov.Asset(), "engine credentials: "+cloud.Reason(err), nil)
		c.stats.gap++
		return
	}
	env := cloud.CleanEnv(c.environ)
	for k, v := range envAdd {
		env[k] = v
	}
	ev := c.ev(prov.Kind(), prov.Account())
	var ok []string
	var runs []*Run
	for _, name := range names {
		fn := engines()[name]
		if fn == nil {
			c.doc.Gap(prov.Asset()+"/engine:"+name, "unknown engine "+name+" ("+engineNames()+")", nil)
			continue
		}
		e := &engineCall{prov: prov, env: env, args: args, ecfg: cloud.Account(dyn.Map(ecfgs[name])), workdir: tmp,
			home: c.home(), warn: c.stderr}
		run := fn(ctx, e)
		c.recordRun(prov, ev, name, run)
		if !run.OK {
			c.doc.Gap(prov.Asset()+"/engine:"+name, dyn.Or(run.Reason, name+" failed"), nil)
			continue
		}
		ok = append(ok, name)
		runs = append(runs, run)
	}
	c.serviceGaps(prov, runs)
	if len(ok) > 0 {
		c.doc.OK(prov.Asset(), "")
		c.stats.scanned++
		return
	}
	parts := make([]string, len(names))
	for i, n := range names {
		reason := "?"
		if m, isMap := ev.engines[n].(map[string]any); isMap {
			reason = dyn.Str(m["reason"])
		}
		parts[i] = n + ": " + reason
	}
	c.doc.Gap(prov.Asset(), "no engine ran: "+dyn.Cut(strings.Join(parts, "; "), 250), nil)
	c.stats.gap++
}

func (c *collector) home() string {
	if h := c.deps.Getenv("HOME"); h != "" {
		return h
	}
	return c.deps.Getenv("USERPROFILE")
}

func (c *collector) recordRun(prov cloud.Provider, ev *evidence, name string, run *Run) {
	errs := map[string]any{}
	for _, s := range run.Errors.keys {
		e := run.Errors.m[s]
		errs[s] = strs(e[:min(3, len(e))])
	}
	ev.engines[name] = map[string]any{"ok": run.OK, "reason": run.Reason, "version": run.Version, "errors": errs,
		"results": len(run.Results)}
	res := "failed"
	if run.OK {
		res = "ok"
	}
	c.stats.engines[[2]string{name, res}]++
	if !run.OK {
		return
	}
	if run.Version != "" {
		c.doc.Tools.Set(name, run.Version)
	}
	for i := range run.Results {
		r := &run.Results[i]
		c.pool.Add(prov.Kind(), dyn.Or(r.Account, prov.Account()), r)
	}
}

// serviceGaps: a service is a gap when an engine could not list it (errors, no verdict) and NO engine covered it
// cleanly (verdicts without errors): its findings are then kept, never "fixed" by a blind run.
func (c *collector) serviceGaps(prov cloud.Provider, runs []*Run) {
	clean := map[string]bool{}
	for _, run := range runs {
		for i := range run.Results {
			if svc := run.Results[i].Service; !run.Errors.has(svc) {
				clean[svc] = true
			}
		}
	}
	for _, run := range runs {
		gaps := run.gapServices()
		svcs := make([]string, 0, len(gaps))
		for s := range gaps {
			svcs = append(svcs, s)
		}
		sort.Strings(svcs)
		for _, svc := range svcs {
			if !clean[svc] {
				c.doc.Gap(prov.Asset()+"/"+ServiceNorm(prov.Kind(), svc),
					dyn.Cut(run.Engine+" could not list "+svc+": "+gaps[svc][0], 300), nil)
			}
		}
	}
}

func strs(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}
