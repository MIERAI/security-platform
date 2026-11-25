// Package host is the `host` collector (collectors/host/collector.py in Go, `sp collect host`): host and endpoint
// hardening, read-only, through an exec adapter and an OS profile. A profile is a script printing key=value lines
// (collectors/host/profiles, sent unchanged); the checks only read those keys. Every probe has its own time limit
// (probe.sh, probe.ps1): a probe that does not finish prints `probe.timeout=<key>`, and the checks reading that key
// become a narrow coverage gap host:<name>/<part> — "could not check", never a pass — while every other check
// reports. The whole-script limit stays as a backstop; when it fires, the lines printed so far are still used and
// the probes that never ran become gaps the same way.
package host

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/MIERAI/security-platform/collectors"
	"github.com/MIERAI/security-platform/internal/collectors/collkit"
	"github.com/MIERAI/security-platform/internal/collectors/execadapter"
	"github.com/MIERAI/security-platform/internal/collectors/pytext"
	"github.com/MIERAI/security-platform/internal/pyvalue"
	"github.com/MIERAI/security-platform/internal/textsafe"
)

// Version is the collector's version (collectors/host/VERSION; a test keeps them equal).
const Version = "0.4.0"

const (
	probeTimeout     = 20 // seconds per probe
	slowProbeTimeout = 90 // network-dependent probes (update servers), run last
)

// Main runs the collector and returns its exit status.
func Main(ctx context.Context, env collkit.Env) int {
	return collkit.Main(ctx, env, "host", Version, collect)
}

func collect(ctx context.Context, r *collkit.Run) error {
	hosts, err := collkit.Targets(r.Inst, "hosts", "name")
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if err := collectHost(ctx, r, h); err != nil {
			return err
		}
	}
	return nil
}

// timeLimits are a host's probe, slow-probe and whole-script time limits in seconds.
type timeLimits struct{ probe, slow, script int64 }

func limits(h *pyvalue.Map) (timeLimits, error) {
	var l timeLimits
	var err error
	if l.probe, err = pyvalue.ToInt(h.GetOr("probe_timeout", int64(probeTimeout))); err != nil {
		return l, fmt.Errorf("probe_timeout: %w", err)
	}
	if l.slow, err = pyvalue.ToInt(h.GetOr("slow_probe_timeout", int64(slowProbeTimeout))); err != nil {
		return l, fmt.Errorf("slow_probe_timeout: %w", err)
	}
	if l.script, err = pyvalue.ToInt(h.GetOr("script_timeout", max(300, 2*l.slow+120))); err != nil {
		return l, fmt.Errorf("script_timeout: %w", err)
	}
	return l, nil
}

// scriptFor is the profile with its probe helper in front, the limits from the instance config and the end marker.
func scriptFor(profile string, probe, slow int64) (string, error) {
	if profile == "probe" || !collkit.SafeFileName(profile) {
		return "", fmt.Errorf("unknown profile %s", pyvalue.Repr(profile))
	}
	ext := ".sh"
	if profile == "windows" {
		ext = ".ps1"
	}
	body, err := collectors.Script("host/profiles/" + profile + ext)
	if err != nil {
		return "", fmt.Errorf("unknown profile %s", pyvalue.Repr(profile))
	}
	helper, err := collectors.Script("host/profiles/probe" + ext)
	if err != nil {
		return "", err
	}
	p, s := strconv.FormatInt(probe, 10), strconv.FormatInt(slow, 10)
	if profile == "windows" {
		return "$SpProbeTimeout = " + p + "\n$SpProbeSlowTimeout = " + s + "\n" + helper + "\n" + body + "\n'" + endKey + "=1'\n", nil
	}
	return "SP_PROBE_TIMEOUT=" + p + "\nSP_PROBE_SLOW_TIMEOUT=" + s + "\n" + helper + "\n" + body + "\necho " + endKey + "=1\n", nil
}

// target is one configured host, ready to run.
type target struct {
	name, asset, profile string
	exec                 execadapter.Executor
	script               string
	total                time.Duration
}

// prepare reads a host's configuration; a host that cannot run is a gap (reason returned), not an error.
func prepare(r *collkit.Run, h *pyvalue.Map) (*target, string) {
	t := &target{name: pyvalue.Str(h.Value("name"))}
	t.asset = "host:" + t.name
	if !collkit.SafeFileName(t.name) {
		return t, "invalid host name for an evidence file: " + pyvalue.Repr(t.name)
	}
	profile, _ := h.Value("profile").(string) // not text: an unknown profile below
	t.profile = profile
	lim, err := limits(h)
	if err == nil {
		t.script, err = scriptFor(profile, lim.probe, lim.slow)
	}
	if err == nil {
		t.exec, err = execadapter.New(h.Value("exec"), r.Environ)
	}
	if err != nil {
		return t, "invalid configuration: " + err.Error()
	}
	t.total = time.Duration(lim.script) * time.Second
	return t, ""
}

func collectHost(ctx context.Context, r *collkit.Run, h *pyvalue.Map) error {
	if !collkit.InScope(r.Inst, h.Value("name"), "host") {
		return nil // instance scope: another collector covers this asset (not a gap)
	}
	asset := "host:" + pyvalue.Str(h.Value("name"))
	if !pyvalue.Truthy(h.Value("exec")) {
		r.Doc.Gap(asset, pyvalue.Str(h.GetOr("gap", "no exec adapter configured")), nil)
		return nil
	}
	t, why := prepare(r, h)
	if why != "" {
		r.Doc.Gap(asset, why, nil)
		return nil
	}
	var res execadapter.Result
	var err error
	if t.profile == "windows" { // through stdin: a script of any length (cmd.exe caps command lines at 8191)
		res, err = execadapter.PowerShell(ctx, t.exec, t.script, t.total, true)
	} else {
		res, err = t.exec.Run(ctx, []string{"sh", "-s"}, t.script, t.total, true)
	}
	if err != nil {
		if errors.Is(err, execadapter.ErrOutputTooLarge) {
			r.Doc.Gap(asset, "exec failed: "+err.Error(), nil)
			return nil
		}
		return fmt.Errorf("host %s: %w", t.name, err)
	}
	return evaluate(r, t, res)
}

// evaluate turns one host's output into its coverage, evidence, findings and metric.
func evaluate(r *collkit.Run, t *target, res execadapter.Result) error {
	o := parse(res.Out)
	if res.RC != 0 && !printedAnything(o.kv) {
		r.Doc.Gap(t.asset, "exec failed rc="+strconv.Itoa(res.RC)+": "+pytext.Tail(pytext.Strip(res.Err), maxErrorTail), nil)
		return nil
	}
	miss := unread(o, t.script, res.RC)
	bad := badDates(o.kv)
	for _, k := range bad.keys {
		miss.set(k, bad.vals[k])
	}
	for _, k := range miss.keys {
		o.kv.delete(k) // "unknown" is not a value: no check may read it
	}
	gaps := narrowGaps(miss)
	ev, err := r.Doc.Raw(r.Dir, t.name+".json", evidence(t.profile, o, res.RC, miss))
	if err != nil {
		return err
	}
	r.Doc.OK(t.asset)
	c := &checker{doc: r.Doc, asset: t.asset, ev: ev, kv: o.kv, now: r.Now()}
	mark := r.Doc.Count()
	c.all()
	wild := c.listeners(o.listen)
	if c.err != nil {
		return c.err
	}
	if !hasPart(gaps, "listeners") {
		r.Doc.Metric("security_host_wildcard_listeners", float64(wild), "Sockets listening on all interfaces",
			map[string]string{"host": t.name})
	}
	// a part with an unread key may still have produced a finding from its OTHER keys (e.g. ufw inactive, nft
	// unknown): that is a guess, not an observation - drop it, the narrow gap stands for the whole part
	var blocked []string
	for _, g := range gaps {
		blocked = append(blocked, g.checks...)
	}
	r.Doc.DropSince(mark, func(check string) bool { return matchAny(check, blocked) })
	for _, g := range gaps {
		r.Doc.Gap(t.asset+"/"+g.part, pytext.Head(t.name+" "+g.part+": could not check ("+g.why+")", 300), g.checks)
		_, _ = fmt.Fprintln(r.Stderr, textsafe.Line("[host] "+t.name+": "+g.part+" could not be checked: "+g.why)) // informational
	}
	return nil
}

func printedAnything(kv *ordered) bool {
	for _, k := range kv.keys {
		if k != endKey {
			return true
		}
	}
	return false
}

func hasPart(gaps []narrowGap, name string) bool {
	for _, g := range gaps {
		if g.part == name {
			return true
		}
	}
	return false
}

func evidence(profile string, o output, rc int, miss *ordered) *pyvalue.Map {
	listen := make([]any, len(o.listen))
	for i, l := range o.listen {
		listen[i] = l
	}
	m := pyvalue.NewMap()
	m.Set("profile", profile)
	m.Set("kv", o.kv.pyMap())
	m.Set("listen", listen)
	m.Set("rc", int64(rc))
	m.Set("unread", miss.pyMap())
	return m
}
