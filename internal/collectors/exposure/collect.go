// Package exposure is the exposure collector (collectors/exposure): what an outsider sees. Open TCP ports and which
// HTTP(S) services answer without authentication, seen from a vantage host outside the targets' trust zone.
//
// `sp exposure collect` discovers the targets (static, tailscale, file, gcp), validates every address before it
// can reach a command line, and runs the probe on the vantage: in this process for {type: local}, as
// `sp exposure probe` over ssh otherwise. `sp exposure probe [--ports P] TARGET...` is the probe itself: nmap -sT
// (no root) at a gentle rate, then GET requests only, without credentials, redirects or a proxy.
package exposure

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/execad"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
	"github.com/MIERAI/security-platform/internal/textsafe"
)

// Version is the collector's version (collectors/exposure/VERSION; TestVersionMatchesTree keeps them equal).
const Version = "0.5.0"

// Name is the collector's name.
const Name = "exposure"

const remoteProbeTimeout = time.Hour

// Main is `sp exposure collect|probe ...`.
func Main(ctx context.Context, env *rundoc.Env, args []string, stdout io.Writer) int {
	if len(args) > 0 && args[0] == "probe" {
		return probeMain(ctx, env, stdout, args[1:])
	}
	return rundoc.Main(ctx, &rundoc.Collector{Name: Name, Version: Version, Collect: collect}, args, env, stdout)
}

// collector is one run.
type collector struct {
	env      *rundoc.Env
	runDir   string // SP_RUN_DIR: the evidence goes under it
	run      *rundoc.Run
	doc      *rundoc.Document
	cfg      *pyvalue.Map
	prober   *Prober
	nameOf   map[string]string
	verified map[string]bool
	fromCIDR map[string]bool
}

// collect is one run (collector protocol); the caller writes the document.
func collect(ctx context.Context, run *rundoc.Run, env *rundoc.Env) error {
	prober, err := NewProber()
	if err != nil {
		return err
	}
	c := &collector{runDir: run.Dir, env: env, run: run, doc: run.Doc, cfg: rundoc.MapOr(run.Instance.Value("exposure")), prober: prober,
		nameOf: map[string]string{}, verified: map[string]bool{}, fromCIDR: map[string]bool{}}
	if err := c.collect(ctx); err != nil {
		return err
	}
	return nil
}

func (c *collector) collect(ctx context.Context) error {
	targets, err := c.targets(ctx)
	if err != nil {
		return err
	}
	res, done, err := c.result(ctx, targets)
	if err != nil || done {
		return err
	}
	for k, v := range res.Tools {
		c.doc.Tools.Set(k, pyvalue.Str(v))
	}
	ev, err := c.doc.Raw(c.runDir, "probe.json", rundoc.JSON(res.Value()))
	if err != nil {
		return err
	}
	c.report(res, ev)
	return nil
}

// targets discovers the devices, records their coverage and returns the addresses to scan (in order, once each).
func (c *collector) targets(ctx context.Context) ([]string, error) {
	dc := &discoverer{run: c.prober.Run, env: c.env, home: c.env.Home()}
	var devs []Device
	for _, x := range rundoc.List(c.cfg.Value("discovery")) {
		m := rundoc.MapOr(x)
		found, err := dc.discover(ctx, m)
		if err != nil {
			c.doc.Gap("discovery:"+pyvalue.Str(m.Value("type")), err.Error(), nil)
			continue
		}
		devs = append(devs, found...)
	}
	devs = applyScope(devs, c.run.Instance.Value("scope"))
	values := make([]any, len(devs))
	for i := range devs {
		values[i] = devs[i].value()
	}
	ev, err := c.doc.Raw(c.runDir, "devices.json", rundoc.JSON(values))
	if err != nil {
		return nil, err
	}
	var targets []string
	seen := map[string]bool{}
	for i := range devs {
		if t, ok := c.device(&devs[i], ev); ok && !seen[t] {
			seen[t] = true
			targets = append(targets, t)
		}
	}
	return targets, nil
}

// device records one device's coverage; it returns its address when it is a scan target.
func (c *collector) device(d *Device, ev string) (string, bool) {
	if !pyvalue.Truthy(d.Address) {
		return "", false
	}
	addr, name := pyvalue.Str(d.Address), pyvalue.Str(d.Name)
	host := "host:" + name
	if !ValidTarget(addr) { // never an nmap argument: "-iL file" or "--script x" is not an address
		c.doc.Gap(host, "refused as a scan target: "+pyvalue.Repr(addr)+" is not an IP address or host name", nil)
		return "", false
	}
	c.nameOf[addr] = name
	if d.Online && pyvalue.Truthy(d.Attrs["online_verified"]) {
		c.verified[addr] = true
	}
	if pyvalue.Truthy(d.Attrs["cidr"]) {
		c.fromCIDR[addr] = true
	}
	if !d.Online {
		c.doc.Gap(host, "offline at scan time", nil)
		return "", false
	}
	if !c.fromCIDR[addr] {
		c.doc.OK(host, "")
	}
	if pyvalue.Truthy(d.Attrs["key_expiry_disabled"]) {
		c.doc.AddFinding(&rundoc.Finding{Layer: "identity", Asset: host, Check: "overlay.node_key_expiry_disabled",
			Title: "overlay-network node key never expires", Severity: "low", Evidence: ev, NeedsHuman: true,
			Remediation: "enable key expiry, or record an exception for unattended servers"})

	}
	return addr, true
}

// result is the probe result: SP_EXPOSURE_RAW, or a probe from the vantage. done: there is none, a vantage gap
// was recorded instead.
func (c *collector) result(ctx context.Context, targets []string) (*Result, bool, error) {
	if raw := c.env.Getenv("SP_EXPOSURE_RAW"); raw != "" {
		data, err := rundoc.ReadLimited(raw, maxResult)
		if err != nil {
			return nil, false, fmt.Errorf("SP_EXPOSURE_RAW: %w", err)
		}
		res, err := ParseResult(data)
		if err != nil {
			return nil, false, fmt.Errorf("SP_EXPOSURE_RAW: %w", err)
		}
		return res, false, nil
	}
	res, reason, err := c.probe(ctx, targets)
	if err != nil {
		return nil, false, err
	}
	if reason != "" {
		c.doc.Gap("vantage", reason, nil)
		return nil, true, nil
	}
	return res, false, nil
}

// probe runs the probe on the vantage; a failure is a reason for the vantage gap.
func (c *collector) probe(ctx context.Context, targets []string) (*Result, string, error) {
	if !c.cfg.Has("vantage") {
		return nil, "", fmt.Errorf("%w: exposure.vantage is not set (where the probe runs)", rundoc.ErrUsage)
	}
	vantage := c.cfg.Value("vantage")
	ex, err := execad.FromConfig(vantage)
	if err != nil {
		return nil, "", fmt.Errorf("%w: exposure.vantage: %w", rundoc.ErrUsage, err)
	}
	extra := ""
	if v := c.cfg.Value("extra_ports"); pyvalue.Truthy(v) {
		extra = pyvalue.Str(v)
		if !ValidPorts(extra) {
			return nil, "extra_ports " + pyvalue.Repr(v) + " is not a port list (P,Q,R-S): nothing scanned", nil
		}
	}
	if ex.Local() {
		res, err := c.prober.Probe(ctx, targets, extra)
		if err != nil {
			return nil, "probe failed rc=1: " + err.Error(), nil //nolint:nilerr // a failed probe is a coverage gap, not a failed run
		}
		return res, "", nil
	}
	return c.remoteProbe(ctx, ex, rundoc.StrOr(rundoc.Get(vantage, "sp"), "sp"), targets, extra)
}

func (c *collector) remoteProbe(ctx context.Context, ex *execad.Executor, sp string, targets []string, extra string) (*Result, string, error) {
	if strings.HasPrefix(sp, "-") {
		return nil, "", fmt.Errorf("%w: exposure.vantage.sp %q is not a program", rundoc.ErrUsage, sp)
	}
	r := ex.Run(ctx, remoteArgv(sp, extra, targets), nil, remoteProbeTimeout, false)
	if r.RC != 0 {
		return nil, fmt.Sprintf("probe failed rc=%d: %s", r.RC, tail(r.Err, 200)), nil
	}
	res, err := ParseResult([]byte(r.Out))
	if err != nil {
		return nil, "probe output unreadable: " + err.Error(), nil //nolint:nilerr // unreadable probe output is a coverage gap
	}
	return res, "", nil
}

// remoteArgv is the probe's command line on the vantage (targets and ports validated before).
func remoteArgv(sp, extra string, targets []string) []string {
	argv := []string{sp, "exposure", "probe"}
	if extra != "" {
		argv = append(argv, "--ports", extra)
	}
	return append(argv, targets...)
}

// report turns the probe result into coverage, findings and metrics.
func (c *collector) report(res *Result, ev string) {
	timedOut := map[string]bool{}
	for _, ip := range res.TimedOut {
		timedOut[ip] = true
	}
	unauth, open := 0, 0
	for _, h := range res.Hosts {
		name := h.IP
		if n, ok := c.nameOf[h.IP]; ok {
			name = n
		}
		asset := "net-endpoint:" + name + "@" + h.IP
		if !c.cover(h, name, asset, timedOut[h.IP]) {
			continue
		}
		open += len(h.Ports)
		for _, p := range h.Ports {
			unauth += c.port(h.IP, asset, p, ev)
		}
	}
	c.doc.Metric("security_exposure_open_ports", float64(open), "Open TCP ports seen from the vantage point (all targets)", nil)
	c.doc.Metric("security_exposure_unauth_services", float64(unauth), "Sensitive services answering without auth, seen from the vantage point", nil)

}

// cover records an address's coverage; false when it has no port to report.
func (c *collector) cover(h Host, name, asset string, timedOut bool) bool {
	switch {
	case timedOut: // nmap gave up on it: what was seen is reported, the address is not covered
		c.doc.Gap(asset, "the scan of this address timed out: the open ports are a partial result", nil)
		return len(h.Ports) > 0
	case len(h.Ports) > 0:
		c.doc.OK(asset, "")
		return true
	case c.verified[h.IP]: // discovery saw it online at scan time: nothing open = fully filtered (the goal)
		c.doc.OK(asset, "")
	case c.fromCIDR[h.IP]: // an unused address of a range nobody vouched for: no host there
	default: // -Pn scan of an address nobody vouched for: down or filtered cannot be told apart
		c.doc.Gap("host:"+name, "no open port seen from the vantage point (down or filtered)", nil)
	}
	return false
}

func (c *collector) port(ip, asset string, p Port, ev string) int {
	n := 0
	for _, v := range Classify(p.Num, p.Entry) {
		if v.Check != "metrics.unauth" && v.Check != "http.catch_all_unverified" && v.Check != "otlp.unauth_ingest" {
			n++
		}
		c.doc.AddFinding(&rundoc.Finding{Layer: "network", Asset: asset + ":" + p.Key, Check: v.Check,
			Title: v.Title + " (" + ip + ":" + p.Key + ")", Severity: v.Severity, Evidence: ev + "#" + ip + "/" + p.Key,
			Remediation: v.Remediation, Kind: rundoc.KindDetection})

	}
	return n
}

// probeMain is `sp exposure probe [--ports P] TARGET...`: the probe document on stdout.
func probeMain(ctx context.Context, env *rundoc.Env, stdout io.Writer, args []string) int {
	extra := ""
	if len(args) >= 2 && args[0] == "--ports" {
		extra, args = args[1], args[2:]
	}
	if len(args) == 0 {
		_, _ = fmt.Fprintln(env.Stderr, "usage: sp exposure probe [--ports P,Q] TARGET...") // the status says it too
		return 2
	}
	p, err := NewProber()
	if err == nil {
		var res *Result
		if res, err = p.Probe(ctx, args, extra); err == nil {
			var out []byte
			if out, err = res.Encode(); err == nil {
				_, err = stdout.Write(out)
			}
		}
	}
	if err != nil {
		_, _ = fmt.Fprintln(env.Stderr, "sp exposure probe: "+textsafe.Line(err.Error())) // the status says it too
		return 1
	}
	return 0
}
