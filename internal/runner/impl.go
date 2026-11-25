//go:build unix

package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/pyvalue"
	"github.com/MIERAI/security-platform/internal/runner/config"
)

// The implementation switch (contract runner §7), exactly as the Python runner applies it: per component
// `python` (default), `go` (the Go sp binary; the reference when none is found, logged once per process) or
// `shadow` (the reference writes; the Go binary runs on a copy and the outputs are compared). Shadow runs use the
// Python runner's own comparison through runner/bridge.py, so both runners produce the same report files
// (`<run>/shadow-<component>.json`, state/runner/shadow/<component>.json) and the same metrics.
const (
	implPython = "python"
	implGo     = "go"
	implShadow = "shadow"
)

// goCandidates are where the Go binary is looked for when runner.go_binary is unset (then `sp` on PATH).
const goCandidate = "/usr/local/bin/sp"

// implComponents maps each component with more than one implementation to the sp subcommand that implements it.
// A fresh map on every call.
func implComponents() map[string]string {
	return map[string]string{"ledger": "ledger", "remediation": "ledger"}
}

func implValues() []string { return []string{implPython, implGo, implShadow} }

// implSwitch is the per-process state of the switch: what the instance selects, messages already logged, the
// subcommands of each binary probed.
type implSwitch struct {
	selected map[string]string
	once     map[string]bool
	probed   map[string][]string
}

// initImpls reads runner.implementations as the Python runner does: invalid entries are logged once and ignored.
func (r *Runner) initImpls() {
	r.impl = implSwitch{selected: map[string]string{}, once: map[string]bool{}, probed: map[string][]string{}}
	raw := r.inst.Runner.Get("implementations")
	if !config.Truthy(raw) {
		return
	}
	m, ok := raw.(*config.Map)
	if !ok {
		r.logOnce("implementations", fmt.Sprintf("runner.implementations is not a mapping (%s): python everywhere",
			pyvalue.TypeName(raw)))
		return
	}
	comps := implComponents()
	names := make([]string, 0, len(comps))
	for c := range comps {
		names = append(names, "'"+c+"'")
	}
	sort.Strings(names)
	for _, c := range m.Keys {
		v, isText := m.Get(c).(string)
		if _, known := comps[c]; known && isText && (v == implPython || v == implGo || v == implShadow) {
			r.impl.selected[c] = v
			continue
		}
		r.logOnce("impl:"+c, fmt.Sprintf("runner.implementations.%s: %s ignored (components [%s], values ['%s']): python",
			c, pyvalue.Repr(m.Get(c)), strings.Join(names, ", "), strings.Join(implValues(), "', '")))
	}
}

func (r *Runner) logOnce(key, msg string) {
	if !r.impl.once[key] {
		r.impl.once[key] = true
		r.log.Printf("%s", msg)
	}
}

// implementation returns the implementation that runs a component now and, for go and shadow, the Go binary.
// go or shadow without a Go binary fall back to python (logged once; shadow records that nothing was compared).
func (r *Runner) implementation(ctx context.Context, comp, runDir string) (mode, bin string) {
	mode = r.impl.selected[comp]
	if mode == "" || mode == implPython {
		return implPython, ""
	}
	if bin = r.goBinary(ctx, comp); bin != "" {
		return mode, bin
	}
	msg := fmt.Sprintf("implementation %s requested for %s but no Go sp binary with %#q was found; using python",
		mode, comp, implComponents()[comp])
	if mode == implShadow {
		msg += " (no shadow comparison)"
		r.saveShadowUnavailable(comp, runDir)
	}
	r.logOnce("nogo:"+comp, msg)
	return implPython, ""
}

// goBinary is the Go sp binary that implements the component's subcommand, or "": runner.go_binary, else
// /usr/local/bin/sp, then sp on PATH. A candidate must prove it is the Go binary (`version --json`, schema
// version/v1, the subcommand listed); probed once per process.
func (r *Runner) goBinary(ctx context.Context, comp string) string {
	sub := implComponents()[comp]
	var cands []string
	if v := r.inst.Runner.Get("go_binary"); config.Truthy(v) {
		cands = []string{expandUser(config.Str(v), r.environ)}
	} else {
		cands = []string{goCandidate}
		if p, err := lookPath("sp", r.environ); err == nil {
			cands = append(cands, p)
		}
	}
	for _, c := range cands {
		subs, ok := r.impl.probed[c]
		if !ok {
			subs = r.probeGo(ctx, c)
			r.impl.probed[c] = subs
		}
		for _, s := range subs {
			if s == sub {
				return c
			}
		}
	}
	return ""
}

// probeGo returns the Go subcommands of the binary at path (none when it is not the Go sp binary or cannot run).
func (r *Runner) probeGo(ctx context.Context, path string) []string {
	c, err := r.capture(ctx, []string{path, "version", "--json"}, r.environ, 10*time.Second, false)
	if err != nil || c.rc != 0 {
		return nil
	}
	var v struct {
		Schema string `json:"schema"`
		Subs   []any  `json:"go_subcommands"`
	}
	if json.Unmarshal([]byte(c.stdout), &v) != nil || v.Schema != "security-platform/version/v1" {
		return nil
	}
	var out []string
	for _, s := range v.Subs {
		if t, ok := s.(string); ok {
			out = append(out, t)
		}
	}
	return out
}

// saveShadowUnavailable records that a shadow run compared nothing (no Go binary), as the Python runner does.
func (r *Runner) saveShadowUnavailable(comp, runDir string) {
	st := map[string]any{"go_available": false, "component": comp, "at": int64(r.clock.Now()), "run_dir": r.rel(runDir)}
	if err := writeJSON(filepath.Join(r.stateDir, "shadow", comp+".json"), st); err != nil {
		r.log.Printf("shadow %s: %v", comp, err)
	}
}

// jobRemediation is the remediation job (ledger track) with the implementation the instance selects.
func (r *Runner) jobRemediation(ctx context.Context, j *config.Job, runDir string) (int, string) {
	mode, bin := r.implementation(ctx, "remediation", runDir)
	s := script{component: "remediation", log: "remediation.log", args: []string{"--data", r.data, "--instance", r.inst.Path},
		ok: "tracker synced"}
	switch mode {
	case implShadow:
		return r.bridgeJob(ctx, j, runDir)
	case implGo:
		s.argv = []string{bin, "ledger", "track"}
	}
	return r.jobScript(ctx, j, runDir, s)
}
