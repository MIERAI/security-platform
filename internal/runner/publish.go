//go:build unix

package runner

import (
	"context"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/runner/config"
	"github.com/MIERAI/security-platform/internal/runner/promtext"
)

// maxPromFile bounds one .prom file read into the published metrics.
const maxPromFile = 16 << 20

// publishedMode is the mode of a textfile sink's file: the metrics (aggregates only, by design) are read by
// another user's exporter (node_exporter's textfile collector), as with the reference under the usual umask.
const publishedMode = 0o644

// publishLogged publishes and logs a failure; it reports whether publishing worked.
func (r *Runner) publishLogged(ctx context.Context) bool {
	if err := r.Publish(ctx); err != nil {
		r.log.Printf("publish: %v", err)
		return false
	}
	return true
}

// Publish (role hub) recomputes the scorecard, builds the metrics text, writes it to
// <data>/metrics/security-platform.prom and hands it to every sink (contract §4 "Publish").
func (r *Runner) Publish(ctx context.Context) error {
	if r.inst.Role != "hub" {
		return nil
	}
	r.scorecard(ctx)
	local := filepath.Join(r.data, "metrics", "security-platform.prom")
	if err := writeAtomic(local, []byte(r.MetricsText()), 0o600); err != nil {
		return err
	}
	sinks, _ := r.inst.Runner.Get("sinks").([]any) // not a list: no sinks (the schema requires a list)
	if len(sinks) == 0 {
		return nil
	}
	r.publishSinks(ctx, sinks)
	return writeAtomic(local, []byte(r.MetricsText()), 0o600) // the local copy carries this tick's sink results
}

func (r *Runner) scorecard(ctx context.Context) {
	if !r.inst.Scorecard {
		return
	}
	argv, err := r.program("scorecard")
	if err != nil {
		r.log.Printf("scorecard: %v", err)
		return
	}
	argv = append(argv, "compute", "--data", r.data, "--instance", r.inst.Path, "--now",
		strconv.FormatInt(int64(r.clock.Now()), 10))
	c, err := r.capture(ctx, argv, r.productEnv(), 300*time.Second, false)
	switch {
	case err != nil:
		r.log.Printf("scorecard: %v", err)
	case c.rc != 0:
		r.log.Printf("scorecard: rc=%d: %s", c.rc, tail(c.stderr, 300))
	}
}

func (r *Runner) sinkStatePath() string { return filepath.Join(r.stateDir, "sinks.json") }

func (r *Runner) publishSinks(ctx context.Context, sinks []any) {
	states, ok := readJSONObject(r.sinkStatePath())
	if !ok {
		states = map[string]any{}
	}
	text := r.MetricsText()
	for i, s := range sinks {
		cfg, _ := s.(*config.Map) // not a mapping: its type reads as None and publishing fails below
		key := fmt.Sprintf("%d-%s", i, config.Str(cfg.Get("type")))
		st, ok := states[key].(map[string]any)
		if !ok {
			st = map[string]any{"failures_total": int64(0), "consecutive_failures": int64(0)}
			states[key] = st
		}
		st["last_attempt"] = int64(r.clock.Now())
		r.sinkResult(key, State(st), r.deliver(ctx, i, cfg, text))
	}
	if err := writeJSON(r.sinkStatePath(), states); err != nil {
		r.log.Printf("sinks: state: %v", err)
	}
}

func (r *Runner) sinkResult(key string, st State, failure string) {
	if failure == "" {
		if n := st.Int("consecutive_failures", 0); n != 0 {
			r.log.Printf("sink %s: delivered again after %d failed tick(s)", key, n)
		}
		st["last_success"], st["consecutive_failures"], st["last_error"] = int64(r.clock.Now()), int64(0), ""
		return
	}
	st["failures_total"] = st.Int("failures_total", 0) + 1
	st["consecutive_failures"] = st.Int("consecutive_failures", 0) + 1
	st["last_error"] = failure
	r.log.Printf("sink %s: %s (failed %dx in a row; retried next tick)", key, failure, st.Int("consecutive_failures", 0))
}

// deliver hands the text to one sink and returns "" or the failure. A local textfile sink is written here; every
// other sink type (and a textfile written through `exec`) is the Python adapter (adapters/sinks.py).
func (r *Runner) deliver(ctx context.Context, i int, cfg *config.Map, text string) string {
	if cfg == nil {
		return "TypeError: a sink is a mapping"
	}
	if config.Str(cfg.Get("type")) == "textfile" && !config.Truthy(cfg.Get("exec")) {
		path, ok := cfg.Get("path").(string)
		if !ok {
			return "KeyError: 'path'"
		}
		if err := writeAtomic(expandUser(path, r.environ), []byte(text), publishedMode); err != nil {
			return "OSError: " + truncate(err.Error(), 200)
		}
		return ""
	}
	tmp := filepath.Join(r.stateDir, fmt.Sprintf(".sink-%d.prom", i))
	if err := writeAtomic(tmp, []byte(text), 0o600); err != nil {
		return "OSError: " + truncate(err.Error(), 200)
	}
	out, err := r.bridge(ctx, "sink", "--index", strconv.Itoa(i), "--text", tmp)
	if rerr := removeIfExists(tmp); rerr != nil {
		r.log.Printf("sink %d: %v", i, rerr)
	}
	if err != nil {
		return "RunnerError: " + truncate(err.Error(), 200)
	}
	return out.Error
}

// MetricsText is the published text: latest/*.prom, the ledger's, remediation's, export's and scorecard's .prom,
// and the runner's own series, merged by family.
func (r *Runner) MetricsText() string {
	var b strings.Builder
	proms := glob(filepath.Join(r.latest, "*.prom"))
	for _, f := range []string{"ledger.prom", "remediation.prom", "export.prom", "scorecard.prom"} {
		proms = append(proms, filepath.Join(r.data, "metrics", f))
	}
	for _, p := range proms {
		if data, err := readFile(p, maxPromFile); err == nil {
			b.Write(data)
		}
	}
	now := r.clock.Now()
	b.WriteString(promtext.Render(runnerSeries(r.seriesInput(now))))
	b.WriteString(promtext.Render([]promtext.Series{{Name: "security_metrics_published_timestamp_seconds",
		Labels: map[string]string{"site": r.inst.Site}, Value: promtext.Int(int64(now)),
		Help: "When the hub last published these metrics"}}))
	return promtext.Merge(b.String())
}

func (r *Runner) seriesInput(now float64) seriesInput {
	sinks, ok := readJSONObject(r.sinkStatePath())
	if !ok {
		sinks = map[string]any{}
	}
	in := seriesInput{site: r.inst.Site, release: r.release, now: now, decision: r.clock.Decision(),
		maxGap: r.inst.TickStaleAfter, sinks: sinks, jobs: r.inst.Jobs, loc: r.loc}
	if !r.clock.Fake() {
		in.decision = now
	}
	for _, j := range r.inst.Jobs {
		in.rows = append(in.rows, row{site: r.inst.Site, name: j.Name, st: r.LoadState(j.Name), job: j})
	}
	for i := range r.forwards() {
		name := fmt.Sprintf("forward-%d", i)
		in.rows = append(in.rows, row{site: r.inst.Site, name: name, st: r.LoadState(name)})
	}
	for _, f := range glob(filepath.Join(r.stateDir, "shadow", "*.json")) {
		if m, ok := readJSONObject(f); ok {
			in.shadows = append(in.shadows, State(m))
		}
	}
	return r.siteRows(in)
}

func (r *Runner) siteRows(in seriesInput) seriesInput {
	for _, f := range glob(filepath.Join(r.data, "state", "sites", "*.json")) {
		data, err := readFile(f, maxStateFile)
		if err != nil {
			continue
		}
		sf, ok := decodeSite(data)
		if !ok {
			continue
		}
		for _, n := range sf.names {
			st, _ := sf.jobs[n].(map[string]any) // not an object: every field reads as absent
			in.rows = append(in.rows, row{site: sf.site, name: n, st: State(st)})
		}
	}
	return in
}

func (r *Runner) forwards() []any {
	f, _ := r.inst.Runner.Get("forward").([]any) // absent or not a list: no forwards
	return f
}

// forward is store-and-forward (contract §4 "After the jobs"): each entry reports like a job (forward-<i>).
func (r *Runner) forward(ctx context.Context) {
	for i := range r.forwards() {
		name := fmt.Sprintf("forward-%d", i)
		st := r.LoadState(name)
		t0, started := r.clock.Now(), time.Now()
		st["last_attempt"], st["runs_total"] = int64(t0), st.Int("runs_total", 0)+1
		out, err := r.bridge(ctx, "forward", "--index", strconv.Itoa(i))
		if err != nil {
			out.Error = "RunnerError: " + truncate(err.Error(), 200)
		}
		r.forwardResult(ctx, name, st, out, time.Since(started).Seconds())
	}
}

func (r *Runner) forwardResult(ctx context.Context, name string, st State, out bridgeOut, dur float64) {
	if out.Pending != nil {
		st["pending"] = int64(*out.Pending)
	}
	st["last_rc"], st["last_duration"], st["runner_version"] = int64(0), math.Round(dur*10)/10, Version
	st["last_note"] = fmt.Sprintf("delivered %d", out.Sent)
	if out.Error != "" {
		st["last_rc"], st["last_note"] = int64(75), out.Error
		st["failures_total"] = st.Int("failures_total", 0) + 1
		r.log.Printf("%s: %s (delivered %d; the rest stays queued, retried next tick)", name, out.Error, out.Sent)
	} else {
		st["last_success"] = int64(r.clock.Now())
		if out.Sent > 0 {
			r.log.Printf("%s: delivered %d", name, out.Sent)
		}
	}
	if err := r.SaveState(name, st); err != nil {
		r.log.Printf("%s: state: %v", name, err)
	}
	r.sendState(ctx, name)
}

// sendState sends a job's public state to the state outbox (role site), when one is configured.
func (r *Runner) sendState(ctx context.Context, job string) {
	if !config.Truthy(r.inst.Runner.Get("state_outbox")) {
		return
	}
	if _, err := r.bridge(ctx, "send-state", "--job", job); err != nil {
		r.log.Printf("%s: state outbox: %v", job, err)
	}
}

// prune deletes runs/<date>/ older than runner.retention.
func (r *Runner) prune() {
	if r.inst.Retention <= 0 {
		return
	}
	cutoff := time.Unix(int64(r.clock.Now())-r.inst.Retention, 0).In(r.loc).Format("2006-01-02")
	for _, d := range glob(filepath.Join(r.data, "runs", "????-??-??")) {
		if filepath.Base(d) < cutoff {
			if err := os.RemoveAll(d); err != nil {
				r.log.Printf("prune %s: %v", filepath.Base(d), err)
			}
		}
	}
}
