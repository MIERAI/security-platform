//go:build unix

package runner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/MIERAI/security-platform/internal/runner/config"
)

// runJob runs one job of any type in its run directory and returns (exit code, note) as contract §4 records them.
func (r *Runner) runJob(ctx context.Context, j *config.Job, runDir string) (int, string) {
	switch j.Type {
	case config.TypeCollector, config.TypeCommand:
		return r.jobCollector(ctx, j, runDir)
	case config.TypeRemediation:
		return r.jobScript(ctx, j, runDir, script{component: "remediation", log: "remediation.log",
			args: []string{"--data", r.data, "--instance", r.inst.Path}, ok: "tracker synced"})
	case config.TypeExport:
		args := []string{"--data", r.data, "--instance", r.inst.Path}
		if config.Truthy(j.Raw.Get("dry_run")) {
			args = append(args, "--dry-run")
		}
		return r.jobScript(ctx, j, runDir, script{component: "export", log: "export.log", args: args, ok: "exported"})
	case config.TypeDigest:
		args := []string{"--data", r.data}
		if config.Truthy(j.Raw.Get("days")) {
			args = append(args, "--days", config.Str(j.Raw.Get("days")))
		}
		rc, _ := r.jobScript(ctx, j, runDir, script{component: "digest", log: "digest.log", args: args})
		return rc, "digest written" // the reference notes this whatever the exit code
	case config.TypeNotify:
		days := j.Raw.Get("days")
		if days == nil {
			days = int64(1)
		}
		return r.jobScript(ctx, j, runDir, script{component: "notify", log: "notify.log", ok: "summary sent",
			args: []string{"--data", r.data, "--instance", r.inst.Path, "--days", config.Str(days)}})
	case config.TypeEvents:
		return r.jobEvents(ctx, j, runDir)
	default: // ingest, push, snapshot, pull-snapshot: the Python implementation, unchanged
		return r.bridgeJob(ctx, j, runDir)
	}
}

// script is a job that runs one product program and succeeds with its exit code 0.
type script struct {
	component string
	log       string
	args      []string
	ok        string
}

func (r *Runner) jobScript(ctx context.Context, j *config.Job, runDir string, s script) (int, string) {
	argv, err := r.program(s.component)
	if err != nil {
		return 64, err.Error()
	}
	rc, err := r.spawn(ctx, spawnSpec{argv: append(argv, s.args...), env: r.jobEnv(j, runDir), timeout: j.Timeout,
		logPath: filepath.Join(runDir, s.log), job: j.Name})
	if err != nil {
		return rcInternal, failureNote(err)
	}
	if rc == 0 {
		return 0, s.ok
	}
	return rc, fmt.Sprintf("%s rc=%d (see %s)", s.component, rc, s.log)
}

// jobEnv is a job's environment (contract §4): the allowed part of the runner's environment, SP_INSTANCE,
// SP_DATA, SP_RUN_DIR, SP_INPUT_DIR, SP_INSTANCE_NAME, the job's env, SP_COLLECTOR_NAME when `as:` is set.
func (r *Runner) jobEnv(j *config.Job, runDir string) []string {
	e := r.filter.base(r.environ)
	e["SP_INSTANCE"], e["SP_DATA"], e["SP_RUN_DIR"] = r.inst.Path, r.data, runDir
	e["SP_INPUT_DIR"], e["SP_INSTANCE_NAME"] = r.latest, r.inst.Name
	for _, k := range j.EnvKeys() {
		e[k] = j.Env[k]
	}
	if j.As != "" {
		e["SP_COLLECTOR_NAME"] = j.As
	}
	return envList(e)
}

// productEnv is the environment of the product's own programs run outside a job (ledger merge, scorecard).
func (r *Runner) productEnv() []string {
	return envList(r.filter.base(r.environ))
}

// jobCollector runs a collector or command job (contract §4 "Success of a collector/command job").
func (r *Runner) jobCollector(ctx context.Context, j *config.Job, runDir string) (int, string) {
	var argv []string
	if len(j.Argv) > 0 {
		for _, a := range j.Argv {
			argv = append(argv, expandUser(a, r.environ))
		}
	} else {
		var err error
		if argv, err = r.program("collectors/" + j.Collector); err != nil {
			return 64, err.Error()
		}
	}
	col := j.Report()
	rc, err := r.spawn(ctx, spawnSpec{argv: argv, env: r.jobEnv(j, runDir), timeout: j.Timeout,
		logPath: filepath.Join(runDir, col+".log"), job: j.Name})
	if err != nil {
		return rcInternal, failureNote(err)
	}
	doc := filepath.Join(runDir, col+".findings.json")
	_, statErr := os.Stat(doc)
	if rc != 0 || statErr != nil {
		has := "yes"
		if statErr != nil {
			has = "no"
		}
		note := fmt.Sprintf("collector exited rc=%d, document=%s", rc, has)
		if rc == 0 {
			rc = 1 // exit 0 without a document is a failure: no document != secure
		}
		return rc, note
	}
	out, err := r.bridge(ctx, "collector-finish", "--job", j.Name, "--run-dir", runDir, "--stamp", r.stamp())
	if err != nil {
		return rcInternal, failureNote(err)
	}
	if !out.Merge {
		return out.RC, out.Note
	}
	return r.ledger(ctx, runDir)
}

// stamp is the outbox name prefix (%Y%m%dT%H%M%S of the runner's clock).
func (r *Runner) stamp() string {
	return r.clock.Time(r.loc).Format("20060102T150405")
}

// bridgeJob runs a job type that is implemented in the Python runner only (runner/bridge.py job).
func (r *Runner) bridgeJob(ctx context.Context, j *config.Job, runDir string) (int, string) {
	out, err := r.bridge(ctx, "job", "--job", j.Name, "--run-dir", runDir)
	if err != nil {
		return rcInternal, failureNote(err)
	}
	return out.RC, out.Note
}
