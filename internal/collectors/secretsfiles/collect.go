// Package secretsfiles is the `secrets-files` collector (collectors/secrets-files/collector.py in Go,
// `sp secrets-files collect`): where secrets live, never what they are. It runs the scan program
// (collectors/secrets-files/remote/scan.py, sent unchanged on standard input to the target's python3) through an exec
// adapter; the scan prints metadata only — path, kind, permissions, owner, size, age and boolean properties
// (encrypted, passphrase, embedded key) — and this collector turns that into findings. The collector itself never
// opens a scanned file: no byte of a file's content can reach the document, the evidence or the log.
package secretsfiles

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/MIERAI/security-platform/collectors"
	"github.com/MIERAI/security-platform/internal/collectors/execadapter"
	"github.com/MIERAI/security-platform/internal/collectors/pytext"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Version is the collector's version (collectors/secrets-files/VERSION; a test keeps them equal).
const Version = "0.3.0"

const (
	scanTimeout  = 600 * time.Second
	maxErrorTail = 160
	// loader runs the scan program it reads from stdin, so that the scan settings can be one argument.
	loader = "import sys;exec(sys.stdin.buffer.read().decode('utf-8'))"
)

// Collector is the collector behind `sp secrets-files collect|version`.
func Collector() *rundoc.Collector {
	return &rundoc.Collector{Name: "secrets-files", Version: Version, Collect: func(ctx context.Context, run *rundoc.Run, env *rundoc.Env) error {
		return collect(ctx, &job{Run: run, env: env})
	}}
}

// Main is `sp secrets-files collect|version`; it returns the exit status.
func Main(ctx context.Context, args []string, env *rundoc.Env, stdout io.Writer) int {
	return rundoc.Main(ctx, Collector(), args, env, stdout)
}

// job is one run: the collector-protocol context and the process environment.
type job struct {
	*rundoc.Run
	env *rundoc.Env
}

func collect(ctx context.Context, r *job) error {
	targets, err := rundoc.Targets(r.Instance, "secrets_files", "host")
	if err != nil {
		return err
	}
	script, err := collectors.Script("secrets-files/remote/scan.py")
	if err != nil {
		return err
	}
	for _, t := range targets {
		if err := collectTarget(ctx, r, t, script); err != nil {
			return err
		}
	}
	return nil
}

// scanArgv is the target's command: [sudo -n] python -c LOADER '{"roots": ..., "exclude": ..., "maxdepth": ...}'.
func scanArgv(t *pyvalue.Map, sudo bool) ([]string, error) {
	roots, ok := t.Get("roots")
	if !ok {
		return nil, errors.New("roots missing")
	}
	conf := pyvalue.NewMap()
	conf.Set("roots", roots)
	conf.Set("exclude", t.GetOr("exclude", []any{}))
	conf.Set("maxdepth", t.GetOr("maxdepth", int64(5)))
	js, err := pyjson.Marshal(rundoc.JSON(conf), pyjson.Compact())
	if err != nil {
		return nil, fmt.Errorf("scan settings: %w", err)
	}
	argv := []string{pyvalue.Str(t.GetOr("python", "python3")), "-c", loader, string(js)}
	if sudo {
		argv = append([]string{"sudo", "-n"}, argv...)
	}
	return argv, nil
}

func collectTarget(ctx context.Context, r *job, t *pyvalue.Map, script string) error {
	host := pyvalue.Str(t.Value("host"))
	asset := "host:" + host
	if !rundoc.InScope(r.Instance, t.Value("host"), "secrets-files") {
		return nil // instance scope: another collector covers this asset (not a gap)
	}
	if !pyvalue.Truthy(t.Value("exec")) {
		r.Doc.Gap(asset, pyvalue.Str(t.GetOr("gap", "no exec adapter")), nil)
		return nil
	}
	res, err := scan(ctx, r, t, host, script)
	var sr scanResult
	if err == nil {
		if sr, err = parseScan(res.Out); err != nil {
			err = rundoc.Gap(pytext.Head("scan output unreadable: "+err.Error(), 300))
		}
	}
	if why, ok := rundoc.AsGap(err); ok {
		r.Doc.Gap(asset, why, nil)
		return nil
	}
	if err != nil {
		return fmt.Errorf("host %s: %w", host, err)
	}
	return report(r, host, sr)
}

// scan runs the scan on one target (through sudo -n first when configured, then unprivileged if sudo refuses);
// a target that cannot be scanned returns a gap reason.
func scan(ctx context.Context, r *job, t *pyvalue.Map, host, script string) (execadapter.Result, error) {
	if !rundoc.SafeFileName(host) {
		return execadapter.Result{}, rundoc.Gap("invalid host name for an evidence file: " + pyvalue.Repr(host))
	}
	e, err := execadapter.New(t.Value("exec"), r.env.Environ)
	if err != nil {
		return execadapter.Result{}, rundoc.Gap("invalid configuration: " + err.Error())
	}
	sudo := pyvalue.Truthy(t.Value("sudo"))
	argv, err := scanArgv(t, sudo)
	if err != nil {
		return execadapter.Result{}, rundoc.Gap("invalid configuration: " + err.Error())
	}
	res, err := e.Run(ctx, argv, script, scanTimeout, false)
	if err == nil && res.RC != 0 && sudo {
		res, err = e.Run(ctx, argv[2:], script, scanTimeout, false)
		if err == nil && res.RC == 0 {
			r.Doc.Gap("host:"+host+"/privileged-paths", "sudo -n not available; privileged paths skipped", nil)
		}
	}
	if errors.Is(err, execadapter.ErrOutputTooLarge) {
		return res, rundoc.Gap("scan failed: " + err.Error())
	}
	if err != nil {
		return res, err
	}
	if res.RC != 0 {
		return res, rundoc.Gap("scan failed rc=" + strconv.Itoa(res.RC) + ": " + pytext.Tail(pytext.Strip(res.Err), maxErrorTail))
	}
	return res, nil
}
