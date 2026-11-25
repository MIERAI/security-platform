package k8s

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// executor runs a read-only script on a node, non-interactively (adapters/exec.py): `local`, or `ssh` with batch
// mode (a password prompt is a failure, never a hang) and strict host key checking.
type executor struct {
	prefix []string // ssh and its options and host; empty for local
	env    []string
	exec   func(context.Context, *rundoc.Cmd) rundoc.Result
}

func newExecutor(cfg *pyvalue.Map, env []string, run func(context.Context, *rundoc.Cmd) rundoc.Result) (*executor, error) {
	typ := "local"
	if cfg.Has("type") {
		typ = rundoc.Str(cfg.Value("type"))
	}
	switch typ {
	case "local":
		return &executor{env: env, exec: run}, nil
	case "ssh":
		host := rundoc.Str(cfg.Value("host"))
		if host == "" || strings.HasPrefix(host, "-") {
			return nil, &kubeError{"KeyError", "'host'"}
		}
		prefix := []string{"ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "PasswordAuthentication=no",
			"-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes"}
		prefix = append(prefix, rundoc.Strings(cfg.Value("options"))...)
		return &executor{prefix: append(prefix, host), env: env, exec: run}, nil
	case "ssm", "osquery":
		return nil, &kubeError{"NotImplementedError", fmt.Sprintf("exec adapter %s is a documented future adapter", pyvalue.Repr(typ))}
	default:
		return nil, &kubeError{"KeyError", pyvalue.Repr(typ)}
	}
}

// run runs argv on the target with stdin; for ssh, argv is one remote command line quoted for a POSIX shell.
func (e *executor) run(ctx context.Context, argv []string, stdin string, timeout time.Duration) rundoc.Result {
	cmd := argv
	if len(e.prefix) > 0 {
		quoted := make([]string, len(argv))
		for i, a := range argv {
			quoted[i] = shellQuote(a)
		}
		cmd = append(append([]string(nil), e.prefix...), strings.Join(quoted, " "))
	}
	return e.exec(ctx, &rundoc.Cmd{Argv: cmd, Env: e.env, Stdin: strings.NewReader(stdin), Timeout: timeout, MaxOut: maxBenchOutput})
}

var shellSafe = regexp.MustCompile(`^[A-Za-z0-9_@%+=:,./-]+$`)

// shellQuote is Python's shlex.quote.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if shellSafe.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
