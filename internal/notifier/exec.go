package notifier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// sshBase are the options every ssh call gets (adapters/exec.py SSH.BASE): never prompt, never trust a new host key.
func sshBase() []string {
	return []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes"}
}

// execNotifier pipes the text into a command, locally or on a host through ssh; a non-zero exit is a failure.
func execNotifier(ctx context.Context, env Env, cfg *pyvalue.Map, text string) error {
	argv, err := stringList(cfg.Value("argv"), "argv")
	if err != nil {
		return err
	}
	if len(argv) == 0 {
		return fmt.Errorf("%w: argv is empty", ErrConfig)
	}
	full, err := commandLine(cfg.Value("exec"), argv)
	if err != nil {
		return err
	}
	run := env.Run
	if run == nil {
		run = runLocal
	}
	rc, stderr, err := run(ctx, full, text)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrDelivery, err)
	}
	if rc != 0 {
		return fmt.Errorf("%w: rc=%d: %s", ErrDelivery, rc, tailChars(strings.TrimSpace(stderr), maxErrTail))
	}
	return nil
}

func stringList(v any, key string) ([]string, error) {
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: %s must be a list", ErrConfig, key)
	}
	out := make([]string, len(l))
	for i, x := range l {
		out[i] = pyvalue.Str(x)
	}
	return out, nil
}

// commandLine is the argument vector that runs argv through the exec adapter configuration (adapters/exec.py).
func commandLine(execCfg any, argv []string) ([]string, error) {
	cfg, _ := execCfg.(*pyvalue.Map)
	if cfg == nil {
		cfg = pyvalue.NewMap()
	}
	switch t := pyvalue.Str(cfg.GetOr("type", "local")); t {
	case "local":
		return argv, nil
	case "ssh":
		host, err := required(cfg, "host")
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(host, "-") {
			return nil, fmt.Errorf("%w: ssh host %s looks like an option", ErrConfig, pyvalue.Repr(host))
		}
		var opts []string
		if o, ok := cfg.Get("options"); ok && o != nil {
			if opts, err = stringList(o, "exec.options"); err != nil {
				return nil, err
			}
		}
		remote := shellJoin(argv)
		if cfg.Value("shell") == "windows" {
			remote = windowsCommandLine(argv)
		}
		return append(append(append([]string{"ssh"}, sshBase()...), opts...), host, remote), nil
	case "ssm", "osquery":
		return nil, fmt.Errorf("%w: exec adapter %s is a documented future adapter", ErrConfig, pyvalue.Repr(t))
	default:
		return nil, fmt.Errorf("%w: unknown exec adapter %s", ErrConfig, pyvalue.Repr(t))
	}
}

// unsafeShell matches a character that needs quoting for a POSIX shell (Python shlex.quote).
var unsafeShell = regexp.MustCompile(`[^\w@%+=:,./-]`)

// shellQuote is Python's shlex.quote.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if !unsafeShell.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

func shellJoin(argv []string) string {
	q := make([]string, len(argv))
	for i, a := range argv {
		q[i] = shellQuote(a)
	}
	return strings.Join(q, " ")
}

// windowsCommandLine is Python's subprocess.list2cmdline (the MS C runtime's quoting rules).
func windowsCommandLine(argv []string) string {
	var b strings.Builder
	for i, arg := range argv {
		if i > 0 {
			b.WriteByte(' ')
		}
		quote := arg == "" || strings.ContainsAny(arg, " \t")
		if quote {
			b.WriteByte('"')
		}
		backslashes := 0
		for _, c := range arg {
			switch c {
			case '\\':
				backslashes++
			case '"':
				b.WriteString(strings.Repeat(`\`, backslashes*2) + `\"`)
				backslashes = 0
			default:
				b.WriteString(strings.Repeat(`\`, backslashes))
				backslashes = 0
				b.WriteRune(c)
			}
		}
		b.WriteString(strings.Repeat(`\`, backslashes))
		if quote {
			b.WriteString(strings.Repeat(`\`, backslashes) + `"`)
		}
	}
	return b.String()
}

// runLocal runs argv with stdin, in its own process group on Unix (stopped as a whole at the deadline), and
// returns the exit status and stderr; 124 and "timeout" when it took longer than ExecTimeout.
func runLocal(ctx context.Context, argv []string, stdin string) (int, string, error) {
	ctx, cancel := context.WithTimeout(ctx, ExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- the user's own configured notifier command
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &limitedWriter{w: &stderr, n: maxStderrRead}
	ownProcessGroup(cmd)
	err := cmd.Run()
	if ctx.Err() != nil {
		return 124, "timeout", nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), stderr.String(), nil
	}
	if err != nil {
		return 0, "", fmt.Errorf("cannot start %s: %w", argv[0], errors.Unwrap(err))
	}
	return 0, stderr.String(), nil
}

// limitedWriter keeps the first n bytes and discards the rest (a chatty command cannot exhaust memory).
type limitedWriter struct {
	w io.Writer
	n int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n > 0 {
		k := min(int64(len(p)), l.n)
		if _, err := l.w.Write(p[:k]); err != nil {
			return 0, err
		}
		l.n -= k
	}
	return len(p), nil
}
