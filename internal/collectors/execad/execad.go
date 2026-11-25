// Package execad is the exec adapter (adapters/exec.py) for the Go collectors and the events shipper: run a
// read-only program on a target, non-interactively, with an argument vector (never a shell command line built from
// strings), in its own process group that is killed as a whole on timeout.
//
//	{type: local}                                     run here
//	{type: ssh, host: <alias>, options: [...], shell: posix|windows}   run there (BatchMode: never prompts)
//
// On timeout the result is rc 124 with stderr "timeout" and no output unless partial output was asked for.
package execad

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Exit codes the adapter reports itself.
const (
	RCTimeout  = 124
	RCNotFound = 127
	maxOutput  = 64 << 20
	waitDelay  = 5 * time.Second
)

// ErrUnsupported is returned for adapter types that are documented but not implemented (ssm, osquery) or unknown.
var ErrUnsupported = errors.New("exec adapter not implemented")

// sshBase are the options every ssh run gets (adapters/exec.py SSH.BASE): never prompt, verify host keys.
func sshBase() []string {
	return []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes"}
}

// Result is a finished run.
type Result struct {
	RC       int
	Out, Err string
}

// Executor runs an argument vector on its target.
type Executor struct {
	kind    string // local | ssh
	host    string
	options []string
	windows bool
}

// FromConfig reads an exec adapter config (a mapping; nil = local).
func FromConfig(cfg any) (*Executor, error) {
	m, _ := cfg.(*pyvalue.Map) // nil or another type: the default, local
	kind := "local"
	if t, ok := m.Value("type").(string); ok {
		kind = t
	}
	switch kind {
	case "local":
		return &Executor{kind: kind}, nil
	case "ssh":
		host, _ := m.Value("host").(string) // validated below
		if host == "" || strings.HasPrefix(host, "-") {
			return nil, fmt.Errorf("exec adapter ssh: host %q is not a host name", host)
		}
		var opts []string
		for _, o := range listOf(m.Value("options")) {
			s, ok := o.(string)
			if !ok {
				return nil, errors.New("exec adapter ssh: options must be strings")
			}
			opts = append(opts, s)
		}
		shell, _ := m.Value("shell").(string) // absent: posix
		return &Executor{kind: kind, host: host, options: opts, windows: shell == "windows"}, nil
	case "ssm", "osquery":
		return nil, fmt.Errorf("%w: exec adapter %q is a documented future adapter", ErrUnsupported, kind)
	default:
		return nil, fmt.Errorf("%w: exec adapter %q unknown", ErrUnsupported, kind)
	}
}

func listOf(v any) []any {
	l, _ := v.([]any) // anything else: empty
	return l
}

// Local reports whether the executor runs programs on this host.
func (e *Executor) Local() bool { return e.kind == "local" }

// Argv is the local argument vector that runs argv on the target.
func (e *Executor) Argv(argv []string) []string {
	if e.kind != "ssh" {
		return argv
	}
	remote := QuotePOSIX(argv)
	if e.windows {
		remote = QuoteWindows(argv)
	}
	out := append([]string{"ssh"}, sshBase()...)
	out = append(out, e.options...)
	return append(out, e.host, remote)
}

// Run runs argv on the target with stdin (nil: none) and a timeout.
func (e *Executor) Run(ctx context.Context, argv []string, stdin []byte, timeout time.Duration, partial bool) Result {
	if len(argv) == 0 {
		return Result{RC: RCNotFound, Err: "empty argument vector"}
	}
	full := e.Argv(argv)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, full[0], full[1:]...) // #nosec G204 -- argument vector, no shell; programs from the instance config or the collector
	setGroup(cmd)
	cmd.WaitDelay = waitDelay
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var out, errb capped
	out.n, errb.n = maxOutput, maxOutput
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if ctx.Err() != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		res := Result{RC: RCTimeout, Err: "timeout"}
		if partial {
			res.Out = Decode(out.b.Bytes())
		}
		return res
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		return Result{RC: 0, Out: Decode(out.b.Bytes()), Err: Decode(errb.b.Bytes())}
	case errors.As(err, &exitErr):
		return Result{RC: exitErr.ExitCode(), Out: Decode(out.b.Bytes()), Err: Decode(errb.b.Bytes())}
	default:
		return Result{RC: RCNotFound, Err: err.Error()}
	}
}

// Decode is bytes.decode("utf-8", errors="replace") as the adapter reads output: invalid bytes become U+FFFD.
func Decode(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var sb strings.Builder
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		sb.WriteRune(r) // RuneError for an invalid byte
		b = b[size:]
	}
	return sb.String()
}

// capped keeps at most n bytes of a stream and discards the rest.
type capped struct {
	b bytes.Buffer
	n int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.n - c.b.Len(); room > 0 {
		if len(p) > room {
			c.b.Write(p[:room])
		} else {
			c.b.Write(p)
		}
	}
	return len(p), nil
}

// QuotePOSIX is " ".join(shlex.quote(a) for a in argv).
func QuotePOSIX(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = shQuote(a)
	}
	return strings.Join(parts, " ")
}

func shQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("@%+=:,./-_", r) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// QuoteWindows is subprocess.list2cmdline(argv): the quoting rules of the Microsoft C runtime.
func QuoteWindows(argv []string) string {
	parts := make([]string, len(argv))
	for i, a := range argv {
		parts[i] = winQuote(a)
	}
	return strings.Join(parts, " ")
}

func winQuote(arg string) string {
	need := arg == "" || strings.ContainsAny(arg, " \t")
	var b strings.Builder
	if need {
		b.WriteByte('"')
	}
	slashes := 0
	for _, c := range arg {
		switch c {
		case '\\':
			slashes++
		case '"':
			b.WriteString(strings.Repeat(`\`, slashes*2) + `\"`)
			slashes = 0
		default:
			b.WriteString(strings.Repeat(`\`, slashes))
			slashes = 0
			b.WriteRune(c)
		}
	}
	b.WriteString(strings.Repeat(`\`, slashes))
	if need {
		b.WriteString(strings.Repeat(`\`, slashes))
		b.WriteByte('"')
	}
	return b.String()
}
