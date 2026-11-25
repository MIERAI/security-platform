// Package execadapter is the exec adapter (adapters/exec.py) of every Go collector and of the events shipper:
// run a read-only program on a target, non-interactively, with an argument vector (never a local shell command line
// built from strings), in its own process group that is stopped as a whole on timeout.
//
//	{type: local}                                                      run here
//	{type: ssh, host: <alias>, options: [...], shell: posix|windows}   run there through OpenSSH
//
// `ssh` runs with batch mode, no password or keyboard-interactive authentication and strict host-key checking,
// placed before the instance's own options (ssh takes the first value of an option, so instance options cannot
// weaken them); a host that would be read as an option is refused. The remote command line is quoted for the remote
// POSIX shell (shlex.quote) or for cmd.exe (`shell: windows`, list2cmdline). PowerShell scripts of any length go on
// standard input behind a fixed -EncodedCommand bootstrap (cmd.exe drops command lines over 8191 characters).
//
// Results are what the Python adapter returns: the exit status (minus the signal when one ended the process), the
// output decoded as UTF-8 with replacement characters and universal newlines; on timeout status 124, error
// "timeout" and — only when asked for (`partial`) — what was printed before the process group was stopped. A
// program that is not installed is status 127, "<program>: not found". The process itself is run by rundoc.Exec.
package execadapter

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/MIERAI/security-platform/internal/collectors/pytext"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Errors of the adapter configuration and of a run.
var (
	ErrConfig         = errors.New("invalid exec adapter configuration")
	ErrHost           = errors.New("exec adapter ssh: no usable host")
	ErrNotImplemented = errors.New("exec adapter not implemented")
	ErrOutputTooLarge = errors.New("output exceeds its size limit")
)

// Statuses the adapter gives a run itself.
const (
	StatusTimeout  = rundoc.RCTimeout  // stopped by its time limit
	StatusNotFound = rundoc.RCNotFound // the program is not installed
	maxStdout      = 256 << 20         // a package inventory of a large host is a few MB
)

// Result is a finished run.
type Result struct {
	RC       int
	Out, Err string
}

// Runner runs one child process (rundoc.Exec; tests inject fakes).
type Runner func(context.Context, *rundoc.Cmd) rundoc.Result

// Executor runs argument vectors on one target.
type Executor struct {
	ssh     bool
	host    string
	options []string
	windows bool
	environ []string // the programs' environment, also where they are looked up (PATH); nil: this process's
	run     Runner   // nil: rundoc.Exec
}

// sshBase are the options every ssh run starts with (adapters/exec.py SSH.BASE).
func sshBase() []string {
	return []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes"}
}

// New returns the executor an instance's `exec:` mapping describes (nil: local). environ is the environment of the
// programs it starts and the PATH they are looked up on; nil means this process's environment.
func New(cfg any, environ []string) (*Executor, error) {
	e := &Executor{environ: environ}
	if cfg == nil {
		return e, nil
	}
	m, ok := cfg.(*pyvalue.Map)
	if !ok {
		return nil, fmt.Errorf("%w: exec is a %s, not a mapping", ErrConfig, pyvalue.TypeName(cfg))
	}
	switch typ := m.GetOr("type", "local"); typ {
	case "local":
		return e, nil
	case "ssh":
		if err := e.setSSH(m); err != nil {
			return nil, err
		}
		return e, nil
	case "ssm", "osquery":
		return nil, fmt.Errorf("%w: exec adapter %s is a documented future adapter", ErrNotImplemented, pyvalue.Repr(typ))
	default:
		return nil, fmt.Errorf("%w: unknown exec adapter type %s", ErrConfig, pyvalue.Repr(typ))
	}
}

func (e *Executor) setSSH(m *pyvalue.Map) error {
	host, ok := m.Value("host").(string)
	if !ok || host == "" {
		return fmt.Errorf("%w: ssh needs host: <ssh alias or address>", ErrHost)
	}
	if strings.HasPrefix(host, "-") {
		return fmt.Errorf("%w: ssh host %s would be read as an option", ErrHost, pyvalue.Repr(host))
	}
	if v := m.Value("options"); v != nil {
		list, isList := v.([]any)
		if !isList {
			return fmt.Errorf("%w: ssh options must be a list of arguments", ErrConfig)
		}
		for _, o := range list {
			s, isStr := o.(string)
			if !isStr {
				return fmt.Errorf("%w: ssh option %s is not text", ErrConfig, pyvalue.Repr(o))
			}
			e.options = append(e.options, s)
		}
	}
	e.ssh, e.host, e.windows = true, host, m.Value("shell") == "windows"
	return nil
}

// WithRunner returns the executor running its processes through r (tests).
func (e *Executor) WithRunner(r Runner) *Executor {
	c := *e
	c.run = r
	return &c
}

// Local reports whether the executor runs programs on this host.
func (e *Executor) Local() bool { return !e.ssh }

// Command is the local argument vector that runs argv on the target.
func (e *Executor) Command(argv []string) []string {
	if !e.ssh {
		return argv
	}
	var remote string
	if e.windows {
		remote = pytext.CmdLine(argv)
	} else {
		quoted := make([]string, len(argv))
		for i, a := range argv {
			quoted[i] = pytext.ShellQuote(a)
		}
		remote = strings.Join(quoted, " ")
	}
	cmd := append([]string{"ssh"}, sshBase()...)
	cmd = append(cmd, e.options...)
	return append(cmd, e.host, remote)
}

// Run runs argv on the target with stdin ("" : none) and a time limit; partial keeps the output printed before a
// timeout. The error is ErrOutputTooLarge only: everything else is in the result's status.
func (e *Executor) Run(ctx context.Context, argv []string, stdin string, timeout time.Duration, partial bool) (Result, error) {
	if len(argv) == 0 {
		return Result{}, fmt.Errorf("%w: empty argument vector", ErrConfig)
	}
	full := e.Command(argv)
	run := e.run
	if run == nil {
		run = rundoc.Exec
		if e.environ == nil { // this process's environment: its PATH
			if p, err := exec.LookPath(full[0]); err == nil {
				full[0] = p
			}
		}
	}
	var in io.Reader
	if stdin != "" {
		in = strings.NewReader(stdin)
	}
	res := run(ctx, &rundoc.Cmd{Argv: full, Env: e.environ, Stdin: in, Timeout: timeout, MaxOut: maxStdout,
		Partial: partial})
	timedOut := res.RC == StatusTimeout && res.Stderr == "timeout"
	if res.Truncated && !timedOut {
		return Result{}, ErrOutputTooLarge
	}
	rc := res.RC
	if res.Signal > 0 {
		rc = -res.Signal // Python's returncode
	}
	return Result{RC: rc, Out: pytext.Decode([]byte(res.Stdout)), Err: pytext.Decode([]byte(res.Stderr))}, nil
}

// Output runs argv on the target without standard input and returns its result; output over the size limit is a
// failed run (status 1) like any other.
func (e *Executor) Output(ctx context.Context, argv []string, timeout time.Duration) Result {
	res, err := e.Run(ctx, argv, "", timeout, false)
	if err != nil {
		return Result{RC: 1, Err: err.Error()}
	}
	return res
}

// Reason is a configuration error's text without the sentinel in front (what the reference's exception says).
func Reason(err error) string {
	msg := err.Error()
	for _, s := range []error{ErrNotImplemented, ErrConfig, ErrHost} {
		msg = strings.TrimPrefix(msg, s.Error()+": ")
	}
	return msg
}

// NotInstalled reports whether a result is "the program is not installed" (as opposed to a program that ran and
// failed).
func NotInstalled(r Result) bool {
	return r.RC == StatusNotFound && r.Out == "" && strings.HasSuffix(r.Err, ": not found")
}

// psBootstrap reads the whole script from stdin and runs it; UTF-8 output so that non-ASCII names survive.
const psBootstrap = "[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ProgressPreference='SilentlyContinue';" +
	"$s=@($input) -join [char]10;Invoke-Expression $s"

// PowerShellArgv is the argument vector that runs a PowerShell script given on standard input.
func PowerShellArgv() []string {
	u := utf16.Encode([]rune(psBootstrap))
	b := make([]byte, 2*len(u))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2*i:], c)
	}
	return []string{"powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(b)}
}

// PowerShell runs a PowerShell script (ASCII source) of any length through e.
func PowerShell(ctx context.Context, e *Executor, script string, timeout time.Duration, partial bool) (Result, error) {
	return e.Run(ctx, PowerShellArgv(), script, timeout, partial)
}
