// Package execadapter runs a read-only script on a target, non-interactively (adapters/exec.py in Go): `local`
// runs an argument vector on this machine, `ssh` runs it through OpenSSH with batch mode, no password or
// keyboard-interactive authentication and strict host-key checking placed before the instance's own options (ssh
// takes the first value of an option, so instance options cannot weaken them). Nothing goes through a local
// shell; the remote command line is quoted for the remote POSIX shell (shlex.quote) or for cmd.exe
// (`shell: windows`, list2cmdline). PowerShell scripts of any length go on standard input behind a fixed
// -EncodedCommand bootstrap (cmd.exe drops command lines over 8191 characters).
//
// Results are what the Python adapter returns: the exit status (negative signal number when killed by a signal),
// standard output and error decoded as UTF-8 with replacement characters and universal newlines; on timeout
// status 124, error "timeout" and — only when asked for (`partial`) — what was printed before the whole process
// group was stopped. A program that is not installed is status 127, "<program>: not found".
package execadapter

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/MIERAI/security-platform/internal/collectors/pytext"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Errors of the adapter configuration and of a run.
var (
	ErrConfig         = errors.New("invalid exec adapter configuration")
	ErrNotImplemented = errors.New("exec adapter not implemented")
	ErrOutputTooLarge = errors.New("output exceeds its size limit")
)

// Result is the outcome of one run.
type Result struct {
	RC       int
	Out, Err string
}

// Executor runs an argument vector on its target with the script (if any) on standard input.
type Executor interface {
	Run(ctx context.Context, argv []string, stdin string, timeout time.Duration, partial bool) (Result, error)
}

// sshBase are the options every ssh run starts with (adapters/exec.py SSH.BASE).
func sshBase() []string {
	return []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes"}
}

// New returns the executor an instance's `exec:` mapping describes. environ is the environment of the programs it
// starts (also where `ssh` and local programs are looked up: its PATH).
func New(cfg any, environ []string) (Executor, error) {
	m, ok := cfg.(*pyvalue.Map)
	if !ok {
		return nil, fmt.Errorf("%w: exec is a %s, not a mapping", ErrConfig, pyvalue.TypeName(cfg))
	}
	typ := m.GetOr("type", "local")
	switch typ {
	case "local":
		return local{environ: environ}, nil
	case "ssh":
		return newSSH(m, environ)
	case "ssm", "osquery":
		return nil, fmt.Errorf("%w: exec adapter %s is a documented future adapter", ErrNotImplemented, pyvalue.Repr(typ))
	}
	return nil, fmt.Errorf("%w: unknown exec adapter type %s", ErrConfig, pyvalue.Repr(typ))
}

type local struct{ environ []string }

func (l local) Run(ctx context.Context, argv []string, stdin string, timeout time.Duration, partial bool) (Result, error) {
	return run(ctx, l.environ, job{argv: argv, stdin: stdin, timeout: timeout, partial: partial})
}

type sshExec struct {
	environ []string
	host    string
	options []string
	windows bool
}

func newSSH(m *pyvalue.Map, environ []string) (Executor, error) {
	host, ok := m.Value("host").(string)
	if !ok || host == "" {
		return nil, fmt.Errorf("%w: ssh needs host: <ssh alias or address>", ErrConfig)
	}
	if strings.HasPrefix(host, "-") {
		return nil, fmt.Errorf("%w: ssh host %s would be read as an option", ErrConfig, pyvalue.Repr(host))
	}
	var opts []string
	if v := m.Value("options"); v != nil {
		list, isList := v.([]any)
		if !isList {
			return nil, fmt.Errorf("%w: ssh options must be a list of arguments", ErrConfig)
		}
		for _, o := range list {
			s, isStr := o.(string)
			if !isStr {
				return nil, fmt.Errorf("%w: ssh option %s is not text", ErrConfig, pyvalue.Repr(o))
			}
			opts = append(opts, s)
		}
	}
	return sshExec{environ: environ, host: host, options: opts, windows: m.Value("shell") == "windows"}, nil
}

// Command is the local argument vector that runs argv on the target.
func (s sshExec) Command(argv []string) []string {
	var remote string
	if s.windows {
		remote = pytext.CmdLine(argv)
	} else {
		quoted := make([]string, len(argv))
		for i, a := range argv {
			quoted[i] = pytext.ShellQuote(a)
		}
		remote = strings.Join(quoted, " ")
	}
	cmd := append([]string{"ssh"}, sshBase()...)
	cmd = append(cmd, s.options...)
	return append(cmd, s.host, remote)
}

func (s sshExec) Run(ctx context.Context, argv []string, stdin string, timeout time.Duration, partial bool) (Result, error) {
	return run(ctx, s.environ, job{argv: s.Command(argv), stdin: stdin, timeout: timeout, partial: partial})
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
func PowerShell(ctx context.Context, e Executor, script string, timeout time.Duration, partial bool) (Result, error) {
	return e.Run(ctx, PowerShellArgv(), script, timeout, partial)
}
