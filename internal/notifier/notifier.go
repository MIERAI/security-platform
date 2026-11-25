// Package notifier delivers the short summary (`sp digest`) to people: the Go implementation of
// notifier/notifiers.py, with the same instance configuration (`notify: [...]`) and the same rules. The text is
// aggregates only; secrets (bot tokens, webhook URLs) come from files that must be private (0600) and are never
// printed, logged or put in an error: errors name an HTTP status or a connection failure class, not a URL.
//
// Adapters:
//
//	stdout    {type: stdout}
//	file      {type: file, path: <file>}                         replaced with the latest summary
//	webhook   {type: webhook, url_file: <0600 file> | url: <url>, format?: slack|json|text}
//	telegram  {type: telegram, token_file: <0600 file>, chat_id: <id> | chat_id_file: <file>, api?: <base url>}
//	exec      {type: exec, argv: [cmd, ...], exec?: {type: local} | {type: ssh, host, options?, shell?: posix|windows}}
package notifier

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Limits.
const (
	HTTPTimeout   = 20 * time.Second // per request, as the reference
	ExecTimeout   = 60 * time.Second // per exec notifier
	maxSecret     = 64 << 10         // a secret file
	maxTelegram   = 4000             // characters of text a chat message carries
	maxErrTail    = 120              // characters of a failing command's stderr in the error
	maxStderrRead = 64 << 10
)

// Errors.
var (
	ErrConfig   = errors.New("bad notifier configuration")
	ErrDelivery = errors.New("not delivered")
)

// Env is what the adapters need from the process.
type Env struct {
	Stdout io.Writer
	Getenv func(string) string // HOME, to expand ~ in paths
	Client *http.Client        // nil: one with HTTPTimeout and the environment's proxy settings
	// Run runs an exec notifier's argument vector with the text on its stdin and returns its exit status and
	// stderr; nil: a local process (its own process group on Unix, stopped after ExecTimeout).
	Run func(ctx context.Context, argv []string, stdin string) (int, string, error)
}

// Types lists the adapters.
func Types() []string { return []string{"stdout", "file", "webhook", "telegram", "exec"} }

// Send delivers text through the notifier cfg describes.
func Send(ctx context.Context, env Env, cfg *pyvalue.Map, text string) error {
	if cfg == nil {
		return fmt.Errorf("%w: a notifier is a mapping", ErrConfig)
	}
	switch t := cfg.Value("type"); t {
	case "stdout":
		_, err := fmt.Fprintln(env.Stdout, text)
		return err
	case "file":
		return toFile(env, cfg, text)
	case "webhook":
		return webhook(ctx, env, cfg, text)
	case "telegram":
		return telegram(ctx, env, cfg, text)
	case "exec":
		return execNotifier(ctx, env, cfg, text)
	default:
		return fmt.Errorf("%w: unknown notifier %s (one of %s)", ErrConfig, pyvalue.Repr(t), strings.Join(Types(), ", "))
	}
}

func expandUser(p string, getenv func(string) string) string {
	if p != "~" && !strings.HasPrefix(p, "~/") {
		return p
	}
	if home := getenv("HOME"); home != "" {
		return home + p[1:]
	}
	return p
}

// required returns a string setting of cfg.
func required(cfg *pyvalue.Map, key string) (string, error) {
	v, ok := cfg.Get(key)
	if !ok || v == nil || v == "" {
		return "", fmt.Errorf("%w: %s is required", ErrConfig, key)
	}
	return pyvalue.Str(v), nil
}

// secret reads a secret file: it must not be readable by group or others; its content without surrounding white
// space. The error names the path, never the content.
func secret(env Env, path string) (string, error) {
	p := expandUser(path, env.Getenv)
	fi, err := os.Stat(p)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrConfig, path, errors.Unwrap(err))
	}
	// Windows has no permission bits (ACLs decide; Go reports 0666 for every writable file): not checked there
	if fi.Mode().Perm()&0o077 != 0 && runtime.GOOS != "windows" {
		return "", fmt.Errorf("%w: %s must be mode 0600", ErrConfig, path)
	}
	b, err := readLimited(p, maxSecret)
	if err != nil {
		return "", fmt.Errorf("%w: %s: %w", ErrConfig, path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

func readLimited(path string, limit int64) (b []byte, err error) {
	f, err := os.Open(path) // #nosec G304 -- a path from the user's own instance config
	if err != nil {
		return nil, fmt.Errorf("open: %w", errors.Unwrap(err))
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close: %w", cerr)
		}
	}()
	b, err = io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("larger than %d bytes", limit)
	}
	return b, nil
}

// toFile replaces the file with the summary (written next to it, then renamed: readers never see half a text).
func toFile(env Env, cfg *pyvalue.Map, text string) error {
	path, err := required(cfg, "path")
	if err != nil {
		return err
	}
	p := expandUser(path, env.Getenv)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("%w: %w", ErrDelivery, err)
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(text+"\n"), 0o600); err != nil {
		return fmt.Errorf("%w: %w", ErrDelivery, err)
	}
	if err := os.Rename(tmp, p); err != nil {
		return fmt.Errorf("%w: %w", ErrDelivery, err)
	}
	return nil
}

// headChars is s cut to n characters (code points).
func headChars(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i := 0
	for pos := range s {
		if i == n {
			return s[:pos]
		}
		i++
	}
	return s
}

// tailChars is the last n characters of s.
func tailChars(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}
