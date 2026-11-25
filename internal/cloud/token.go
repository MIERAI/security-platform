package cloud

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

const (
	tokenSkew        = 30 * time.Second // a token about to expire is treated as expired
	maxSmallFile     = 1 << 20          // a token, an account entry, ADC, a CA bundle
	tokenCmdDefault  = 30               // seconds
	maxCommandOutput = 1 << 20
)

// ReadIdentityToken reads the workload's OIDC token: {type: file, path} | {type: command, argv} | {type: env,
// name}. It is read fresh on every acquisition and never kept.
func ReadIdentityToken(ctx context.Context, src map[string]any, deps Deps) (string, error) {
	if len(src) == 0 {
		return "", failf("identity_token not configured")
	}
	typ := "file"
	if v, ok := src["type"]; ok {
		typ = dyn.Str(v)
	}
	switch typ {
	case "file":
		return tokenFromFile(src, deps)
	case "env":
		return tokenFromEnv(src, deps)
	case "command":
		return tokenFromCommand(ctx, src)
	default:
		return "", failf("identity_token type %s unknown (file, command, env)", pyRepr(src["type"]))
	}
}

func tokenFromFile(src map[string]any, deps Deps) (string, error) {
	p, ok := src["path"]
	if !ok {
		return "", failf("identity token unavailable: KeyError")
	}
	data, err := readSmallFile(ExpandUser(dyn.Str(p), deps.home()))
	if err != nil {
		return "", failf("identity token unavailable: %s", pyExcName(err))
	}
	return strings.TrimSpace(string(data)), nil
}

func tokenFromEnv(src map[string]any, deps Deps) (string, error) {
	name, ok := src["name"]
	if !ok {
		return "", failf("identity token unavailable: KeyError")
	}
	v := strings.TrimSpace(deps.getenv(dyn.Str(name)))
	if v == "" {
		return "", failf("identity token env %s empty", dyn.Str(name))
	}
	return v, nil
}

func tokenFromCommand(ctx context.Context, src map[string]any) (string, error) {
	argv, err := commandArgv(src["argv"])
	if err != nil || len(argv) == 0 {
		return "", failf("identity token unavailable: KeyError")
	}
	secs := tokenCmdDefault
	if n, aerr := strconv.Atoi(dyn.Str(src["timeout"])); aerr == nil {
		secs = n
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(secs)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // #nosec G204 -- the operator's configured token command, run without a shell
	var out bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &out, n: maxCommandOutput}
	cmd.Stderr = io.Discard
	err = cmd.Run()
	if ctx.Err() != nil {
		return "", failf("identity token unavailable: TimeoutExpired")
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return "", failf("identity token unavailable: %s", pyExcName(err))
	}
	tok := strings.TrimSpace(out.String())
	if code := cmd.ProcessState.ExitCode(); code != 0 || tok == "" {
		return "", failf("identity token command failed (rc=%d)", code)
	}
	return tok, nil
}

func commandArgv(v any) ([]string, error) {
	if l, ok := v.([]any); ok {
		return dyn.Strings(l), nil
	}
	s, ok := v.(string)
	if !ok {
		return nil, errors.New("argv missing")
	}
	return ShellSplit(s)
}

// JWTClaims returns the claims of a JWT without verifying it (the server verifies the signature).
func JWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil, failf("identity token is not a JWT")
	}
	raw, err := base64.URLEncoding.DecodeString(parts[1] + strings.Repeat("=", (4-len(parts[1])%4)%4))
	if err != nil {
		return nil, failf("identity token is not a JWT")
	}
	v, err := dyn.Decode(raw)
	if err != nil {
		return nil, failf("identity token is not a JWT")
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, failf("identity token is not a JWT")
	}
	return m, nil
}

// PrecheckToken is what a client can check before sending a token: expiry and audience.
func PrecheckToken(token, audience string, now time.Time) (map[string]any, error) {
	c, err := JWTClaims(token)
	if err != nil {
		return nil, err
	}
	if exp, ok := c["exp"]; ok && exp != nil {
		f, err := strconv.ParseFloat(dyn.Str(exp), 64)
		if err != nil {
			return nil, failf("identity token is not a JWT")
		}
		if f <= float64(now.Add(tokenSkew).UnixNano())/1e9 {
			return nil, failf("identity token expired")
		}
	}
	if audience != "" && !containsStr(audiences(c["aud"]), audience) {
		return nil, failf("identity token audience mismatch (expected %s)", audience)
	}
	return c, nil
}

func audiences(v any) []string {
	if l, ok := v.([]any); ok {
		return dyn.Strings(l)
	}
	return []string{dyn.Str(v)}
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// pyExcName names an error like the Python exception the reference implementation reports.
func pyExcName(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, exec.ErrNotFound):
		return "FileNotFoundError"
	case errors.Is(err, fs.ErrPermission):
		return "PermissionError"
	case errors.Is(err, errTooLarge):
		return "ValueError"
	default:
		return "OSError"
	}
}

var errTooLarge = errors.New("file too large")

// readSmallFile reads a configuration-sized file (a token, an account entry, ADC, a CA bundle): at most 1 MiB.
func readSmallFile(path string) (data []byte, err error) {
	f, err := os.Open(path) // #nosec G304 -- paths come from the operator's instance config
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			data, err = nil, fmt.Errorf("close: %w", cerr)
		}
	}()
	data, err = io.ReadAll(io.LimitReader(f, maxSmallFile+1))
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}
	if len(data) > maxSmallFile {
		return nil, errTooLarge
	}
	return data, nil
}

// limitedWriter keeps at most n bytes and silently drops the rest (a runaway program cannot exhaust memory).
type limitedWriter struct {
	w io.Writer
	n int64
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if l.n <= 0 {
		return len(p), nil
	}
	keep := p
	if int64(len(keep)) > l.n {
		keep = keep[:l.n]
	}
	n, err := l.w.Write(keep)
	l.n -= int64(n)
	if err != nil {
		return n, fmt.Errorf("buffer output: %w", err)
	}
	return len(p), nil
}
