package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

// writePrivate writes a file readable by its owner only (0600), replacing an existing one.
func writePrivate(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- a file in the run's private directory
	if err != nil {
		return failf("engine credentials: cannot write a private file: %s", pyExcName(err))
	}
	_, werr := f.Write(data)
	cerr := f.Close()
	if err := errors.Join(werr, cerr); err != nil {
		return failf("engine credentials: cannot write a private file: %s", pyExcName(err))
	}
	return nil
}

func writeJSONPrivate(path string, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return failf("engine credentials: %s", err)
	}
	return writePrivate(path, data)
}

// callbackCommand is the command line an engine runs to get credentials from sp: `<sp> cloud <verb> <file>`,
// quoted for the shell the SDKs use (sh -c on Unix, cmd.exe on Windows).
func callbackCommand(deps Deps, verb, file string) string {
	if deps.GOOS == "windows" {
		return `"` + deps.Executable + `" cloud ` + verb + ` "` + file + `"`
	}
	return ShellQuote(deps.Executable) + " cloud " + verb + " " + ShellQuote(file)
}

func devNull(goos string) string {
	if goos == "windows" {
		return "NUL"
	}
	return "/dev/null"
}

// LoadAccountFile reads an account entry written by EngineEnv.
func LoadAccountFile(path string) (Account, error) {
	data, err := readSmallFile(path)
	if err != nil {
		return nil, failf("account file unreadable: %s", pyExcName(err))
	}
	v, err := dyn.Decode(data)
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		return nil, failf("account file is not a JSON object")
	}
	return Account(m), nil
}

// CredentialProcess is the AWS `credential_process` output for an account file: temporary credentials, freshly
// acquired (the engine's SDK caches and asks again before Expiration).
func CredentialProcess(ctx context.Context, path string, deps Deps) ([]byte, error) {
	cfg, err := LoadAccountFile(path)
	if err != nil {
		return nil, err
	}
	p, err := newAWS(cfg, deps)
	if err != nil {
		return nil, err
	}
	c, err := p.Credentials(ctx)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(map[string]any{"Version": 1, "AccessKeyId": c.AccessKeyID,
		"SecretAccessKey": c.SecretAccessKey, "SessionToken": c.SessionToken,
		"Expiration": c.Expires.UTC().Format("2006-01-02T15:04:05Z")})
	if err != nil {
		return nil, fmt.Errorf("encode credentials: %w", err)
	}
	return out, nil
}

// ExecutableToken is google-auth's executable-sourced credential output for an account file: the workload's OIDC
// token (not a cloud credential) and its expiry.
func ExecutableToken(ctx context.Context, path string, deps Deps) ([]byte, error) {
	cfg, err := LoadAccountFile(path)
	if err != nil {
		return nil, err
	}
	tok, err := ReadIdentityToken(ctx, cfg.Map("identity_token"), deps)
	if err != nil {
		return nil, err
	}
	claims, err := JWTClaims(tok)
	if err != nil {
		return nil, err
	}
	exp := deps.now().Add(5 * time.Minute).Unix()
	if f, perr := strconv.ParseFloat(dyn.Str(claims["exp"]), 64); perr == nil && f != 0 {
		exp = int64(f)
	}
	out, err := json.Marshal(map[string]any{"version": 1, "success": true,
		"token_type": jwtTokenType, "id_token": tok, "expiration_time": exp})
	if err != nil {
		return nil, fmt.Errorf("encode token: %w", err)
	}
	return out, nil
}
