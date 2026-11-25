package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/MIERAI/security-platform/internal/cloud"
	"github.com/MIERAI/security-platform/internal/cloud/dyn"
	"github.com/MIERAI/security-platform/internal/textsafe"
)

const usage = `usage: sp cloud collect                            run the cloud collector (collector protocol: SP_RUN_DIR, SP_INSTANCE)
       sp cloud discover CONFIG.json              discovery gcp: list a project's VM instances (JSON on stdout)
       sp cloud credential-process ACCOUNT.json   (engines) AWS credential_process output
       sp cloud executable-token ACCOUNT.json     (engines) google-auth executable-sourced token output`

// Main runs `sp cloud ...` and returns the exit status: 0 done, 1 failed, 2 usage or configuration error.
func Main(ctx context.Context, args []string, env Env, stdout io.Writer) int {
	if len(args) == 0 {
		return usageError(env.Stderr)
	}
	switch args[0] {
	case "collect":
		if len(args) != 1 {
			return usageError(env.Stderr)
		}
		return collectMain(ctx, env)
	case "discover", "credential-process", "executable-token":
		if len(args) != 2 {
			return usageError(env.Stderr)
		}
		return fileCommand(ctx, args[0], args[1], env, stdout)
	default:
		return usageError(env.Stderr)
	}
}

func usageError(stderr io.Writer) int {
	_, _ = fmt.Fprintln(stderr, usage) // nowhere else to report a failed write
	return 2
}

func collectMain(ctx context.Context, env Env) int {
	err := Collect(ctx, env)
	if err == nil {
		return 0
	}
	_, _ = fmt.Fprintln(env.Stderr, "sp cloud collect: "+textsafe.Line(err.Error())) // the status says it too
	if errors.Is(err, ErrUsage) {
		return 2
	}
	return 1
}

func fileCommand(ctx context.Context, verb, path string, env Env, stdout io.Writer) int {
	deps := cloud.Deps{Getenv: env.Getenv, Now: env.Now, HTTP: env.HTTP, Executable: env.Executable, GOOS: env.GOOS}
	var out []byte
	var err error
	switch verb {
	case "credential-process":
		out, err = cloud.CredentialProcess(ctx, path, deps)
	case "executable-token":
		out, err = cloud.ExecutableToken(ctx, path, deps)
	default:
		out, err = discover(ctx, path, deps)
	}
	if err != nil {
		_, _ = fmt.Fprintln(env.Stderr, "security-platform cloud: "+textsafe.Line(cloud.Reason(err))) // the status says it too
		return 1
	}
	if _, err := stdout.Write(append(out, '\n')); err != nil {
		return 1
	}
	return 0
}

func discover(ctx context.Context, path string, deps cloud.Deps) ([]byte, error) {
	data, err := readLimited(path, maxInstanceFile)
	if err != nil {
		return nil, fmt.Errorf("discovery config unreadable: %s", excName(err))
	}
	v, err := dyn.Decode(data)
	m, ok := v.(map[string]any)
	if err != nil || !ok {
		return nil, errors.New("discovery config is not a JSON object")
	}
	devs, err := cloud.DiscoverGCP(ctx, cloud.Account(m), deps)
	if err != nil {
		return nil, err
	}
	if devs == nil {
		devs = []cloud.Device{}
	}
	out, err := json.Marshal(devs)
	if err != nil {
		return nil, fmt.Errorf("encode devices: %w", err)
	}
	return out, nil
}
