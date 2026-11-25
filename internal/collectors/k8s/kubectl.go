package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
)

// maxListOutput bounds what one `kubectl get` may print (a large cluster's pods are tens of megabytes).
const maxListOutput = 512 << 20

// kubeError is a failed kubectl call. Its text is the reason a gap records, as the Python collector words it
// (`RuntimeError: <last 200 characters of kubectl's stderr>`), so both implementations write the same documents.
type kubeError struct {
	kind string // the Python exception name the reference reports: RuntimeError, TimeoutExpired, JSONDecodeError
	msg  string
}

func (e *kubeError) Error() string { return e.kind + ": " + rundoc.Cut(e.msg, 200) }

// notFound reports whether kubectl said the resource type does not exist (a CRD that is not installed).
func (e *kubeError) notFound() bool { return strings.Contains(e.msg, "doesn't have a resource type") }

// kubectl runs the cluster's kubectl, read verbs only: every call goes through get or whoami, and argv refuses
// anything else, so no code path can change a cluster.
type kubectl struct {
	kubeconfig string // "" = kubectl's own default / in-cluster configuration
	env        []string
	run        func(context.Context, *rundoc.Cmd) rundoc.Result
}

// readVerbs are the only kubectl verbs the collector ever runs.
func readVerbs() map[string]bool { return map[string]bool{"get": true, "auth whoami": true} }

// argv builds `kubectl [--kubeconfig F] <verb> <args>` for a read verb; any other verb is an error.
func (k *kubectl) argv(verb string, args ...string) ([]string, error) {
	if !readVerbs()[verb] {
		return nil, fmt.Errorf("kubectl %q refused: the collector is read-only", verb)
	}
	for _, a := range args {
		if a == "" {
			return nil, errors.New("kubectl: empty argument")
		}
	}
	out := []string{"kubectl"}
	if k.kubeconfig != "" {
		out = append(out, "--kubeconfig", k.kubeconfig)
	}
	out = append(out, strings.Fields(verb)...)
	return append(out, args...), nil
}

// call runs one read verb and returns its standard output.
func (k *kubectl) call(ctx context.Context, timeout time.Duration, verb string, args ...string) (string, error) {
	argv, err := k.argv(verb, args...)
	if err != nil {
		return "", err
	}
	res := k.run(ctx, &rundoc.Cmd{Argv: argv, Env: k.env, Timeout: timeout, MaxOut: maxListOutput})
	switch {
	case res.RC == rundoc.RCTimeout:
		return "", &kubeError{"TimeoutExpired", fmt.Sprintf("kubectl %s timed out after %d seconds", verb, int(timeout.Seconds()))}
	case res.RC == rundoc.RCNotFound:
		return "", &kubeError{"FileNotFoundError", "[Errno 2] No such file or directory: 'kubectl'"}
	case res.RC != 0:
		return "", &kubeError{"RuntimeError", lastChars(strings.TrimSpace(res.Stderr), 200)}
	case res.Truncated:
		return "", &kubeError{"RuntimeError", fmt.Sprintf("kubectl %s printed more than %d bytes", verb, maxListOutput)}
	}
	return res.Stdout, nil
}

// get lists a resource (`get <resource> [-A] -o json`) and decodes its items into T.
func get[T any](ctx context.Context, k *kubectl, resource string, allNamespaces bool) ([]T, error) {
	args := []string{resource}
	if allNamespaces {
		args = append(args, "-A")
	}
	out, err := k.call(ctx, 120*time.Second, "get", append(args, "-o", "json")...)
	if err != nil {
		return nil, err
	}
	var list struct {
		Items []T `json:"items"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		return nil, &kubeError{"JSONDecodeError", err.Error()}
	}
	return list.Items, nil
}

// lastChars is s[-n:] (characters).
func lastChars(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[len(r)-n:])
}
