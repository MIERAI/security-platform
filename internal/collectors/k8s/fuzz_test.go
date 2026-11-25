package k8s

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

func fuzzRun(t *testing.T, out string) *clusterRun {
	t.Helper()
	fake := func(context.Context, *rundoc.Cmd) rundoc.Result { return rundoc.Result{Stdout: out} }
	env := &rundoc.Env{Getenv: func(string) string { return "" }, Now: time.Now}
	run := &rundoc.Run{Dir: t.TempDir(), Doc: rundoc.New("k8s", Version, "", time.Now)}
	c := &collector{run: run, env: env, exec: fake, sources: pyjson.NewObject()}
	return &clusterRun{collector: c, cfg: &clusterConfig{name: "f", parts: map[string]bool{}}, asset: "k8s-cluster:f",
		kube: &kubectl{run: fake}}
}

// FuzzKubectlLists: any kubectl output for the lists the collector reads is a result or an error, never a panic.
func FuzzKubectlLists(f *testing.F) {
	f.Add(`{"items": [{"metadata": {"name": "p", "namespace": "n", "uid": "u", "labels": {"a": "b"},
	 "ownerReferences": [{"kind": "ReplicaSet", "name": "x-1234567"}]}, "spec": {"hostNetwork": true,
	 "containers": [{"name": "c", "image": "i", "securityContext": {"privileged": true, "capabilities": {"add": ["ALL"]}}}],
	 "volumes": [{"hostPath": {"path": "/"}}]}, "status": {"phase": "Running"}}]}`)
	f.Add(`{"items": [{"kind": "RoleBinding", "metadata": {"namespace": "n"}, "roleRef": {"kind": "Role", "name": "r"},
	 "subjects": [{"kind": "User", "name": "u"}], "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}]}]}`)
	f.Add(`{"items": [{"metadata": {}, "results": [{"policy": "p", "result": "fail"}], "summary": {"fail": 1, "pass": 2.5, "fail": 3}}]}`)
	f.Add(`{"items": null}`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, out string) {
		cr := fuzzRun(t, out)
		ctx := context.Background()
		_ = cr.workloads(ctx) // errors are gaps; the point is no panic
		_ = cr.rbac(ctx)
		_ = cr.policy(ctx)
		_ = cr.operator(ctx)
	})
}

// FuzzSecretsListing: the custom-columns listing of Secrets.
func FuzzSecretsListing(f *testing.F) {
	f.Add("web   a   Opaque   2020-01-01T00:00:00Z\nweb b helm.sh/release.v1 2020-01-01T00:00:00Z\n")
	f.Add("x y z\n")
	f.Add("a b c not-a-time\n")
	f.Fuzz(func(t *testing.T, out string) {
		_ = fuzzRun(t, out).secrets(context.Background())
	})
}

// FuzzKubeBench: kube-bench's JSON report.
func FuzzKubeBench(f *testing.F) {
	b, _ := json.Marshal(map[string]any{"Controls": []any{map[string]any{"tests": []any{map[string]any{"results": []any{
		map[string]any{"test_number": "1.1", "test_desc": "d", "status": "FAIL", "scored": true, "remediation": "a\nb"},
		map[string]any{"test_number": "1.2", "status": "pass"}}}}}}})
	f.Add(string(b))
	f.Add(`{"Controls": null}`)
	f.Fuzz(func(t *testing.T, out string) {
		_ = fuzzRun(t, "").kubeBenchResults("cis-1.9", out)
	})
}

// FuzzSummary: a PolicyReport summary keeps key order and the last duplicate.
func FuzzSummary(f *testing.F) {
	f.Add(`{"pass": 1, "fail": 2, "pass": 3}`)
	f.Add(`null`)
	f.Add(`{"a": 1e400}`)
	f.Fuzz(func(t *testing.T, s string) {
		var o orderedCounts
		if err := o.UnmarshalJSON([]byte(s)); err != nil {
			return
		}
		seen := map[string]bool{}
		for _, c := range o {
			if seen[c.key] {
				t.Fatalf("duplicate key %q kept", c.key)
			}
			seen[c.key] = true
		}
	})
}
