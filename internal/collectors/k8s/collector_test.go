package k8s

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/pytext"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// fakeKube answers kubectl the way the conformance suite's fake does (conformance/tools/fakes/fake_kubectl.py),
// from testdata/clusters.json, in process; it records every argument vector it is given.
type fakeKube struct {
	mu       sync.Mutex
	clusters map[string]map[string]any
	bench    json.RawMessage
	calls    [][]string
}

func newFakeKube(t *testing.T) *fakeKube {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "clusters.json"))
	if err != nil {
		t.Fatal(err)
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		t.Fatal(err)
	}
	f := &fakeKube{clusters: map[string]map[string]any{}, bench: all["kube_bench"]}
	for _, name := range []string{"prod", "lab"} {
		var c map[string]any
		if err := json.Unmarshal(all[name], &c); err != nil {
			t.Fatal(err)
		}
		f.clusters[name] = c
	}
	return f
}

func (f *fakeKube) exec(_ context.Context, c *rundoc.Cmd) rundoc.Result {
	f.mu.Lock()
	f.calls = append(f.calls, slices.Clone(c.Argv))
	f.mu.Unlock()
	if c.Argv[0] == "sh" { // kube-bench on the node
		return rundoc.Result{Stdout: string(f.bench)}
	}
	args := c.Argv[1:]
	name := "in-cluster"
	if len(args) > 1 && args[0] == "--kubeconfig" {
		name = strings.TrimSuffix(filepath.Base(args[1]), ".yaml")
		args = args[2:]
	}
	cl, ok := f.clusters[name]
	if !ok {
		return rundoc.Result{RC: 1, Stderr: "Unable to connect to the server: dial tcp 192.0.2.1:6443: connect: connection refused"}
	}
	if len(args) >= 2 && args[0] == "auth" && args[1] == "whoami" {
		b, _ := json.Marshal(map[string]any{"status": map[string]any{"userInfo": cl["whoami"]}}) // test data
		return rundoc.Result{Stdout: string(b)}
	}
	return f.get(cl, args)
}

func (f *fakeKube) get(cl map[string]any, args []string) rundoc.Result {
	res, _ := cl["resources"].(map[string]any) // test data
	items, ok := res[args[1]]
	switch x := items.(type) {
	case map[string]any:
		return rundoc.Result{RC: 1, Stderr: fmt.Sprint(x["error"])}
	case nil:
		if !ok {
			return rundoc.Result{RC: 1, Stderr: `error: the server doesn't have a resource type "` + args[1] + `"`}
		}
	}
	if slices.Contains(args, "--no-headers") {
		var b strings.Builder
		list, _ := items.([]any) // test data
		for _, it := range list {
			s, _ := it.(map[string]any) // test data
			m, _ := s["metadata"].(map[string]any)
			fmt.Fprintf(&b, "%v   %v   %v   %v\n", m["namespace"], m["name"], s["type"], m["creationTimestamp"])
		}
		return rundoc.Result{Stdout: b.String()}
	}
	out, _ := json.Marshal(map[string]any{"items": items}) // test data
	return rundoc.Result{Stdout: string(out)}
}

type runResult struct {
	dir   string
	doc   map[string]any
	inv   map[string]any
	calls [][]string
}

func runCollector(t *testing.T, fk *fakeKube, instance string) runResult {
	t.Helper()
	dir := t.TempDir()
	inst := filepath.Join(dir, "instance.json")
	if err := os.WriteFile(inst, []byte(instance), 0o600); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(dir, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "kube-bench_0.9.0_linux_amd64.tar.gz"), []byte("tarball"), 0o600); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{"SP_RUN_DIR": filepath.Join(dir, "run"), "SP_INSTANCE": inst, "SP_DATA": data}
	env := &rundoc.Env{Getenv: func(k string) string { return vars[k] }, Stderr: &bytes.Buffer{},
		Now: func() time.Time { return time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC) }}
	run, err := rundoc.Start(env, "k8s", Version)
	if err != nil {
		t.Fatal(err)
	}
	c := &collector{run: run, env: env, exec: fk.exec, sources: pyjson.NewObject()}
	if err := c.collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := run.Doc.Write(run.Dir, env.Errout()); err != nil {
		t.Fatal(err)
	}
	r := runResult{dir: run.Dir, calls: fk.calls}
	r.doc, r.inv = readJSON(t, filepath.Join(run.Dir, "k8s.findings.json")), readJSON(t, filepath.Join(run.Dir, "inventory.k8s-images.json"))
	return r
}

func readJSON(t *testing.T, p string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

const twoClusters = `{"kubernetes": [
 {"name": "prod", "kubeconfig": "/k/prod.yaml", "role": "prod", "host_exec": {"type": "local"},
  "kube_bench": {"benchmark": "cis-1.9", "tarball": "kube-bench_0.9.0_linux_amd64.tar.gz"}},
 {"name": "lab", "kubeconfig": "/k/lab.yaml", "parts": ["workloads", "policy"]},
 {"name": "down", "kubeconfig": "/k/down.yaml"}]}`

func findingKeys(doc map[string]any) map[string]string {
	out := map[string]string{}
	list, _ := doc["findings"].([]any) // shape checked by the conformance suite
	for _, f := range list {
		m, _ := f.(map[string]any)
		out[fmt.Sprint(m["asset"], " ", m["check"])] = fmt.Sprint(m["severity"])
	}
	return out
}

func TestCollectReadOnlyAndComplete(t *testing.T) {
	t.Parallel()
	r := runCollector(t, newFakeKube(t), twoClusters)
	assertReadOnly(t, r.calls)
	got := findingKeys(r.doc)
	for k, sev := range map[string]string{
		"k8s-workload:prod/data/StatefulSet/db k8s.pod.privileged":                                       "high",
		"k8s-workload:prod/kube-system/DaemonSet/node-agent k8s.pod.hostpid":                             "high",
		"k8s-workload:lab/tools/Deployment/builder k8s.pod.privileged":                                   "medium",
		"k8s-identity:prod/User:alice k8s.rbac.cluster_admin_pods_exec_rbac_write_secrets_read_wildcard": "high",
		"k8s-cluster:prod cis.cis-1.9.1.2.6":                                                             "medium",
		"k8s-cluster:lab k8s.policy.engine_missing":                                                      "low",
		"k8s-identity:prod/operator-kubeconfig k8s.operator_cred_system_masters":                         "high",
	} {
		if got[k] != sev {
			t.Errorf("%s: severity %q, want %q", k, got[k], sev)
		}
	}
	if r.inv["complete"] != false { // the third cluster is down
		t.Errorf("inventory complete = %v", r.inv["complete"])
	}
	assertPrivateWithoutSecrets(t, r.dir)
}

// assertReadOnly: the collector never asks kubectl for anything but a read.
func assertReadOnly(t *testing.T, calls [][]string) {
	t.Helper()
	for _, argv := range calls {
		if argv[0] == "sh" {
			continue
		}
		args := argv[1:]
		if args[0] == "--kubeconfig" {
			args = args[2:]
		}
		if args[0] != "get" && (len(args) < 2 || args[0] != "auth" || args[1] != "whoami") {
			t.Errorf("non-read kubectl call %v", argv)
		}
	}
}

// assertPrivateWithoutSecrets: every output is private to the user and holds no env value or Secret data.
func assertPrivateWithoutSecrets(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if bytes.Contains(b, []byte("k8s-conformance-env-canary")) || bytes.Contains(b, []byte("k8s-conformance-secret-canary")) {
			t.Errorf("%s holds a secret value", p)
		}
		if fi, _ := d.Info(); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 { // no POSIX modes there
			t.Errorf("%s: mode %v, want 0600", p, fi.Mode().Perm())
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPartFailuresAreGapsOfThatPart(t *testing.T) {
	t.Parallel()
	fk := newFakeKube(t)
	res, _ := fk.clusters["prod"]["resources"].(map[string]any) // test data
	res["clusterrolebindings"] = map[string]any{"error": "Error from server (Forbidden): cannot list"}
	res["policyreports.wgpolicyk8s.io"] = map[string]any{"error": "Error from server (Forbidden): cannot list"}
	res["pods"] = map[string]any{"error": "Error from server (Forbidden): cannot list pods"}
	r := runCollector(t, fk, `{"kubernetes": [{"name": "prod", "kubeconfig": "/k/prod.yaml", "role": "prod"}]}`)
	cov := map[string]string{}
	list, _ := r.doc["coverage"].([]any) // shape checked by the conformance suite
	for _, e := range list {
		m, _ := e.(map[string]any)
		cov[fmt.Sprint(m["asset"])] = fmt.Sprint(m["status"], " ", m["checks"])
	}
	want := map[string]string{"k8s-cluster:prod": "ok <nil>", "k8s-identity:prod": "gap <nil>", "k8s-workload:prod": "gap <nil>",
		"k8s-namespace:prod": "gap <nil>", "k8s-cluster:prod/policy": "gap [k8s.policy.*]", "cis:prod": "", "k8s-cluster:prod/secrets": ""}
	for asset, w := range want {
		if cov[asset] != w && w != "" {
			t.Errorf("%s: %q, want %q", asset, cov[asset], w)
		}
	}
	if src, _ := r.inv["sources"].(map[string]any); src["k8s-cluster:prod"] != "failed: RuntimeError" { // test data
		t.Errorf("sources = %v", r.inv["sources"])
	}
	if _, ok := findingKeys(r.doc)["k8s-identity:prod/operator-kubeconfig k8s.operator_cred_system_masters"]; !ok {
		t.Error("the parts after a failed one were not evaluated")
	}
}

func TestKubectlArgvIsReadOnly(t *testing.T) {
	t.Parallel()
	k := &kubectl{kubeconfig: "/k/c.yaml"}
	for _, verb := range []string{"delete", "apply", "create", "patch", "edit", "exec", "auth can-i", "replace", "label", ""} {
		if _, err := k.argv(verb, "pods"); err == nil {
			t.Errorf("verb %q accepted", verb)
		}
	}
	argv, err := k.argv("get", "pods", "-A", "-o", "json")
	if err != nil || strings.Join(argv, " ") != "kubectl --kubeconfig /k/c.yaml get pods -A -o json" {
		t.Errorf("argv = %v, %v", argv, err)
	}
	if _, err := k.argv("get", ""); err == nil {
		t.Error("an empty argument was accepted")
	}
}

func TestOwnerAndSelectors(t *testing.T) {
	t.Parallel()
	owners := []struct {
		refs       []ownerRef
		kind, name string
	}{
		{nil, "Pod", "p"},
		{[]ownerRef{{"ReplicaSet", "web-7d4b9c8f6d"}}, "Deployment", "web"},
		{[]ownerRef{{"ReplicaSet", "web-abc"}}, "Deployment", "web-abc"},
		{[]ownerRef{{"Job", "backup-28123456"}}, "Job", "backup"},
		{[]ownerRef{{"StatefulSet", "db"}}, "StatefulSet", "db"},
	}
	for _, tc := range owners {
		p := &pod{Metadata: objectMeta{Name: "p", OwnerReferences: tc.refs}}
		if k, n := owner(p); k != tc.kind || n != tc.name {
			t.Errorf("owner(%v) = %s/%s", tc.refs, k, n)
		}
	}
	labels := map[string]string{"app": "web", "tier": "front"}
	sels := []struct {
		sel  *labelSelector
		want bool
	}{
		{nil, true}, {&labelSelector{}, true},
		{&labelSelector{MatchLabels: map[string]string{"app": "web"}}, true},
		{&labelSelector{MatchLabels: map[string]string{"app": "db"}}, false},
		{&labelSelector{MatchExpressions: []labelExpr{{"tier", "In", []string{"front", "x"}}}}, true},
		{&labelSelector{MatchExpressions: []labelExpr{{"tier", "NotIn", []string{"front"}}}}, false},
		{&labelSelector{MatchExpressions: []labelExpr{{"zone", "Exists", nil}}}, false},
		{&labelSelector{MatchExpressions: []labelExpr{{"zone", "DoesNotExist", nil}}}, true},
		{&labelSelector{MatchExpressions: []labelExpr{{"zone", "Gt", nil}}}, true},
	}
	for _, tc := range sels {
		np := &networkPolicy{}
		np.Spec.PodSelector = tc.sel
		if got := npSelects(np, labels); got != tc.want {
			t.Errorf("npSelects(%+v) = %v", tc.sel, got)
		}
	}
	if selects(nil, labels) || !selects(map[string]string{"app": "web"}, labels) {
		t.Error("selects")
	}
}

func TestShellQuoteIsShlexQuote(t *testing.T) {
	t.Parallel()
	// shlex.quote in CPython 3.12
	for in, want := range map[string]string{"": "''", "abc-1.2/x:y@z%+=,": "abc-1.2/x:y@z%+=,", "a b": "'a b'",
		"it's": `'it'"'"'s'`, "$D": "'$D'", "é": "'é'"} {
		if got := pytext.ShellQuote(in); got != want {
			t.Errorf("shellQuote(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExecutorConfig(t *testing.T) {
	t.Parallel()
	var got []string
	fake := func(_ context.Context, c *rundoc.Cmd) rundoc.Result { got = c.Argv; return rundoc.Result{} }
	tests := []struct {
		cfg  string
		want string
		err  string
	}{
		{`{"type": "ssh", "host": "node1", "options": ["-p", "2222"]}`, "ssh -o BatchMode=yes -o ConnectTimeout=10 " +
			"-o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o StrictHostKeyChecking=yes -p 2222 node1 sh -c 'a b'", ""},
		{`{}`, "sh -c a b", ""},
		{`{"type": "ssh", "host": "-oProxyCommand=x"}`, "", "KeyError"},
		{`{"type": "ssm"}`, "", "NotImplementedError: exec adapter 'ssm' is a documented future adapter"},
	}
	for _, tc := range tests {
		m := mapOf(t, tc.cfg)
		e, err := newExecutor(m, nil, fake)
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: err %v, want %s", tc.cfg, err, tc.err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err := e.Run(context.Background(), []string{"sh", "-c", "a b"}, "", time.Second, false); err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, " ") != tc.want {
			t.Errorf("%s: argv %q", tc.cfg, strings.Join(got, " "))
		}
	}
}

func TestVersionMatchesComponent(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "collectors", "k8s", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(b)) != Version {
		t.Errorf("Version %s, collectors/k8s/VERSION %s", Version, b)
	}
}

func mapOf(t *testing.T, s string) *pyvalue.Map {
	t.Helper()
	v, err := pyvalue.DecodeJSON([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	m, ok := v.(*pyvalue.Map)
	if !ok {
		t.Fatalf("%s is not an object", s)
	}
	return m
}
