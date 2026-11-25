package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

const (
	maxTarball       = 256 << 20 // the kube-bench release tarball streamed to the node
	maxBenchOutput   = 64 << 20
	kubeBenchTimeout = 600 * time.Second
)

// benchmarkName is what a kube-bench benchmark id looks like (cis-1.9, eks-1.5.0, ...): it is part of the script
// run on the node, so nothing else is accepted.
var benchmarkName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// cisGap: kube-bench could not run. The gap on cis:<c> is what the reference records; the narrow gap on
// k8s-cluster:<c>/cis keeps the CIS findings, which live on the cluster, unknown instead of fixed (K8S-D3).
func (cr *clusterRun) cisGap(reason string) {
	cr.run.Doc.Gap("cis:"+cr.cfg.name, reason, nil)
	cr.run.Doc.Gap(cr.asset+"/cis", reason, []string{"cis.*"})
}

// cis runs kube-bench on a node through host_exec (it only reads config files and process arguments): the release
// tarball is streamed over stdin, extracted into a temporary directory on the node and removed afterwards.
func (cr *clusterRun) cis(ctx context.Context) error {
	kb := cr.cfg.kubeBench
	if kb == nil || kb.Len() == 0 {
		return nil
	}
	if cr.cfg.hostExec == nil || cr.cfg.hostExec.Len() == 0 {
		cr.cisGap("kube-bench needs host_exec")
		return nil
	}
	bench, tarball := rundoc.Str(kb.Value("benchmark")), rundoc.Str(kb.Value("tarball"))
	if !benchmarkName.MatchString(bench) {
		cr.cisGap(fmt.Sprintf("kube-bench: invalid benchmark name %q", rundoc.Cut(bench, 40)))
		return nil
	}
	_, ver, ok := strings.Cut(filepath.Base(tarball), "_")
	if !ok {
		return &kubeError{"IndexError", "list index out of range"}
	}
	ver, _, _ = strings.Cut(ver, "_")
	data := cr.run.Data
	if data == "" {
		data = "."
	}
	tar, err := rundoc.ReadLimited(filepath.Join(data, tarball), maxTarball)
	if err != nil {
		return &kubeError{"FileNotFoundError", err.Error()}
	}
	ex, err := newExecutor(cr.cfg.hostExec, cr.env.Environ, cr.exec)
	if err != nil {
		return err
	}
	res := ex.run(ctx, kubeBenchArgv(bench), base64.StdEncoding.EncodeToString(tar), kubeBenchTimeout)
	if res.RC != 0 || strings.TrimSpace(res.Stdout) == "" {
		cr.cisGap(fmt.Sprintf("kube-bench failed rc=%d: %s", res.RC, lastChars(strings.TrimSpace(res.Stderr), 160)))
		return nil
	}
	cr.run.Doc.Tools.Set("kube-bench", ver)
	return cr.kubeBenchResults(bench, res.Stdout)
}

// kubeBenchArgv is the script the reference runs on the node (bench is validated above).
func kubeBenchArgv(bench string) []string {
	script := `set -e; D=$(mktemp -d /tmp/sp-kube-bench.XXXXXX); trap "rm -rf $D" EXIT; base64 -d | tar xzf - -C $D; cd $D; ` +
		`sudo -n ./kube-bench --config-dir cfg --benchmark ` + bench + ` --json 2>/dev/null`
	return []string{"sh", "-c", script}
}

type benchResult struct {
	TestNumber  string `json:"test_number"`
	TestDesc    string `json:"test_desc"`
	Status      string `json:"status"`
	Scored      *bool  `json:"scored"`
	Remediation string `json:"remediation"`
}

type benchReport struct {
	Controls []struct {
		Tests []struct {
			Results []benchResult `json:"results"`
		} `json:"tests"`
	} `json:"Controls"`
}

func (cr *clusterRun) kubeBenchResults(bench, out string) error {
	var rep benchReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		return &kubeError{"JSONDecodeError", err.Error()}
	}
	totals := orderedCounts{{key: "pass", isInt: true}, {key: "fail", isInt: true}, {key: "warn", isInt: true}, {key: "info", isInt: true}}
	var fails []benchResult
	for _, c := range rep.Controls {
		for _, t := range c.Tests {
			for _, r := range t.Results {
				totals = totals.add(count{key: strings.ToLower(r.Status), value: 1, isInt: true})
				if strings.EqualFold(r.Status, "fail") {
					r.Remediation = rundoc.Cut(r.Remediation, 300)
					fails = append(fails, r)
				}
			}
		}
	}
	evPtr, err := cr.raw("kube-bench.json", benchEvidence(bench, totals, fails))
	if err != nil {
		return err
	}
	cr.run.Doc.OK("cis:"+cr.cfg.name, "")
	for _, f := range fails {
		cr.benchFinding(bench, &f, evPtr)
	}
	for _, t := range totals {
		cr.run.Doc.Metric("security_cis_results", t.value, "kube-bench results", map[string]string{"cluster": cr.cfg.name, "result": t.key})
	}
	return nil
}

func (cr *clusterRun) benchFinding(bench string, f *benchResult, evPtr string) {
	sev := "low"
	if f.Scored != nil && *f.Scored {
		sev = "medium"
	}
	rem, _, _ := strings.Cut(f.Remediation, "\n")
	if rem == "" {
		rem = "see benchmark"
	}
	cr.run.Doc.AddFinding(&rundoc.Finding{Layer: "workload", Asset: cr.asset, Check: "cis." + bench + "." + f.TestNumber,
		Title: "CIS " + f.TestNumber + " FAIL: " + f.TestDesc, Severity: sev, Evidence: evPtr, Remediation: rem,
		Refs: []pyjson.Value{"cis:" + bench + ":" + f.TestNumber}})
}

func benchEvidence(bench string, totals orderedCounts, fails []benchResult) *pyjson.Object {
	t := pyjson.NewObject()
	for _, c := range totals {
		t.Set(c.key, int64(c.value))
	}
	list := make([]pyjson.Value, len(fails))
	for i, f := range fails {
		o := pyjson.NewObject()
		o.Set("id", f.TestNumber)
		o.Set("desc", f.TestDesc)
		if f.Scored != nil {
			o.Set("scored", *f.Scored)
		} else {
			o.Set("scored", nil)
		}
		o.Set("remediation", f.Remediation)
		list[i] = o
	}
	ev := pyjson.NewObject()
	ev.Set("benchmark", bench)
	ev.Set("totals", t)
	ev.Set("fails", list)
	return ev
}
