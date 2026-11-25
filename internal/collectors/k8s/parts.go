package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// secretColumns lists Secrets without their data: custom columns never fetch .data.
const secretColumns = "custom-columns=NS:.metadata.namespace,NAME:.metadata.name,TYPE:.type,CREATED:.metadata.creationTimestamp"

// secrets: Secret metadata only (names, types, ages), never values.
func (cr *clusterRun) secrets(ctx context.Context) error {
	out, err := cr.kube.call(ctx, 60*time.Second, "get", "secrets", "-A", "--no-headers", "-o", secretColumns)
	if err != nil {
		return err // K8S-D1: an unreadable listing is a gap, never "zero Secrets"
	}
	now := cr.env.Clock()()
	var list []pyjson.Value
	total, old := 0, 0
	for _, line := range strings.Split(out, "\n") {
		o, created, err := secretRow(line)
		if err != nil {
			return err
		}
		if o == nil {
			continue
		}
		list = append(list, o)
		total++
		if now.Sub(created) > 90*24*time.Hour {
			old++
		}
	}
	if list == nil {
		list = []pyjson.Value{}
	}
	if _, err := cr.raw("secrets-metadata.json", list); err != nil {
		return err
	}
	store := map[string]string{"store": "k8s:" + cr.cfg.name}
	cr.run.Doc.Metric("security_secrets_total", float64(total), "Secrets (metadata only)", store)
	cr.run.Doc.Metric("security_secrets_older_than_90d", float64(old), "Secrets older than 90 days", store)
	return nil
}

// secretRow parses one listing row (nil: an empty row or a Secret type that is not a credential of ours).
func secretRow(line string) (*pyjson.Object, time.Time, error) {
	f := strings.Fields(line)
	if len(f) == 0 || (len(f) >= 3 && (f[2] == "helm.sh/release.v1" || f[2] == "kubernetes.io/service-account-token")) {
		return nil, time.Time{}, nil
	}
	if len(f) < 4 {
		return nil, time.Time{}, &kubeError{"KeyError", "a Secret listing row without namespace, name, type and creation time"}
	}
	created, err := time.Parse("2006-01-02T15:04:05Z", f[3])
	if err != nil {
		return nil, time.Time{}, &kubeError{"ValueError", fmt.Sprintf("time data %q does not match format '%%Y-%%m-%%dT%%H:%%M:%%SZ'", f[3])}
	}
	o := pyjson.NewObject()
	for i, k := range []string{"ns", "name", "type", "created"} {
		o.Set(k, f[i])
	}
	return o, created, nil
}

// policy summarises the PolicyReports (wgpolicyk8s.io) of a policy engine (Kyverno, ...). A missing resource type
// means no engine; any other error is a narrow gap of the policy checks (K8S-D2).
func (cr *clusterRun) policy(ctx context.Context) error {
	reps, err := get[policyReport](ctx, cr.kube, "policyreports.wgpolicyk8s.io", true)
	if err == nil {
		var cluster []policyReport
		cluster, err = get[policyReport](ctx, cr.kube, "clusterpolicyreports.wgpolicyk8s.io", false)
		reps = append(reps, cluster...)
	}
	var ke *kubeError
	if errors.As(err, &ke) && ke.notFound() {
		return cr.noPolicyEngine()
	}
	if err != nil {
		return err
	}
	return cr.policyFindings(reps)
}

func (cr *clusterRun) noPolicyEngine() error {
	cr.run.Doc.Metric("security_k8s_policy_engine_present", 0, "PolicyReport CRDs present", map[string]string{"cluster": cr.cfg.name})
	ev := pyjson.NewObject()
	ev.Set("present", false)
	evPtr, err := cr.raw("policyreports.json", ev)
	if err != nil {
		return err
	}
	sev := "low"
	if cr.cfg.prod {
		sev = "medium"
	}
	cr.run.Doc.AddFinding(&rundoc.Finding{Layer: "workload", Asset: cr.asset, Check: "k8s.policy.engine_missing",
		Title: "no admission policy engine reports (no PolicyReports)", Severity: sev, Evidence: evPtr,
		Remediation: "install a policy engine (e.g. Kyverno) in audit mode"})
	return nil
}

// failingPolicies: the policies with fail/error results (in the order met) and the namespaces they fail in.
func failingPolicies(reps []policyReport) (policies []string, failing map[string]map[string]bool) {
	failing = map[string]map[string]bool{}
	for i := range reps {
		ns := reps[i].Metadata.Namespace
		if ns == "" {
			ns = "-"
		}
		for _, res := range reps[i].Results {
			if res.Result != "fail" && res.Result != "error" {
				continue
			}
			pol := "?"
			if res.Policy != nil {
				pol = *res.Policy
			}
			if failing[pol] == nil {
				failing[pol] = map[string]bool{}
				policies = append(policies, pol)
			}
			failing[pol][ns] = true
		}
	}
	return policies, failing
}

func (cr *clusterRun) policyFindings(reps []policyReport) error {
	policies, failing := failingPolicies(reps)
	var summ orderedCounts
	for i := range reps {
		for _, c := range reps[i].Summary {
			summ = summ.add(c)
		}
	}
	evPtr, err := cr.raw("policyreports.json", policyEvidence(summ, failing))
	if err != nil {
		return err
	}
	for _, pol := range policies {
		cr.run.Doc.AddFinding(&rundoc.Finding{Layer: "workload", Asset: cr.asset, Check: "k8s.policy.fail." + pol,
			Title:    "admission/background policy '" + pol + "' failing in " + itoa(len(failing[pol])) + " namespace(s)",
			Severity: "low", Evidence: evPtr, Remediation: "fix the resources or the policy"})
	}
	for _, c := range summ {
		cr.run.Doc.Metric("security_k8s_policyreport_results", c.value, "PolicyReport results",
			map[string]string{"cluster": cr.cfg.name, "result": c.key})
	}
	return nil
}

// add sums c into the counts (a new key goes last).
func (o orderedCounts) add(c count) orderedCounts {
	for i := range o {
		if o[i].key == c.key {
			o[i].value += c.value
			o[i].isInt = o[i].isInt && c.isInt
			return o
		}
	}
	return append(o, c)
}

func policyEvidence(summ orderedCounts, failing map[string]map[string]bool) *pyjson.Object {
	s := pyjson.NewObject()
	for _, c := range summ {
		if c.isInt {
			s.Set(c.key, int64(c.value))
		} else {
			s.Set(c.key, c.value)
		}
	}
	f := pyjson.NewObject()
	for pol, nss := range failing {
		f.Set(pol, sortedValues(nss))
	}
	ev := pyjson.NewObject()
	ev.Set("summary", s)
	ev.Set("failing", f)
	return ev
}

// operator checks the caller's own credential (`kubectl auth whoami`): a system:masters client certificate bypasses
// RBAC and cannot be revoked before it expires.
func (cr *clusterRun) operator(ctx context.Context) error {
	out, err := cr.kube.call(ctx, 30*time.Second, "auth whoami", "-o", "json")
	if err != nil {
		return err
	}
	var review struct {
		Status struct {
			UserInfo struct {
				Username *string   `json:"username"`
				Groups   *[]string `json:"groups"`
			} `json:"userInfo"`
		} `json:"status"`
	}
	if jerr := json.Unmarshal([]byte(out), &review); jerr != nil {
		return &kubeError{"JSONDecodeError", jerr.Error()}
	}
	who := review.Status.UserInfo
	if who.Groups == nil || !contains(*who.Groups, "system:masters") {
		return nil
	}
	ev := pyjson.NewObject()
	groups := make([]pyjson.Value, len(*who.Groups))
	for i, g := range *who.Groups {
		groups[i] = g
	}
	ev.Set("groups", groups)
	if who.Username != nil {
		ev.Set("username", *who.Username)
	} else {
		ev.Set("username", nil)
	}
	evPtr, err := cr.raw("whoami.json", ev)
	if err != nil {
		return err
	}
	sev := "medium"
	if cr.cfg.prod {
		sev = "high"
	}
	cr.run.Doc.AddFinding(&rundoc.Finding{Layer: "identity", Asset: "k8s-identity:" + cr.cfg.name + "/operator-kubeconfig",
		Check: "k8s.operator_cred_system_masters", Severity: sev, Evidence: evPtr,
		Title:       "the operator's kubeconfig is a system:masters client certificate (bypasses RBAC, cannot be revoked before expiry)",
		Remediation: "use a per-person RBAC identity (OIDC or a cert bound to a ClusterRole), keep the admin cert offline"})
	return nil
}
