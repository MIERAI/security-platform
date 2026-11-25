package detection

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/execad"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const kubectlTimeout = 60 * time.Second

// kubectlFunc runs `kubectl [--kubeconfig=K] ARGS` (read-only `get` only) and returns its result.
type kubectlFunc func(ctx context.Context, kubeconfig string, args []string) execad.Result

var errKubeconfig = errors.New("kubeconfig is not a path")

// KubectlArgv is the argument vector: never through a shell; the kubeconfig is one `--kubeconfig=<path>` argument
// and a value that could be read as an option is refused.
func KubectlArgv(kubeconfig string, args []string) ([]string, error) {
	argv := []string{"kubectl"}
	if kubeconfig != "" && kubeconfig != "in-cluster" {
		if strings.HasPrefix(kubeconfig, "-") || strings.ContainsAny(kubeconfig, "\x00\n") {
			return nil, errKubeconfig
		}
		argv = append(argv, "--kubeconfig="+kubeconfig)
	}
	return append(argv, args...), nil
}

func runKubectl(ctx context.Context, kubeconfig string, args []string) execad.Result {
	argv, err := KubectlArgv(kubeconfig, args)
	if err != nil {
		return execad.Result{RC: 1, Err: err.Error()}
	}
	ex, err := execad.FromConfig(nil)
	if err != nil {
		return execad.Result{RC: 1, Err: err.Error()}
	}
	res := ex.Run(ctx, argv, nil, kubectlTimeout, false)
	if res.RC == execad.RCNotFound && res.Out == "" && strings.Contains(res.Err, "executable file not found") {
		res = execad.Result{RC: 1, Err: "[Errno 2] No such file or directory: 'kubectl'"} // as subprocess reports it
	}
	return res
}

func (c *collector) kubeconfig(cl any) string {
	k, _ := rundoc.Get(cl, "kubeconfig").(string) // absent or not text: the in-cluster / default config
	if k == "" || k == "in-cluster" {
		return k
	}
	return rundoc.ExpandUser(k, c.home)
}

// items lists the `items` of a kubectl list answer.
func items(out string) ([]any, error) {
	v, err := pyvalue.DecodeJSON([]byte(out))
	if err != nil {
		return nil, fmt.Errorf("output is not JSON: %w", err)
	}
	m, ok := v.(*pyvalue.Map)
	if !ok {
		return nil, errors.New("output is not a JSON object")
	}
	return rundoc.List(m.Value("items")), nil
}

func itemName(i any) string {
	return pyvalue.Str(rundoc.Get(rundoc.Get(i, "metadata"), "name"))
}

// sensors: the runtime sensor and the node log shipper run, ready, on every node of every configured cluster.
func (c *collector) sensors(ctx context.Context) error {
	for _, cl := range rundoc.List(c.d.Value("clusters")) {
		name := pyvalue.Str(rundoc.Get(cl, "name"))
		asset := "k8s-cluster:" + name
		res := c.kube(ctx, c.kubeconfig(cl), []string{"get", "daemonsets", "-A", "-o", "json"})
		if res.RC != 0 {
			c.doc.Gap(asset, "cannot list DaemonSets: "+rundoc.Cut(strings.TrimSpace(res.Err), maxStderrText), nil)
			continue
		}
		list, err := items(res.Out)
		if err != nil {
			c.doc.Gap(asset, "cannot list DaemonSets: "+err.Error(), nil)
			continue
		}
		c.doc.OK(asset, "")
		byName := map[string]any{}
		for _, i := range list {
			byName[itemName(i)] = i
		}
		if err := c.clusterSensors(cl, name, byName); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) clusterSensors(cl any, name string, byName map[string]any) error {
	kinds := rundoc.List(rundoc.Get(cl, "sensors"))
	if len(kinds) == 0 {
		kinds = []any{"falco", "node-logs"}
	}
	for _, k := range kinds {
		s := pyvalue.Str(k)
		ds, present := byName[s]
		present = present && pyvalue.Truthy(ds)
		st := rundoc.MapOr(rundoc.Get(ds, "status"))
		want, ready := st.GetOr("desiredNumberScheduled", int64(0)), st.GetOr("numberReady", int64(0))
		w, _ := pyvalue.ToFloat64(want)
		r, _ := pyvalue.ToFloat64(ready)
		ratio := 0.0
		if w != 0 {
			ratio = r / w
		}
		c.metric("security_detection_sensor_ready_ratio", ratio, "Nodes where the detection sensor is ready / nodes it should run on",
			label("cluster", name), label("kind", s))
		if present && w != 0 && r >= w {
			continue
		}
		err := c.finding(&rundoc.Finding{Asset: "k8s-cluster:" + name + "/" + s, Check: "detection.sensor_missing",
			Title: fmt.Sprintf("detection sensor %s is not ready on every node of cluster %s (%s/%s)", s, name,
				pyvalue.Str(ready), pyvalue.Str(want)),
			Severity: "high", Remediation: "deploy / repair the sensor through GitOps (docs/detection.md#deploying-an-instance)"},
			"sensors-"+name+".json", map[string]any{s: map[string]any{"desired": rundoc.Loose(want),
				"ready": rundoc.Loose(ready), "present": present}})
		if err != nil {
			return err
		}
	}
	return nil
}

// backstop: each cluster has the in-cluster detection rules (PrometheusRule security-detection) that keep runtime
// detection alive during a log store outage.
func (c *collector) backstop(ctx context.Context) error {
	for _, cl := range rundoc.List(c.d.Value("clusters")) {
		res := c.kube(ctx, c.kubeconfig(cl), []string{"get", "prometheusrules", "-A", "-o", "json"})
		if res.RC != 0 {
			continue // the sensors check already recorded the cluster as a gap
		}
		list, err := items(res.Out)
		if err != nil {
			continue // likewise
		}
		name := pyvalue.Str(rundoc.Get(cl, "name"))
		n := BackstopRules(list)
		c.metric("security_detection_backstop_rules", float64(n), "In-cluster detection rules (independent of the log store)",
			label("cluster", name))
		if n > 0 {
			continue
		}
		err = c.finding(&rundoc.Finding{Asset: "k8s-cluster:" + name + "/backstop", Check: "detection.backstop_missing",
			Title:    "cluster " + name + " has no in-cluster detection rules: a log store outage blinds runtime detection",
			Severity: "medium", Remediation: "deploy detections/falco (PrometheusRule security-detection) to the cluster"},
			"backstop-"+name+".json", map[string]any{"rules": 0})
		if err != nil {
			return err
		}
	}
	return nil
}

// BackstopRules counts the rules of the PrometheusRule objects named security-detection.
func BackstopRules(list []any) int {
	n := 0
	for _, i := range list {
		if itemName(i) != "security-detection" {
			continue
		}
		for _, g := range rundoc.List(rundoc.Get(rundoc.Get(i, "spec"), "groups")) {
			n += len(rundoc.List(rundoc.Get(g, "rules")))
		}
	}
	return n
}
