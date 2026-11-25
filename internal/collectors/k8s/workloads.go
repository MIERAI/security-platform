package k8s

import (
	"context"
	"regexp"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

var (
	replicaSetSuffix = regexp.MustCompile(`-[a-z0-9]{6,10}$`)
	jobSuffix        = regexp.MustCompile(`-\d{6,}$`)
)

// owner is the workload a pod belongs to: (kind, name), a ReplicaSet as its Deployment, a CronJob's Job by its
// stable prefix, a bare pod as itself.
func owner(p *pod) (kind, name string) {
	if len(p.Metadata.OwnerReferences) == 0 {
		return "Pod", p.Metadata.Name
	}
	ref := p.Metadata.OwnerReferences[0]
	switch ref.Kind {
	case "ReplicaSet":
		return "Deployment", replicaSetSuffix.ReplaceAllString(ref.Name, "")
	case "Job":
		return "Job", jobSuffix.ReplaceAllString(ref.Name, "")
	default:
		return ref.Kind, ref.Name
	}
}

// selects: a Service selector (non-empty) matches the labels.
func selects(sel, labels map[string]string) bool {
	if len(sel) == 0 {
		return false
	}
	for k, v := range sel {
		if lv, ok := labels[k]; !ok || lv != v {
			return false
		}
	}
	return true
}

// npSelects: a NetworkPolicy's podSelector matches the labels (an empty selector selects every pod).
func npSelects(np *networkPolicy, labels map[string]string) bool {
	ps := np.Spec.PodSelector
	if ps == nil || (len(ps.MatchLabels) == 0 && len(ps.MatchExpressions) == 0) {
		return true
	}
	for k, v := range ps.MatchLabels {
		if lv, ok := labels[k]; !ok || lv != v {
			return false
		}
	}
	for _, e := range ps.MatchExpressions {
		if !exprMatches(&e, labels) {
			return false
		}
	}
	return true
}

func exprMatches(e *labelExpr, labels map[string]string) bool {
	v, has := labels[e.Key]
	in := has && contains(e.Values, v)
	switch e.Operator {
	case "In":
		return in
	case "NotIn":
		return !in
	case "Exists":
		return has
	case "DoesNotExist":
		return !has
	default:
		return true // an unknown operator does not exclude (as the reference)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// workloadState collects one cluster's pod findings while the pods are read.
type workloadState struct {
	keys     []string                   // workload keys in the order first met
	issues   map[string]map[string]bool // workload key -> issues
	ns       map[string]string          // workload key -> namespace
	rootLike int
	noNP     map[string]int // namespace -> pods no NetworkPolicy selects
	images   []*imageEntry
	byImage  map[string]*imageEntry
}

type imageEntry struct {
	image, imageID        string
	namespaces, workloads map[string]bool
	exposed               bool
}

func (cr *clusterRun) workloads(ctx context.Context) error {
	all, err := get[pod](ctx, cr.kube, "pods", true)
	if err != nil {
		return err
	}
	svcs, err := get[service](ctx, cr.kube, "services", true)
	if err != nil {
		return err
	}
	nps, err := get[networkPolicy](ctx, cr.kube, "networkpolicies", true)
	if err != nil {
		return err
	}
	var pods []*pod
	for i := range all {
		if all[i].Status.Phase == "Running" || all[i].Status.Phase == "Pending" {
			pods = append(pods, &all[i])
		}
	}
	st := &workloadState{issues: map[string]map[string]bool{}, ns: map[string]string{}, noNP: map[string]int{},
		byImage: map[string]*imageEntry{}}
	exposed := exposedPods(pods, svcs)
	for _, p := range pods {
		cr.pod(st, p, exposed[p.Metadata.UID], nps)
	}
	return cr.reportWorkloads(st, len(nps))
}

// exposedPods: pods behind a NodePort/LoadBalancer Service of their namespace, and host-network pods.
func exposedPods(pods []*pod, svcs []service) map[string]bool {
	out := map[string]bool{}
	for i := range svcs {
		s := &svcs[i]
		if s.Spec.Type != "NodePort" && s.Spec.Type != "LoadBalancer" {
			continue
		}
		for _, p := range pods {
			if p.Metadata.Namespace == s.Metadata.Namespace && selects(s.Spec.Selector, p.Metadata.Labels) {
				out[p.Metadata.UID] = true
			}
		}
	}
	for _, p := range pods {
		if p.Spec.HostNetwork {
			out[p.Metadata.UID] = true
		}
	}
	return out
}

func (cr *clusterRun) pod(st *workloadState, p *pod, exposed bool, nps []networkPolicy) {
	ns := p.Metadata.Namespace
	kind, name := owner(p)
	key := "k8s-workload:" + cr.cfg.name + "/" + ns + "/" + kind + "/" + name
	if st.issues[key] == nil {
		st.keys = append(st.keys, key)
		st.issues[key], st.ns[key] = map[string]bool{}, ns
	}
	podIssues(st.issues[key], &p.Spec)
	statuses := map[string]string{}
	for _, s := range append(append([]containerStatus(nil), p.Status.ContainerStatuses...), p.Status.InitContainerStatuses...) {
		statuses[s.Name] = s.ImageID
	}
	var psc securityContext
	if p.Spec.SecurityContext != nil {
		psc = *p.Spec.SecurityContext
	}
	for _, ct := range append(append([]container(nil), p.Spec.Containers...), p.Spec.InitContainers...) {
		if containerIssues(st.issues[key], &ct, &psc) {
			st.rootLike++
		}
		st.image(ct.Image, statuses[ct.Name], ns, key, exposed)
	}
	for i := range nps {
		if nps[i].Metadata.Namespace == ns && npSelects(&nps[i], p.Metadata.Labels) {
			return
		}
	}
	st.noNP[ns]++
}

func podIssues(issues map[string]bool, spec *podSpec) {
	for flag, on := range map[string]bool{"hostNetwork": spec.HostNetwork, "hostPID": spec.HostPID, "hostIPC": spec.HostIPC} {
		if on {
			issues[flag] = true
		}
	}
	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			issues["hostPath:"+v.HostPath.Path] = true
		}
	}
}

// containerIssues adds a container's issues and reports whether it may run as root (neither runAsNonRoot nor a
// non-zero runAsUser, from the container or else the pod).
func containerIssues(issues map[string]bool, ct *container, psc *securityContext) bool {
	var sc securityContext
	if ct.SecurityContext != nil {
		sc = *ct.SecurityContext
	}
	if sc.Privileged != nil && *sc.Privileged {
		issues["privileged"] = true
	}
	if sc.Capabilities != nil {
		for _, c := range sc.Capabilities.Add {
			if contains([]string{"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL", "SYS_MODULE"}, c) {
				issues["cap:"+c] = true
			}
		}
	}
	nonRoot, uid := sc.RunAsNonRoot, sc.RunAsUser
	if nonRoot == nil {
		nonRoot = psc.RunAsNonRoot
	}
	if uid == nil {
		uid = psc.RunAsUser
	}
	return (nonRoot == nil || !*nonRoot) && (uid == nil || *uid == 0)
}

func (st *workloadState) image(img, imageID, ns, key string, exposed bool) {
	e := st.byImage[img]
	if e == nil {
		e = &imageEntry{image: img, imageID: imageID, namespaces: map[string]bool{}, workloads: map[string]bool{}}
		st.byImage[img] = e
		st.images = append(st.images, e)
	}
	e.namespaces[ns], e.workloads[key] = true, true
	e.exposed = e.exposed || exposed
}

// reportWorkloads writes the evidence, findings, metrics and inventory items of the workloads part.
func (cr *clusterRun) reportWorkloads(st *workloadState, policies int) error {
	ev := pyjson.NewObject()
	for _, k := range st.keys {
		o := pyjson.NewObject()
		o.Set("ns", st.ns[k])
		o.Set("issues", sortedValues(st.issues[k]))
		ev.Set(k, o)
	}
	evPtr, err := cr.raw("workloads.json", ev)
	if err != nil {
		return err
	}
	for _, k := range st.keys {
		cr.workloadFindings(k, st.issues[k], evPtr)
	}
	labels := map[string]string{"cluster": cr.cfg.name}
	cr.run.Doc.Metric("security_k8s_pods_root_capable_containers", float64(st.rootLike),
		"Containers without runAsNonRoot/runAsUser", labels)
	if err := cr.netpolFindings(st.noNP, policies); err != nil {
		return err
	}
	for _, e := range st.images {
		cr.inventory = append(cr.inventory, cr.inventoryItem(e))
	}
	cr.sources.Set(cr.asset, "complete") // every running pod of the cluster was listed
	return nil
}

func (cr *clusterRun) workloadFindings(key string, issues map[string]bool, evPtr string) {
	sevmap := map[string]string{"privileged": "high", "hostPID": "high", "hostNetwork": "medium", "hostIPC": "medium"}
	for _, issue := range sortedStrings(issues) {
		base, rest, hasRest := strings.Cut(issue, ":")
		sev, ok := sevmap[base]
		if !ok {
			sev = "medium"
		}
		if !cr.cfg.prod && sev == "high" {
			sev = "medium"
		}
		check := "k8s.pod." + strings.ToLower(base)
		if base == "cap" && hasRest {
			check += "." + strings.ToLower(rest)
		}
		_, short, _ := strings.Cut(key, ":")
		cr.run.Doc.AddFinding(&rundoc.Finding{Layer: "workload", Asset: key, Check: check, Title: short + ": " + issue,
			Severity: sev, Evidence: evPtr, Remediation: "drop the privilege or record an exception (system components) with expiry"})
	}
}

func (cr *clusterRun) netpolFindings(noNP map[string]int, policies int) error {
	without := pyjson.NewObject()
	total := 0
	for _, ns := range sortedKeys(noNP) {
		without.Set(ns, int64(noNP[ns]))
		total += noNP[ns]
	}
	ev := pyjson.NewObject()
	ev.Set("namespaces_without_policy", without)
	ev.Set("policies", int64(policies))
	evPtr, err := cr.raw("netpol.json", ev)
	if err != nil {
		return err
	}
	sev := "low"
	if cr.cfg.prod {
		sev = "medium"
	}
	for _, ns := range sortedKeys(noNP) {
		cr.run.Doc.AddFinding(&rundoc.Finding{Layer: "workload", Asset: "k8s-namespace:" + cr.cfg.name + "/" + ns,
			Check: "k8s.netpol.missing", Severity: sev, Evidence: evPtr, Remediation: "default-deny NetworkPolicy + explicit allows",
			Title: itoa(noNP[ns]) + " pod(s) in " + cr.cfg.name + "/" + ns + " not selected by any NetworkPolicy (flat network)"})
	}
	cr.run.Doc.Metric("security_k8s_pods_without_netpol", float64(total), "Pods not selected by any NetworkPolicy",
		map[string]string{"cluster": cr.cfg.name})
	return nil
}

func (cr *clusterRun) inventoryItem(e *imageEntry) *pyjson.Object {
	o := pyjson.NewObject()
	o.Set("cluster", cr.cfg.name)
	o.Set("image", e.image)
	o.Set("image_id", e.imageID)
	o.Set("namespaces", sortedValues(e.namespaces))
	o.Set("workloads", sortedValues(e.workloads))
	o.Set("exposed", e.exposed)
	o.Set("prod", cr.cfg.prod)
	return o
}

func sortedStrings(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedValues(set map[string]bool) []pyjson.Value {
	keys := sortedStrings(set)
	out := make([]pyjson.Value, len(keys))
	for i, k := range keys {
		out[i] = k
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
