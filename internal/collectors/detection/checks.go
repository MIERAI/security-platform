package detection

import (
	"context"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// source is an expected log source and the stream label that names its senders (docs/detection.md, log contract).
type source struct{ name, label, window string }

// sourceTable lists the sources in the reference's order with their default windows (shippers send heartbeats,
// so a quiet sender still delivers lines).
func sourceTable() []source {
	return []source{{"k8s-audit", "cluster", "30m"}, {"auth", "host", "1d"}, {"codehost", "host", "2d"},
		{"overlay-network", "host", "2d"}}
}

// scope: every cluster the instance knows must be under detection (a runtime sensor and an audit-log source).
func (c *collector) scope(context.Context) error {
	var known []string
	for _, k := range rundoc.List(c.inst.Value("kubernetes")) {
		if n := rundoc.Get(k, "name"); pyvalue.Truthy(n) {
			known = append(known, pyvalue.Str(n))
		}
	}
	sensed := map[string]bool{}
	for _, cl := range rundoc.List(c.d.Value("clusters")) {
		sensed[pyvalue.Str(rundoc.Get(cl, "name"))] = true
	}
	audited := map[string]bool{}
	for _, a := range rundoc.List(rundoc.Get(c.d.Value("expected"), "k8s-audit")) {
		audited[pyvalue.Str(a)] = true
	}
	covered := 0
	for _, name := range known {
		parts := missingParts(sensed[name], audited[name])
		if len(parts) == 0 {
			covered++
			continue
		}
		c.doc.OK("k8s-cluster:" + name)
		missing := make([]any, len(parts))
		for i, m := range parts {
			missing[i] = m
		}
		err := c.finding(&rundoc.Finding{Asset: "k8s-cluster:" + name, Check: "detection.cluster_not_covered",
			Title:    fmt.Sprintf("cluster %s is not under detection (%s missing)", name, strings.Join(parts, ", ")),
			Severity: "high", Remediation: "add the cluster to detection.clusters / detection.expected.k8s-audit after deploying the sensors"},
			"scope-"+name+".json", map[string]any{"missing": missing})
		if err != nil {
			return err
		}
	}
	c.metric("security_detection_clusters_known", float64(len(known)), "Clusters in the instance")
	c.metric("security_detection_clusters_covered", float64(covered), "Clusters with a runtime sensor and an audit-log source configured")
	return nil
}

// routing: page-severity detection alerts must reach a receiver that notifies a person.
func (c *collector) routing(ctx context.Context) error {
	cfg := c.d.Value("alertmanager")
	if !pyvalue.Truthy(cfg) {
		return nil
	}
	const asset = "detection-alertmanager:routing"
	st, err := c.fetch(ctx, cfg, "/api/v2/status", nil)
	if err != nil {
		c.doc.Gap(asset, "alertmanager status: "+reason(err))
		return nil
	}
	c.doc.OK(asset)
	notifying, page := Routing(pyvalue.Str(rundoc.Map(rundoc.Get(st, "config")).GetOr("original", "")))
	v := 0.0
	if page {
		v = 1
	}
	c.metric("security_detection_page_route", v, "1 if page-severity detection alerts reach a notifying receiver")
	if page {
		return nil
	}
	names := make([]any, len(notifying))
	for i, n := range notifying {
		names[i] = n
	}
	return c.finding(&rundoc.Finding{Asset: asset, Check: "detection.page_route_missing",
		Title:    "page-severity detection alerts are recorded but reach no human (no notifying receiver on a severity=page route)",
		Severity: "high", Remediation: "route severity=page to a receiver that notifies a person (docs/detection.md)"},
		"routing.json", map[string]any{"notifying_receivers": names})
}

// fetch reads one JSON document from an endpoint config (a config error is a failure of this check only).
func (c *collector) fetch(ctx context.Context, cfg any, path string, params url.Values) (any, error) {
	e, err := c.endpoint(cfg)
	if err != nil {
		return nil, keyError("url")
	}
	return e.get(ctx, path, params)
}

// Routing reads an Alertmanager configuration (YAML): the receivers that notify somebody (sorted) and whether a
// route with a severity=page matcher, anywhere in the tree, ends at one of them. Unparsable text routes nothing.
func Routing(conf string) (notifying []string, page bool) {
	v, err := pyvalue.DecodeYAML([]byte(conf))
	doc, ok := v.(*pyvalue.Map)
	if err != nil || !ok {
		doc = pyvalue.NewMap()
	}
	set := map[string]bool{}
	for _, r := range rundoc.List(doc.Value("receivers")) {
		if rm, isMap := r.(*pyvalue.Map); isMap && notifies(rm) {
			set[pyvalue.Str(rm.Value("name"))] = true
		}
	}
	for n := range set {
		notifying = append(notifying, n)
	}
	sort.Strings(notifying)
	return notifying, pageRoute(rundoc.Map(doc.Value("route")), set, 0)
}

func notifies(r *pyvalue.Map) bool {
	for _, k := range r.Keys() {
		if strings.HasSuffix(k, "_configs") && pyvalue.Truthy(r.Value(k)) {
			return true
		}
	}
	return false
}

const maxRouteDepth = 64

func pageRoute(r *pyvalue.Map, notifying map[string]bool, depth int) bool {
	if depth > maxRouteDepth {
		return false
	}
	if recv, ok := r.Value("receiver").(string); ok && notifying[recv] {
		for _, m := range rundoc.List(r.Value("matchers")) {
			s := strings.ReplaceAll(pyvalue.Str(m), " ", "")
			if strings.Contains(s, `severity="page"`) || strings.Contains(s, "severity=page") {
				return true
			}
		}
	}
	for _, x := range rundoc.List(r.Value("routes")) {
		if pageRoute(rundoc.Map(x), notifying, depth+1) {
			return true
		}
	}
	return false
}

// sources: every expected source delivered lines to the log store within its window (a count query per source;
// no line content is read).
func (c *collector) sources(ctx context.Context, store *endpoint) error {
	windows := rundoc.Map(c.d.Value("windows"))
	expected := rundoc.Map(c.d.Value("expected"))
	for _, s := range sourceTable() {
		want := rundoc.List(expected.Value(s.name))
		if len(want) == 0 {
			continue
		}
		w := s.window
		if v, ok := windows.Get(s.name); ok {
			w = pyvalue.Str(v)
		}
		if err := c.source(ctx, store, s, w, want); err != nil {
			return err
		}
	}
	return nil
}

// Query is the LogQL count query of a source over a window.
func Query(src, label, window string) string {
	return "sum by (" + label + `) (count_over_time({source="` + src + `"}[` + window + "]))"
}

func (c *collector) source(ctx context.Context, store *endpoint, s source, w string, want []any) error {
	doc, err := store.get(ctx, "/loki/api/v1/query", url.Values{"query": {Query(s.name, s.label, w)}})
	var seen map[string]float64
	if err == nil {
		var res []any
		if res, err = apiResult(doc); err == nil {
			seen, err = vector(res, s.label)
		}
	}
	if err != nil {
		for _, x := range want {
			c.doc.Gap("log-source:"+s.name+"/"+pyvalue.Str(x), "log store query failed: "+reason(err))
		}
		return nil
	}
	names := make([]any, 0, len(seen))
	for _, k := range sortedKeys(seen) {
		names = append(names, k)
	}
	live, sev := 0, "medium"
	if s.name == "k8s-audit" || s.name == "auth" {
		sev = "high"
	}
	for _, x := range want {
		who := pyvalue.Str(x)
		asset := "log-source:" + s.name + "/" + who
		c.doc.OK(asset)
		if xs, ok := x.(string); ok && seen[xs] > 0 {
			live++
			continue
		}
		err := c.finding(&rundoc.Finding{Asset: asset, Check: "detection.source_silent", Severity: sev,
			Title:       fmt.Sprintf("no %s log lines from %s in the last %s: detections for it are blind", s.name, who, w),
			Remediation: "fix the shipper for this source (docs/detection.md#log-contract) or remove it from detection.expected"},
			"source-"+s.name+".json", map[string]any{"window": windowValue(c.d, s), "seen": names})
		if err != nil {
			return err
		}
	}
	c.metric("security_detection_sources_expected", float64(len(want)), "Sources that must deliver logs", label("source", s.name))
	c.metric("security_detection_sources_live", float64(live), "Expected sources that delivered logs in their window", label("source", s.name))
	return nil
}

// windowValue is the window as configured (a number stays a number in the evidence), or the default text.
func windowValue(d *pyvalue.Map, s source) any {
	if v, ok := rundoc.Map(d.Value("windows")).Get(s.name); ok {
		return rundoc.Loose(v)
	}
	return s.window
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// AlertName is the alert a catalog rule id becomes: SecurityDetection + the id's parts capitalised.
func AlertName(id string) string {
	var b strings.Builder
	b.WriteString("SecurityDetection")
	for _, p := range strings.Split(strings.ReplaceAll(id, "_", "-"), "-") {
		r := []rune(strings.ToLower(p))
		if len(r) > 0 {
			r[0] = unicode.ToTitle(r[0])
		}
		b.WriteString(string(r))
	}
	return b.String()
}

// ruler: the catalog's rules are loaded in the log store's ruler and evaluate without errors.
func (c *collector) ruler(ctx context.Context, store *endpoint) error {
	want := map[string]bool{}
	for _, r := range rundoc.List(c.cat.Value("rules")) {
		if id, ok := rundoc.Get(r, "id").(string); ok {
			want[AlertName(id)] = true
		}
	}
	const asset = "detection-ruler:log-store"
	doc, err := store.get(ctx, "/prometheus/api/v1/rules", nil)
	if err != nil {
		c.doc.Gap(asset, "ruler API: "+reason(err))
		return nil
	}
	c.doc.OK(asset)
	loaded, unhealthy := RulerState(doc)
	var missing []any
	both := 0
	for _, n := range sortedKeys(want) {
		if loaded[n] {
			both++
		} else {
			missing = append(missing, n)
		}
	}
	c.metric("security_detection_rules_loaded", float64(both), "Catalog rules loaded in the log store's ruler")
	c.metric("security_detection_rules_total", float64(len(want)), "Rules in the detection catalog (log-store rules)")
	c.metric("security_detection_rules_unhealthy", float64(len(unhealthy)), "Loaded rules whose last evaluation failed")
	if len(missing) == 0 && len(unhealthy) == 0 {
		return nil
	}
	if missing == nil {
		missing = []any{}
	}
	return c.finding(&rundoc.Finding{Asset: asset, Check: "detection.ruler_incomplete", Severity: "high",
		Title: fmt.Sprintf("%d catalog rule(s) not loaded, %d failing evaluation in the log store's ruler", len(missing),
			len(unhealthy)),
		Remediation: "render the rules (detections/render.py --params) and deploy them to the ruler; check its log"},
		"ruler.json", map[string]any{"missing": missing, "unhealthy": unhealthy})
}

// RulerState reads a ruler's rules answer: the loaded rule names and, in order, the names of rules whose health is
// neither ok nor unknown.
func RulerState(doc any) (loaded map[string]bool, unhealthy []any) {
	loaded, unhealthy = map[string]bool{}, []any{}
	for _, g := range rundoc.List(rundoc.Map(rundoc.Get(doc, "data")).Value("groups")) {
		for _, r := range rundoc.List(rundoc.Get(g, "rules")) {
			name := rundoc.Get(r, "name")
			if s, ok := name.(string); ok {
				loaded[s] = true
			}
			switch rundoc.Get(r, "health") {
			case nil, "ok", "unknown":
			default:
				unhealthy = append(unhealthy, rundoc.Loose(name))
			}
		}
	}
	return loaded, unhealthy
}

// alertHistory: minutes any detection alert was firing in the last 24 hours, per severity.
func (c *collector) alertHistory(ctx context.Context) error {
	cfg := c.d.Value("alert_history")
	if !pyvalue.Truthy(cfg) {
		return nil
	}
	const asset = "detection-alerts:history"
	q := `sum by (severity) (count_over_time(ALERTS{component="security-detection",alertstate="firing"}[24h]))`
	doc, err := c.fetch(ctx, cfg, "/api/v1/query", url.Values{"query": {q}})
	var per map[string]float64
	if err == nil {
		var res []any
		if res, err = apiResult(doc); err == nil {
			per, err = vector(res, "severity")
		}
	}
	if err != nil {
		c.doc.Gap(asset, "alert history query: "+reason(err))
		return nil
	}
	c.doc.OK(asset)
	for _, sev := range []string{"page", "ticket", "info"} {
		c.metric("security_detection_alert_minutes_24h", per[sev], "Minutes any detection alert was firing in the last 24h",
			label("severity", sev))
	}
	return nil
}

// missingParts names what a cluster lacks to be under detection.
func missingParts(sensed, audited bool) []string {
	var parts []string
	if !sensed {
		parts = append(parts, "runtime sensor")
	}
	if !audited {
		parts = append(parts, "audit log")
	}
	return parts
}
