package exposure

import (
	"slices"
	"strings"
)

// Verdict is one classified exposure.
type Verdict struct {
	Check, Severity, Title, Remediation string
}

// entry is one open port's probe entry, read loosely (a probe document is data from another host).
type entry map[string]any

func (e entry) path(p string) map[string]any {
	paths, _ := e["paths"].(map[string]any) // absent: not HTTP
	r, _ := paths[p].(map[string]any)       // absent or another shape: no answer
	return r
}

// status is r.get("status") as a number; ok false when absent or not a number.
func status(r map[string]any) (int64, bool) {
	switch x := r["status"].(type) {
	case int64:
		return x, true
	case float64:
		return int64(x), x == float64(int64(x))
	case bool:
		if x {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case int64:
		return x != 0
	case float64:
		return x != 0
	case string:
		return x != ""
	case []any:
		return len(x) > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

func (e entry) st(p string) int64 {
	n, _ := status(e.path(p)) // absent: 0, never a status the checks look for
	return n
}

func (e entry) ok2xx(p string) bool {
	r := e.path(p)
	n, ok := status(r)
	return ok && n != 0 && n >= 200 && n < 300 && !truthy(r["auth"])
}

func (e entry) snip(p string) string {
	s, _ := e.path(p)["snippet"].(string) // absent: ""
	return s
}

func (e entry) service() any { return e["nmap_service"] }

// Classify is the exposure of one open port, by response fingerprint (generic), not by the instance's port numbers,
// except for non-HTTP protocols, which nmap names.
func Classify(port int, e map[string]any) []Verdict {
	en := entry(e)
	if _, ok := e["paths"]; !ok {
		return classifyPlain(port, en)
	}
	paths, _ := e["paths"].(map[string]any) // another shape: no paths answered
	if catchAll(en, paths) {                // SPA / catch-all: every path answers the same page
		return []Verdict{{"http.catch_all_unverified", "low",
			"web app answers every path with the same page; login enforcement not verifiable by GET",
			"verify login is required; ensure open sign-up is disabled"}}
	}
	authed := anyAuth(en, paths)
	out := classifyAPIs(en)
	if len(out) == 0 && en.ok2xx("/metrics") {
		out = append(out, Verdict{"metrics.unauth", "low", "/metrics readable without auth (software versions, internals)",
			"restrict to the scraper"})
	}
	if len(out) == 0 && en.ok2xx("/") && !authed {
		out = append(out, Verdict{"http.unauth_root", "low", "HTTP service answers / without auth (purpose unknown)",
			"identify the service; require auth or close"})
	}
	return out
}

func classifyPlain(port int, e entry) []Verdict {
	svc, _ := e.service().(string) // null or absent: no name
	switch {
	case port == 23 || svc == "telnet":
		return []Verdict{{"telnet.open", "high", "telnet (cleartext remote login) is reachable", "disable telnetd / firewall the port"}}
	case slices.Contains([]int{5432, 55432, 3306, 6379, 27017, 9200, 2379}, port) ||
		slices.Contains([]string{"postgresql", "mysql", "redis", "mongodb"}, svc):
		what := svc
		if what == "" {
			what = itoa(port)
		}
		return []Verdict{{"db.reachable", "medium", "database port reachable from the vantage point (" + what + ")",
			"bind to localhost / a private bridge; firewall it"}}
	case svc == "netbios-ssn" || svc == "microsoft-ds":
		return []Verdict{{"smb.reachable", "medium", "SMB (" + svc + ") is reachable from the vantage point",
			"bind SMB to the LAN only / disable guest access"}}
	}
	return nil
}

func flag(e entry, name string) bool {
	fields, _ := e.path("/api/v1/status/flags")["fields"].(map[string]any) // absent: no flags read
	return fields[name] == "true"
}

func classifyAPIs(e entry) []Verdict {
	var out []Verdict
	am := e.snip("/api/v2/status")
	if e.ok2xx("/api/v2/status") && (strings.Contains(am, "cluster") || strings.Contains(am, "config")) {
		out = append(out, Verdict{"alertmanager.unauth", "high", "Alertmanager API without auth: anyone can create silences",
			"put behind an auth proxy or expose only via port-forward"})
	} else if e.ok2xx("/api/v1/status/buildinfo") && strings.Contains(e.snip("/api/v1/status/buildinfo"), "version") {
		out = append(out, Verdict{"prometheus.unauth_read", "medium",
			"Prometheus query API without auth (topology, labels, targets disclosed)", "auth proxy; keep the admin API disabled"})
	}
	if flag(e, "web.enable-remote-write-receiver") {
		out = append(out, Verdict{"prometheus.unauth_remote_write", "high",
			"Prometheus remote_write receiver accepts unauthenticated clients: metrics (incl. SLOs) can be forged",
			"auth/mTLS on the receiver or an allowlist of writers"})
	}
	if e.ok2xx("/api/tags") && strings.Contains(e.snip("/api/tags"), "models") {
		out = append(out, Verdict{"ollama.unauth", "high", "Ollama API without auth: anyone can run, pull or delete models",
			"bind to localhost behind an authenticating proxy"})
	}
	if flag(e, "web.enable-admin-api") {
		out = append(out, Verdict{"prometheus.admin_api_unauth", "high", "Prometheus admin API enabled without auth (delete series)",
			"disable --web.enable-admin-api or put behind auth"})
	}
	return append(out, classifyMore(e)...)
}

func classifyMore(e entry) []Verdict {
	var out []Verdict
	if e.ok2xx("/loki/api/v1/labels") && strings.Contains(strings.ReplaceAll(e.snip("/loki/api/v1/labels"), " ", ""), `"status":"success"`) {
		out = append(out, Verdict{"loki.unauth", "high", "Loki without auth: all shipped logs readable and forgeable (query + push)",
			"auth proxy / per-tenant auth"})
	}
	if e.ok2xx("/api/search") && strings.Contains(e.snip("/api/search"), "traces") {
		out = append(out, Verdict{"tempo.unauth_read", "medium", "Tempo search API without auth: traces readable", "auth proxy"})
	}
	if e.st("/v1/traces") == 405 {
		out = append(out, Verdict{"otlp.unauth_ingest", "low", "OTLP/HTTP ingest without auth: spans can be forged", "allowlist senders"})
	}
	if e.st("/probe") == 400 && (strings.Contains(strings.ToLower(e.snip("/probe")), "target") ||
		strings.Contains(strings.ToLower(e.snip("/")), "blackbox")) {
		out = append(out, Verdict{"blackbox.open_probe", "medium",
			"blackbox_exporter /probe reachable: usable as an SSRF relay into the network",
			"restrict callers to the monitoring server"})
	}
	return out
}

// catchAll: six or more paths answer 2xx without auth, all with the same snippet.
func catchAll(en entry, paths map[string]any) bool {
	var two []string
	for p := range paths {
		if en.ok2xx(p) {
			two = append(two, p)
		}
	}
	bodies := map[string]bool{}
	for _, p := range two {
		bodies[en.snip(p)] = true
	}
	return len(bodies) == 1 && len(two) >= 6
}

// anyAuth: some path asked for authentication (401, 403 or WWW-Authenticate).
func anyAuth(en entry, paths map[string]any) bool {
	for p := range paths {
		r := en.path(p)
		n, _ := status(r) // not a number: neither 401 nor 403
		if n == 401 || n == 403 || truthy(r["auth"]) {
			return true
		}
	}
	return false
}
