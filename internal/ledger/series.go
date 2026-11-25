package ledger

import (
	"sort"

	"github.com/MIERAI/security-platform/internal/ledger/instant"
	"github.com/MIERAI/security-platform/internal/ledger/prom"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// series builds the `ledger` metrics of the registry, in the reference's order.
func (m *merger) series(slis []sliResult, gaps gapCounts, expired int64, invalid int) []prom.Series {
	var s []prom.Series
	add := func(name string, labels map[string]string, v pyjson.Value, help string) {
		s = append(s, prom.Series{Name: name, Labels: labels, Value: v, Help: help})
	}
	for _, r := range slis {
		add("security_sli", map[string]string{"sli": r.name}, r.value, "Security SLI current value")
	}
	for _, r := range slis {
		add("security_sli_objective", map[string]string{"sli": r.name}, r.def.target, "Security SLI objective (value must stay <=)")
	}
	s = append(s, m.findingCounts()...)
	for _, r := range slis {
		add("security_sli_ok", map[string]string{"sli": r.name}, boolInt(r.ok), "1 while the SLI meets its objective (slo-platform bool SLI)")
	}
	counts := m.ledger.GetOrCreateObj("sli_new_total")
	for _, k := range counts.SortedKeys() {
		v, _ := counts.Get(k)
		add("security_sli_new_total", map[string]string{"sli": k}, v, "Findings that ENTERED the SLI's set (new or reopened; counter)")
	}
	s = append(s, m.collectorHeartbeats()...)
	add("security_findings_reopened_total", nil, m.reopenedTotal(), "Regressions: fixed findings that came back (counter)")
	add("security_exceptions_active", nil, int64(len(m.byStatus(statusAccepted))), "Active exceptions")
	add("security_exceptions_expired", nil, expired+gaps.expired, "Exceptions past expiry (finding reopened / gap counted again)")
	add("security_coverage_gaps_excepted", nil, gaps.excepted, "Coverage gaps under a human-approved, unexpired exception")
	for _, col := range sortedKeys(gaps.byCollector) {
		add("security_coverage_gaps_open", map[string]string{"collector": col}, gaps.byCollector[col],
			"Coverage gaps not under an exception, per collector (latest documents)")
	}
	fixed := m.fixTimes()
	add("security_time_to_fix_days", map[string]string{"quantile": "0.5"}, medianOrZero(fixed), "Time to fix")
	add("security_time_to_fix_days", map[string]string{"quantile": "1"}, maxOrZero(fixed), "Time to fix")
	add("security_contract_invalid_documents", nil, int64(invalid), "Findings documents rejected by schema validation")
	add("security_ledger_last_update_timestamp_seconds", nil, int64(m.opt.Now), "Ledger heartbeat")
	return append(s, m.knowTimeSeries()...)
}

func boolInt(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

func medianOrZero(vals []pyjson.Value) pyjson.Value {
	if len(vals) == 0 {
		return int64(0)
	}
	return pyjson.Median(vals)
}

type countKey struct{ layer, severity, status string }

func (m *merger) findingCounts() []prom.Series {
	counts := map[countKey]int64{}
	for _, id := range m.entries.Keys() {
		if e := m.entries.Obj(id); e != nil {
			counts[countKey{e.Str("layer"), e.Str("severity"), e.Str("status")}]++
		}
	}
	keys := make([]countKey, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.layer != b.layer {
			return a.layer < b.layer
		}
		if a.severity != b.severity {
			return a.severity < b.severity
		}
		return a.status < b.status
	})
	out := make([]prom.Series, 0, len(keys))
	for _, k := range keys {
		out = append(out, prom.Series{Name: "security_findings", Value: counts[k], Help: "Ledger entries by layer/severity/status",
			Labels: map[string]string{"layer": k.layer, "severity": k.severity, "status": k.status}})
	}
	return out
}

func (m *merger) collectorHeartbeats() []prom.Series {
	cols := m.ledger.GetOrCreateObj("collectors")
	var out []prom.Series
	for _, name := range cols.SortedKeys() {
		c := cols.Obj(name)
		if c == nil || !c.Truthy("last_good_run") {
			continue
		}
		t, err := instant.Parse(c.Str("last_good_run"))
		if err != nil {
			continue
		}
		out = append(out, prom.Series{Name: "security_collector_last_good_run_timestamp_seconds",
			Labels: map[string]string{"collector": name}, Value: int64(t),
			Help: "Last run that covered at least one asset (a blind run does not count)"})
	}
	return out
}

func (m *merger) reopenedTotal() pyjson.Value {
	var vals []pyjson.Value
	for _, id := range m.entries.Keys() {
		if e := m.entries.Obj(id); e != nil {
			if v, ok := e.Get("reopened_count"); ok && pyjson.IsNumber(v) {
				vals = append(vals, v)
			}
		}
	}
	return pyjson.Sum(vals)
}

func (m *merger) fixTimes() []pyjson.Value {
	var out []pyjson.Value
	for _, id := range m.entries.Keys() {
		if e := m.entries.Obj(id); e != nil {
			if v, ok := e.Get("time_to_fix_days"); ok && pyjson.IsNumber(v) {
				out = append(out, v)
			}
		}
	}
	return out
}

type knowKey struct{ class, priority string }

func (m *merger) knowTimeSeries() []prom.Series {
	groups := map[knowKey][]pyjson.Value{}
	for _, e := range m.recentKnowTimes() {
		pr := "other"
		if urgent(e) {
			pr = "urgent"
		}
		h, _ := e.Get("time_to_know_hours")
		k := knowKey{assetClass(e.Str("asset")), pr}
		groups[k] = append(groups[k], h)
	}
	keys := make([]knowKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].class != keys[j].class {
			return keys[i].class < keys[j].class
		}
		return keys[i].priority < keys[j].priority
	})
	var out []prom.Series
	const help = "Advisory/KEV publication -> first detection on an already-covered asset (last 30 days)"
	for _, k := range keys {
		v := groups[k]
		lab := func(q string) map[string]string {
			return map[string]string{"asset_class": k.class, "priority": k.priority, "quantile": q}
		}
		out = append(out, prom.Series{Name: "security_time_to_know_hours", Labels: lab("0.5"), Value: pyjson.Median(v), Help: help},
			prom.Series{Name: "security_time_to_know_hours", Labels: lab("1"), Value: pyjson.Max(v), Help: help},
			prom.Series{Name: "security_time_to_know_detections", Labels: map[string]string{"asset_class": k.class, "priority": k.priority},
				Value: int64(len(v)), Help: "Detections counted for time-to-know (last 30 days)"})
	}
	return out
}
