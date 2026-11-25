package remediation

import (
	"github.com/MIERAI/security-platform/internal/ledger/prom"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

func severities() []string {
	return []string{"critical", "high", "medium", "low", "info"}
}

// severitySeries are the open, overdue and time-to-remediate series of one severity.
func severitySeries(items *pyjson.Object, sev string) []prom.Series {
	var open, overdue int64
	var ttr []pyjson.Value
	for _, id := range items.Keys() {
		it := items.Obj(id)
		if it == nil || it.Str("severity") != sev {
			continue
		}
		if it.Str("status") == "open" {
			open++
		}
		if it.Truthy("overdue") {
			overdue++
		}
		if v, _ := it.Get("time_to_remediate_days"); it.Str("status") == "fixed" && v != nil {
			ttr = append(ttr, v)
		}
	}
	s := []prom.Series{
		{Name: "security_remediation_open", Labels: map[string]string{"severity": sev}, Value: open, Help: "Open findings being remediated"},
		{Name: "security_remediation_overdue", Labels: map[string]string{"severity": sev}, Value: overdue,
			Help: "Open findings past their remediation SLO"},
	}
	if len(ttr) == 0 {
		return s
	}
	const help = "Time from opened (or reopened) to fixed, closed items"
	return append(s,
		prom.Series{Name: "security_time_to_remediate_days", Labels: map[string]string{"severity": sev, "quantile": "0.5"},
			Value: pyjson.Median(ttr), Help: help},
		prom.Series{Name: "security_time_to_remediate_days", Labels: map[string]string{"severity": sev, "quantile": "1"},
			Value: pyjson.Max(ttr), Help: help})
}

// renderSeries is the `remediation` metrics of the registry, in the reference's order.
func renderSeries(items *pyjson.Object, slo map[string]int64, wall float64) string {
	var s []prom.Series
	for _, sev := range severities() {
		s = append(s, severitySeries(items, sev)...)
	}
	for _, cls := range sortedKeys(slo) {
		s = append(s, prom.Series{Name: "security_remediation_slo_seconds", Labels: map[string]string{"severity": cls},
			Value: slo[cls], Help: "Remediation SLO per class"})
	}
	var unassigned int64
	for _, id := range items.Keys() {
		if it := items.Obj(id); it != nil && it.Str("status") == "open" && it.Str("owner") == "unassigned" {
			unassigned++
		}
	}
	s = append(s, prom.Series{Name: "security_remediation_unassigned", Value: unassigned, Help: "Open items without an owner"},
		prom.Series{Name: "security_remediation_last_update_timestamp_seconds", Value: int64(wall), Help: "Remediation tracker heartbeat"})
	return prom.Render(s)
}
