package remediation

import (
	"sort"

	"github.com/MIERAI/security-platform/internal/ledger/instant"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// Item statuses that close an item.
func closed(status string) bool {
	return status == "fixed" || status == "false_positive"
}

// maxHistory is how many status changes an item keeps.
const maxHistory = 20

// Update mirrors the ledger entries into items (§7): a pure function of (items, entries, cfg, now).
func Update(items, entries, cfg *pyjson.Object, now float64, slo map[string]int64) {
	if entries == nil {
		return
	}
	ids := entries.Keys()
	sort.Strings(ids)
	for _, id := range ids {
		e := entries.Obj(id)
		if e == nil {
			continue
		}
		st := e.Str("status")
		it := items.Obj(id)
		if it == nil {
			if closed(st) {
				continue // never open while tracked: nothing to remediate
			}
			first, _ := e.Get("first_seen")
			it = pyjson.ObjectOf("id", id, "opened_at", first, "reopened_at", nil, "reopen_reason", nil,
				"closed_at", nil, "time_to_remediate_days", nil, "history", []pyjson.Value{})
			items.Set(id, it)
		}
		updateItem(it, e, cfg, now, slo)
	}
}

func updateItem(it, e, cfg *pyjson.Object, now float64, slo map[string]int64) {
	st := e.Str("status")
	prevV, _ := it.Get("status")
	prev, _ := prevV.(string)
	reopen(it, e, prev, st, now)
	owner, why := ownerOf(e, cfg)
	cls := ClassOf(e)
	start, startOK := clockStart(it)
	due, hasDue := DueAt(start, cls, slo)
	hasDue = hasDue && startOK
	var dueAt pyjson.Value
	if hasDue {
		dueAt = instant.ISO(due)
	}
	copyEntry(it, e)
	for _, kv := range [][2]any{{"status", st}, {"slo_class", cls}, {"owner", owner}, {"owner_source", why},
		{"due_at", dueAt}, {"exception", exceptionOf(e, st)}} {
		k, _ := kv[0].(string) // literal keys above
		it.Set(k, kv[1])
	}
	if closed(st) && !closed(prev) {
		closeItem(it, e, now, start, startOK)
	}
	it.Set("overdue", st == "open" && hasDue && now > due)
	if s, ok := prevV.(string); !ok || s != st {
		appendHistory(it, now, st)
	}
}

// copyEntry copies what an item shows of its ledger entry.
func copyEntry(it, e *pyjson.Object) {
	for _, k := range []string{"check", "layer", "asset", "title", "severity"} {
		v, _ := e.Get(k)
		it.Set(k, v)
	}
	text, ok := e.Get("remediation")
	if !ok {
		text = ""
	}
	it.Set("remediation", text)
	it.Set("needs_human", e.Truthy("needs_human"))
}

// closeItem records the closure: at the ledger's fixed_at (else now), and the time to remediate.
func closeItem(it, e *pyjson.Object, now, start float64, startOK bool) {
	closedAt := now
	if fixedAt := e.Str("fixed_at"); e.Str("status") == "fixed" && fixedAt != "" {
		if t, err := instant.Parse(fixedAt); err == nil {
			closedAt = t
		}
	}
	it.Set("closed_at", instant.ISO(closedAt))
	var ttr pyjson.Value
	if startOK {
		ttr = pyjson.Round((closedAt-start)/86400, 2)
	}
	it.Set("time_to_remediate_days", ttr)
}

// reopen records a closed item coming back (regression), or an accepted one whose exception expired.
func reopen(it, e *pyjson.Object, prev, st string, now float64) {
	if closed(prev) && !closed(st) {
		reason := "reopened by the ledger"
		if prev == "fixed" {
			reason = "regression"
		}
		it.Set("reopened_at", instant.ISO(now))
		it.Set("closed_at", nil)
		it.Set("time_to_remediate_days", nil)
		it.Set("reopen_reason", reason)
	}
	if exc := e.Obj("exception"); prev == "accepted" && st == "open" && exc != nil && exc.Truthy("expired") {
		it.Set("reopened_at", instant.ISO(now))
		it.Set("reopen_reason", "exception expired")
	}
}

// clockStart is when the item's SLO clock started: reopened_at, else opened_at.
func clockStart(it *pyjson.Object) (float64, bool) {
	start, _ := it.Get("reopened_at")
	if !pyjson.Truthy(start) {
		start, _ = it.Get("opened_at")
	}
	t, err := instant.Parse(pyjson.Str(start))
	return t, err == nil
}

func exceptionOf(e *pyjson.Object, st string) pyjson.Value {
	if st != "accepted" {
		return nil
	}
	exc := e.Obj("exception")
	if exc == nil {
		exc = pyjson.NewObject()
	}
	out := pyjson.NewObject()
	for _, k := range []string{"approved_by", "expires", "reason"} {
		v, _ := exc.Get(k)
		out.Set(k, v)
	}
	return out
}

func appendHistory(it *pyjson.Object, now float64, st string) {
	h, _ := it.Get("history")
	list, _ := h.([]pyjson.Value) // missing or malformed: start a new one
	list = append(list, pyjson.ObjectOf("at", instant.ISO(now), "status", st))
	if len(list) > maxHistory {
		list = list[len(list)-maxHistory:]
	}
	it.Set("history", list)
}

// roleHints are owner values that are not a team (the SDK's role hints and placeholders).
func roleHints() []string {
	return []string{"unknown", "unassigned", "platform", "human"}
}

// ownerOf: the first matching rule, else the finding's own team, else the default owner, else unassigned.
func ownerOf(e, cfg *pyjson.Object) (owner pyjson.Value, source string) {
	if cfg != nil {
		rules, _ := cfg.Get("owners")
		list, _ := rules.([]pyjson.Value) // absent or not a list: no rules
		for _, x := range list {
			if r, ok := x.(*pyjson.Object); ok && ruleMatches(r, e) {
				o, _ := r.Get("owner")
				return o, "rule"
			}
		}
	}
	if o := e.Str("owner"); o != "" && !pyjson.Contains(stringsToValues(roleHints()), o) {
		return o, "finding"
	}
	if cfg != nil && cfg.Truthy("default_owner") {
		o, _ := cfg.Get("default_owner")
		return o, "default"
	}
	return "unassigned", "none"
}

func ruleMatches(r, e *pyjson.Object) bool {
	for _, c := range [][2]string{{"layer_in", "layer"}, {"severity_in", "severity"}} {
		if v, ok := r.Get(c[0]); ok && !pyjson.Contains(v, e.Str(c[1])) {
			return false
		}
	}
	for _, c := range [][2]string{{"asset_prefix", "asset"}, {"check_prefix", "check"}} {
		if v, ok := r.Get(c[0]); ok && !hasPrefix(e.Str(c[1]), pyjson.Str(v)) {
			return false
		}
	}
	return true
}

func hasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

func stringsToValues(ss []string) []pyjson.Value {
	out := make([]pyjson.Value, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
