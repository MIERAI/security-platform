package cli

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/cli/flags"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// filter is the `sp findings` selection; every given condition must hold (contract §2).
type filter struct {
	open, overdue        bool
	severity, layer, chk string
}

func (f filter) match(e *pyvalue.Map, items map[string]*pyvalue.Map) bool {
	switch {
	case f.open && get(e, "status") != "open":
		return false
	case f.severity != "" && sevRank(get(e, "severity")) > sevRank(f.severity):
		return false
	case f.layer != "" && get(e, "layer") != f.layer:
		return false
	case f.chk != "" && !strings.HasPrefix(get(e, "check"), f.chk):
		return false
	case f.overdue && !pyvalue.Truthy(field(items[get(e, "id")], "overdue")):
		return false
	}
	return true
}

// worstFirst sorts entries by severity, then layer, then asset (stable: ledger order breaks ties).
func worstFirst(rows []*pyvalue.Map) {
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if ra, rb := sevRank(get(a, "severity")), sevRank(get(b, "severity")); ra != rb {
			return ra < rb
		}
		if la, lb := get(a, "layer"), get(b, "layer"); la != lb {
			return la < lb
		}
		return get(a, "asset") < get(b, "asset")
	})
}

func runFindings(_ context.Context, s *session, a *flags.Result) (int, error) {
	if err := s.locate(); err != nil {
		return 0, err
	}
	led, err := s.ledger()
	if err != nil {
		return 0, err
	}
	items, err := s.items()
	if err != nil {
		return 0, err
	}
	f := filter{open: a.Bool("open"), overdue: a.Bool("overdue"), severity: a.String("severity"),
		layer: a.String("layer"), chk: a.String("check")}
	var rows []*pyvalue.Map
	for _, e := range led.entries {
		if f.match(e, items) {
			rows = append(rows, e)
		}
	}
	worstFirst(rows)
	switch {
	case a.Bool("json"):
		return writeJSON(s, rows)
	case a.Bool("ids"):
		ids := make([]string, len(rows))
		for i, e := range rows {
			ids[i] = safe(get(e, "id"))
		}
		return ExitOK, emit(s.env.Stdout, strings.Join(ids, "\n")+"\n")
	case len(rows) == 0:
		return ExitOK, emit(s.env.Stdout, "no matching findings\n")
	}
	return ExitOK, emit(s.env.Stdout, s.table(rows, items))
}

// writeJSON prints the entries as json.dumps(rows, indent=1, sort_keys=True) does (machine-readable, schema
// cli/findings-json-v1).
func writeJSON(s *session, rows []*pyvalue.Map) (int, error) {
	list := make([]any, len(rows))
	for i, e := range rows {
		list[i] = e
	}
	b, err := pyvalue.EncodeJSON(list, true)
	if err != nil {
		return 0, fmt.Errorf("findings: %w", err)
	}
	return ExitOK, emit(s.env.Stdout, string(b)+"\n")
}

// table prints the human table: fixed column widths (contract §2), DUE as the local date of the tracker's due_at.
func (s *session) table(rows []*pyvalue.Map, items map[string]*pyvalue.Map) string {
	var b strings.Builder
	b.WriteString(ljust("ID", 13) + ljust("SEVERITY", 10) + ljust("STATUS", 9) + ljust("DUE", 12) + ljust("LAYER", 13) +
		ljust("ASSET", 38) + "WHAT\n")
	for _, e := range rows {
		sev := get(e, "severity")
		b.WriteString(ljust(safe(get(e, "id")), 13))
		// the color codes count in the width, so the visible column stays 10 wide
		b.WriteString(ljust(s.sevColor(safe(sev)), 10+len(s.sevColor(sev))-len(sev)))
		b.WriteString(ljust(safe(get(e, "status")), 9))
		due := s.dueText(items[get(e, "id")])
		if due == "OVERDUE" {
			due = s.paint("31", due)
		}
		b.WriteString(ljust(due, 12))
		b.WriteString(ljust(safe(get(e, "layer")), 13))
		b.WriteString(ljust(safe(head(get(e, "asset"), 37)), 38))
		b.WriteString(safe(head(get(e, "title"), 70)) + "\n")
	}
	fmt.Fprintf(&b, "\n%d finding(s). Details and how to fix: sp explain <ID>\n", len(rows))
	return b.String()
}

func (s *session) dueText(it *pyvalue.Map) string {
	if it == nil {
		return "-"
	}
	if pyvalue.Truthy(it.Value("overdue")) {
		return "OVERDUE"
	}
	due := it.Value("due_at")
	if !pyvalue.Truthy(due) {
		return "-"
	}
	t, err := ts(due)
	if err != nil {
		return "-"
	}
	return s.localDate(t)
}
