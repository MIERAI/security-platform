package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/MIERAI/security-platform/internal/cli/flags"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// exceptionDays is how far ahead the snippet's expiry date is.
const exceptionDays = 90

// maxListed bounds how many ids an ambiguous-prefix message names.
const maxListed = 10

// resolve finds the finding an id or a unique id prefix names (CLI-D4: an ambiguous prefix is an error).
func resolve(led *ledgerDoc, id string) (*pyvalue.Map, error) {
	if e, ok := led.byID[id]; ok {
		return e, nil
	}
	var hits []string
	if id != "" {
		for _, k := range led.keys {
			if strings.HasPrefix(k, id) {
				hits = append(hits, k)
			}
		}
	}
	switch len(hits) {
	case 0:
		return nil, die(ExitUsage, "no finding %s (list them with `sp findings`)", safe(id))
	case 1:
		return led.byID[hits[0]], nil
	}
	listed := hits
	if len(listed) > maxListed {
		listed = append(listed[:maxListed:maxListed], "...")
	}
	return nil, die(ExitUsage, "%s matches %d findings: %s (give more of the id)", safe(id), len(hits),
		safe(strings.Join(listed, ", ")))
}

func runExplain(_ context.Context, s *session, a *flags.Result) (int, error) {
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
	e, err := resolve(led, a.Arg("id"))
	if err != nil {
		return 0, err
	}
	var b strings.Builder
	s.explainHeader(&b, e, items[get(e, "id")])
	s.explainBody(&b, e)
	return ExitOK, emit(s.env.Stdout, b.String())
}

func (s *session) explainHeader(b *strings.Builder, e, it *pyvalue.Map) {
	sev, layer := get(e, "severity"), get(e, "layer")
	b.WriteString(s.paint("1", safe(get(e, "title"))) + "\n")
	fmt.Fprintf(b, "id %s   check %s   %s (%s)\n", safe(get(e, "id")), safe(get(e, "check")), s.sevColor(safe(sev)),
		s.texts.Severity(sev))
	fmt.Fprintf(b, "where: %s   area: %s - %s\n", safe(get(e, "asset")), safe(layer), s.texts.Layer(layer))
	fmt.Fprintf(b, "status: %s   first seen %s   last seen %s", safe(get(e, "status")), safe(head(get(e, "first_seen"), 10)),
		safe(head(get(e, "last_seen"), 10)))
	if rc := field(e, "reopened_count"); pyvalue.Truthy(rc) {
		fmt.Fprintf(b, "   came back %sx", str(rc))
	}
	b.WriteString("\n")
	if it != nil && it.Len() > 0 {
		due := "-"
		if v := it.Value("due_at"); pyvalue.Truthy(v) {
			due = pyvalue.Str(v)
		}
		fmt.Fprintf(b, "owner: %s   fix by: %s", str(it.GetOr("owner", "-")), safe(head(due, 10)))
		if pyvalue.Truthy(it.Value("overdue")) {
			b.WriteString(s.paint("31", "   OVERDUE"))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
}

func (s *session) explainBody(b *strings.Builder, e *pyvalue.Map) {
	x := s.texts.Explain(get(e, "check"))
	if x.What != "" {
		b.WriteString(s.paint("1", "What it means") + "\n  " + x.What + "\n")
	}
	if x.Why != "" {
		b.WriteString(s.paint("1", "Why it matters") + "\n  " + x.Why + "\n")
	}
	b.WriteString(s.paint("1", "How to fix") + "\n")
	for _, line := range splitLines(x.Fix) {
		b.WriteString("  " + line + "\n")
	}
	if r := field(e, "remediation"); pyvalue.Truthy(r) {
		fmt.Fprintf(b, "  (collector's note: %s)\n", str(r))
	}
	b.WriteString(s.paint("1", "How to verify") + "\n  " + x.Verify + "\n")
	if pyvalue.Truthy(field(e, "needs_human")) {
		b.WriteString("\n  This one needs a person (a password, an account setting or a physical step); no automation can do it.\n")
	}
	id := safe(get(e, "id"))
	expires := s.localDate(epochNow(s.env.Now()) + exceptionDays*86400)
	b.WriteString(s.paint("1", "\nIf you decide to accept the risk instead") + " (a human decision with an end date), add to " +
		filepath.Join(s.data, "exceptions.yaml") + ":\n")
	fmt.Fprintf(b, "  exceptions:\n    %s:\n      approved_by: <your name>\n      reason: <why this is acceptable for now>\n"+
		"      expires: '%s'\n", id, expires)
	evidence, _, _ := strings.Cut(get(e, "evidence"), "#")
	fmt.Fprintf(b, "\nevidence (private): %s/.../%s\n", filepath.Join(s.data, "runs"), safe(evidence))
}

// splitLines is Python's str.splitlines() for the line breaks the texts use.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(strings.ReplaceAll(s, "\r\n", "\n"), "\n"), "\n")
}
