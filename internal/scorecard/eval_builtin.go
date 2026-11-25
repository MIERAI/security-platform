package scorecard

import (
	"strconv"
	"strings"

	pv "github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
)

// evalBuiltin answers questions about the scorecard itself; evaluated after every other control.
//
//	pillars_covered / functions_covered  every pillar / CSF function has a passing control of the `check`
//	                                     kinds (default [automated])
//	attestations_current                 no control is expired
func evalBuiltin(e *evaluator, src *pv.Map) (outcome, error) {
	name, err := item(src, "name")
	if err != nil {
		return outcome{}, err
	}
	switch {
	case pv.Equal(name, "pillars_covered"):
		return e.covered(src, "pillars", e.pillars)
	case pv.Equal(name, "functions_covered"):
		return e.covered(src, "functions", stringsToValues(functionOrder()))
	case pv.Equal(name, "attestations_current"):
		return e.attestationsCurrent(), nil
	}
	return outcome{}, pv.ValueError("unknown builtin " + pv.Repr(name))
}

func (e *evaluator) covered(src *pv.Map, key string, want any) (outcome, error) {
	auto := src.GetOr("check", []any{"automated"})
	have := map[string]bool{}
	for _, c := range e.controls {
		in, err := pv.In(c.get("check"), auto)
		if err != nil {
			return outcome{}, err
		}
		if !in || c.Status != "pass" {
			continue
		}
		if err := addCovered(have, c, key); err != nil {
			return outcome{}, err
		}
	}
	wanted, err := pv.Iter(want)
	if err != nil {
		return outcome{}, err
	}
	var missing []any
	for _, x := range wanted {
		if !have[collectorKey(x)] {
			missing = append(missing, x)
		}
	}
	kinds, err := pv.JoinStrings("/", auto)
	if err != nil {
		return outcome{}, err
	}
	if len(missing) == 0 {
		return outcome{"pass", "every " + strings.TrimSuffix(key, "s") + " has a passing " + kinds + " control"}, nil
	}
	list, err := pv.JoinStrings(", ", missing)
	if err != nil {
		return outcome{}, err
	}
	return outcome{"fail", "no passing " + kinds + " control for: " + list}, nil
}

func addCovered(have map[string]bool, c *Control, key string) error {
	if key == "functions" {
		have[c.Function] = true
		return nil
	}
	items, err := pv.Iter(c.get("pillars"))
	if err != nil {
		return err
	}
	for _, p := range items {
		have[collectorKey(p)] = true
	}
	return nil
}

func (e *evaluator) attestationsCurrent() outcome {
	attested := 0
	var bad []string
	for _, c := range e.controls {
		if c.isAttested() {
			attested++
		}
		if c.Status == "expired" {
			bad = append(bad, c.ID)
		}
	}
	if len(bad) > 0 {
		return outcome{"fail", "expired: " + strings.Join(bad, ", ")}
	}
	return outcome{"pass", strconv.Itoa(attested) + " attested controls, none expired"}
}
