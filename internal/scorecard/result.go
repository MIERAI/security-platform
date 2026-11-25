package scorecard

import (
	"sort"

	pv "github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
)

func pillarOrder() []string { return []string{"network", "device", "people", "software"} }

func functionOrder() []string { return []string{"GV", "ID", "PR", "DE", "RS", "RC"} }

func functionTitles() map[string]string {
	return map[string]string{"GV": "Govern", "ID": "Identify", "PR": "Protect", "DE": "Detect", "RS": "Respond",
		"RC": "Recover"}
}

// Result is one computed scorecard (SPEC §4).
type Result struct {
	Version      string
	Now          float64
	Threshold    float64
	Status       string
	Overall      float64
	Mean         float64
	Weakest      string // "" when no dimension applies
	Dims         []*DimensionScore
	NotApplic    []NotApplicable
	Pillars      []GroupScore
	Functions    []GroupScore
	Cross        map[string]float64 // "<dimension>|<pillar>"
	Attestations AttestationCounts
	Controls     []*Control
	Regressions  *pv.Map // dimension -> count, from the regression state
}

// DimensionScore is an applicable dimension's score.
type DimensionScore struct {
	ID, Status                string
	Title, Order, Owner       any
	Threshold, Score          float64
	Pillars, Functions        []string
	WeightTotal, WeightPassed any
	Controls                  int
	Failing                   []string
}

// NotApplicable is a dimension that is excluded from every score.
type NotApplicable struct {
	ID, Reason   string
	Title, Order any
	Controls     int
}

// GroupScore is a pillar's or a CSF function's score.
type GroupScore struct {
	Key, Title, Status string
	Score              float64
	Controls           int
	Failing            []string
}

// AttestationCounts counts the attestable controls by attestation state.
type AttestationCounts struct{ Valid, Expiring, Expired, Missing int }

// score is the weighted pass ratio of a set of controls (SPEC §4): 100 × Σw(pass) / Σw(not na), rounded to one
// decimal; 0 when the denominator is 0. The sums keep integer weights integers.
func score(items []*Control) (pct float64, weightTotal, weightPassed any) {
	var all, passed []any
	for _, c := range items {
		if c.Status != "na" {
			all = append(all, c.get("weight"))
		}
		if c.Status == "pass" {
			passed = append(passed, c.get("weight"))
		}
	}
	w, werr := pv.Sum(all)
	p, perr := pv.Sum(passed)
	if werr != nil || perr != nil || !pv.Truthy(w) { // weights are numbers (validateForCompute)
		return 0, w, p
	}
	wf, _ := pv.ToFloat64(w)
	pf, _ := pv.ToFloat64(p)
	return pv.Round(100.0*pf/wf, 1), w, p
}

func failing(items []*Control) []string {
	out := []string{}
	for _, c := range items {
		if c.Status != "pass" && c.Status != "na" {
			out = append(out, c.ID)
		}
	}
	return out
}

func passFail(ok bool) string {
	if ok {
		return "PASS"
	}
	return "FAIL"
}

func buildResult(cat *Catalog, dimNA map[string]string, threshold float64, e *evaluator, o Options) (*Result, error) {
	r := &Result{Version: o.Version, Now: o.Now, Threshold: threshold, Controls: cat.Controls}
	if err := r.scoreDimensions(cat, dimNA, threshold); err != nil {
		return nil, err
	}
	pillars, err := pillarKeys(e.pillars)
	if err != nil {
		return nil, err
	}
	if err := r.scorePillars(pillars, threshold); err != nil {
		return nil, err
	}
	r.scoreFunctions()
	if err := r.scoreCross(pillars); err != nil {
		return nil, err
	}
	r.countAttestations()
	r.summarize()
	return r, nil
}

// where returns the controls that satisfy pred, in report order.
func (r *Result) where(pred func(*Control) bool) []*Control {
	var out []*Control
	for _, c := range r.Controls {
		if pred(c) {
			out = append(out, c)
		}
	}
	return out
}

func (r *Result) scoreDimensions(cat *Catalog, dimNA map[string]string, threshold float64) error {
	dims, err := sortedDimensions(cat)
	if err != nil {
		return err
	}
	for _, d := range dims {
		items := r.where(func(c *Control) bool { return c.Dimension == d.ID })
		reason, out := dimNA[d.ID]
		if !out && len(items) > 0 && allNA(items) {
			reason, out = "every control is not applicable", true
		}
		if !d.raw.Has("title") {
			return configErr("dimension %s: title missing", d.ID)
		}
		if out {
			r.NotApplic = append(r.NotApplic, NotApplicable{ID: d.ID, Reason: reason, Title: d.raw.Value("title"),
				Order: d.order(), Controls: len(items)})
			continue
		}
		ds, err := dimensionScore(d, items, threshold)
		if err != nil {
			return err
		}
		r.Dims = append(r.Dims, ds)
	}
	return nil
}

func sortedDimensions(cat *Catalog) ([]*Dimension, error) {
	keys := map[*Dimension]float64{}
	for _, d := range cat.Dims {
		k, err := orderKey(d)
		if err != nil {
			return nil, err
		}
		keys[d] = k
	}
	dims := append([]*Dimension(nil), cat.Dims...)
	sort.SliceStable(dims, func(i, j int) bool { return keys[dims[i]] < keys[dims[j]] })
	return dims, nil
}

func allNA(items []*Control) bool {
	for _, c := range items {
		if c.Status != "na" {
			return false
		}
	}
	return true
}
