package scorecard

import (
	"sort"

	pv "github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
)

func dimensionScore(d *Dimension, items []*Control, threshold float64) (*DimensionScore, error) {
	th := threshold
	if d.raw.Has("threshold") {
		f, err := pv.ToFloat(d.raw.Value("threshold"))
		if err != nil {
			return nil, configErr("dimension %s: threshold: %v", d.ID, err)
		}
		th = f
	}
	pillars := map[string]bool{}
	functions := map[string]bool{}
	for _, c := range items {
		names, err := textItems(c.get("pillars"))
		if err != nil {
			return nil, configErr("%s: pillars: %v", c.ID, err)
		}
		for _, p := range names {
			pillars[p] = true
		}
		functions[c.Function] = true
	}
	s, w, p := score(items)
	return &DimensionScore{ID: d.ID, Title: d.raw.Value("title"), Order: d.order(), Owner: d.raw.Value("owner"),
		Threshold: th, Pillars: sortedKeys(pillars), Functions: sortedKeys(functions), Score: s,
		Status: passFail(len(items) > 0 && s >= th), WeightTotal: w, WeightPassed: p, Controls: len(items),
		Failing: failing(items)}, nil
}

// textItems is an iterable whose elements must all be text.
func textItems(v any) ([]string, error) {
	items, err := pv.Iter(v)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(items))
	for i, x := range items {
		s, ok := x.(string)
		if !ok {
			return nil, pv.TypeError("not text: " + pv.Repr(x))
		}
		out[i] = s
	}
	return out, nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// pillarKeys is the instance's pillar list (default network, device, people, software), duplicates dropped.
func pillarKeys(v any) ([]string, error) {
	items, err := textItems(v)
	if err != nil {
		return nil, configErr("scorecard.pillars: %v", err)
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range items {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out, nil
}

func (r *Result) withPillar(pl, dim string) ([]*Control, error) {
	var out []*Control
	for _, c := range r.Controls {
		if dim != "" && c.Dimension != dim {
			continue
		}
		in, err := pv.In(pl, c.get("pillars"))
		if err != nil {
			return nil, configErr("%s: pillars: %v", c.ID, err)
		}
		if in {
			out = append(out, c)
		}
	}
	return out, nil
}

func (r *Result) scorePillars(pillars []string, threshold float64) error {
	for _, pl := range pillars {
		items, err := r.withPillar(pl, "")
		if err != nil {
			return err
		}
		s, _, _ := score(items)
		r.Pillars = append(r.Pillars, GroupScore{Key: pl, Score: s, Controls: len(items),
			Status: passFail(len(items) > 0 && s >= threshold), Failing: failing(items)})
	}
	return nil
}

func (r *Result) scoreFunctions() {
	titles := functionTitles()
	for _, f := range functionOrder() {
		items := r.where(func(c *Control) bool { return c.Function == f })
		s, _, _ := score(items)
		r.Functions = append(r.Functions, GroupScore{Key: f, Title: titles[f], Score: s, Controls: len(items)})
	}
}

func (r *Result) scoreCross(pillars []string) error {
	r.Cross = map[string]float64{}
	for _, d := range r.Dims {
		for _, pl := range pillars {
			items, err := r.withPillar(pl, d.ID)
			if err != nil {
				return err
			}
			if len(items) > 0 {
				r.Cross[d.ID+"|"+pl], _, _ = score(items)
			}
		}
	}
	return nil
}

// countAttestations counts the attestable controls a human decided (or should decide): an automated control
// whose source decided without its attestation is not counted.
func (r *Result) countAttestations() {
	for _, c := range r.Controls {
		if !countsAsAttestation(c) {
			continue
		}
		switch {
		case c.Status == "expired":
			r.Attestations.Expired++
		case c.Status == "unattested":
			r.Attestations.Missing++
		case c.Expires != 0 && c.Expires-r.Now < expiringSoon:
			r.Attestations.Expiring++
		default:
			r.Attestations.Valid++
		}
	}
}

func countsAsAttestation(c *Control) bool {
	if !attestable(c) || c.Status == "na" {
		return false
	}
	return c.isAttested() || c.hasExpires || c.Status == "unattested" || c.Status == "expired"
}

// summarize: PASS only when every applicable dimension passes; overall = the minimum dimension score;
// weakest = the first dimension with it; mean (informative) rounded to one decimal.
func (r *Result) summarize() {
	r.Status = passFail(len(r.Dims) > 0)
	scores := make([]any, 0, len(r.Dims))
	for i, d := range r.Dims {
		if d.Status != "PASS" {
			r.Status = "FAIL"
		}
		if i == 0 || d.Score < r.Overall {
			r.Overall, r.Weakest = d.Score, d.ID
		}
		scores = append(scores, d.Score)
	}
	if len(scores) > 0 {
		if sum, err := pv.Sum(scores); err == nil { // always: scores are floats
			f, _ := pv.ToFloat64(sum)
			r.Mean = pv.Round(f/float64(len(scores)), 1)
		}
	}
}
