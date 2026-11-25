package scorecard

import (
	"sort"
	"strconv"
	"strings"

	pv "github.com/MIERAI/security-platform/internal/pyvalue"
)

// Widths of the Markdown report's control columns (characters).
const (
	mdTitleWidth  = 70
	mdDetailWidth = 160
)

// Markdown is the human report (its format is not part of the contract; it is kept identical to the reference
// implementation's so that the two can be compared during the move).
func (r *Result) Markdown() (string, error) {
	weakest := "None"
	if r.Weakest != "" {
		weakest = r.Weakest
	}
	l := []string{"# Security scorecard " + gmTime(r.Now), "",
		"**" + r.Status + "** - overall (weakest dimension) " + pv.FloatRepr(r.Overall) + " / threshold " +
			pv.FormatG(r.Threshold) + "; mean " + pv.FloatRepr(r.Mean) + "; weakest: " + weakest + ".", "",
		"PRIVATE: failing controls are attacker intelligence.", "",
		"## Dimensions", "", "| # | dimension | score | status | pillars | CSF | failing controls |",
		"|---|---|---|---|---|---|---|"}
	for _, d := range r.Dims {
		fail := strings.Join(d.Failing, ", ")
		if fail == "" {
			fail = "-"
		}
		l = append(l, "| "+pv.Str(d.Order)+" | "+pv.Str(d.Title)+" (`"+d.ID+"`) | "+pv.FloatRepr(d.Score)+" | "+
			d.Status+" | "+strings.Join(d.Pillars, ", ")+" | "+strings.Join(d.Functions, ", ")+" | "+fail+" |")
	}
	for _, d := range r.NotApplic {
		l = append(l, "| "+pv.Str(d.Order)+" | "+pv.Str(d.Title)+" (`"+d.ID+"`) | n/a | NOT APPLICABLE | - | - | "+
			d.Reason+" |")
	}
	l = append(l, "", "## Pillars", "", "| pillar | score | controls |", "|---|---|---|")
	for _, p := range r.Pillars {
		l = append(l, "| "+p.Key+" | "+pv.FloatRepr(p.Score)+" | "+strconv.Itoa(p.Controls)+" |")
	}
	l = append(l, "", "## NIST CSF 2.0 functions", "", "| function | score | controls |", "|---|---|---|")
	for _, f := range r.Functions {
		l = append(l, "| "+f.Key+" "+f.Title+" | "+pv.FloatRepr(f.Score)+" | "+strconv.Itoa(f.Controls)+" |")
	}
	a := r.Attestations
	l = append(l, "", "## Attestations: "+strconv.Itoa(a.Valid)+" valid, "+strconv.Itoa(a.Expiring)+
		" expiring within 14 days, "+strconv.Itoa(a.Expired)+" expired, "+strconv.Itoa(a.Missing)+" missing", "",
		"## Controls", "", "| control | dim | check | w | status | detail | CIS |", "|---|---|---|---|---|---|---|")
	rows, err := r.controlRows()
	if err != nil {
		return "", err
	}
	return strings.Join(append(l, rows...), "\n") + "\n", nil
}

func statusRank(s string) int {
	ranks := map[string]int{"fail": 0, "expired": 0, "unattested": 1, "unknown": 2, "not_implemented": 3, "pass": 5,
		"na": 6}
	if r, ok := ranks[s]; ok {
		return r
	}
	return 4
}

// controlRows lists the controls, failing first, then by dimension and id.
func (r *Result) controlRows() ([]string, error) {
	cs := append([]*Control(nil), r.Controls...)
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if ra, rb := statusRank(a.Status), statusRank(b.Status); ra != rb {
			return ra < rb
		}
		if a.Dimension != b.Dimension {
			return a.Dimension < b.Dimension
		}
		return a.ID < b.ID
	})
	rows := make([]string, 0, len(cs))
	for _, c := range cs {
		row, err := controlRow(c)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func controlRow(c *Control) (string, error) {
	title, ok := c.get("title").(string)
	if !ok {
		return "", configErr("%s: title must be text", c.ID)
	}
	w, _ := pv.ToFloat64(c.get("weight")) // a number (validateForCompute)
	cis, err := pv.Iter(c.get("cis"))
	if err != nil {
		return "", configErr("%s: cis: %v", c.ID, err)
	}
	refs := make([]string, len(cis))
	for i, x := range cis {
		refs[i] = pv.Str(x)
	}
	detail := strings.ReplaceAll(truncate(c.Detail, mdDetailWidth), "|", "/")
	return "| `" + c.ID + "` " + truncate(title, mdTitleWidth) + " | " + c.Dimension + " | " + pv.Str(c.get("check")) +
		" | " + pv.FormatG(w) + " | " + c.Status + " | " + detail + " | " + strings.Join(refs, ", ") + " |", nil
}
