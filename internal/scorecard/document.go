package scorecard

import (
	pv "github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
)

type pair struct {
	key string
	val any
}

func kv(key string, val any) pair { return pair{key, val} }

func obj(pairs ...pair) *pv.Map {
	m := pv.NewMap()
	for _, p := range pairs {
		m.Set(p.key, p.val)
	}
	return m
}

func texts(s []string) []any { return stringsToValues(s) }

// Document is the scorecard report (schema security-platform/scorecard/v1).
func (r *Result) Document() *pv.Map {
	var weakest any
	if r.Weakest != "" {
		weakest = r.Weakest
	}
	return obj(kv("schema", Schema), kv("scorecard_version", r.Version), kv("computed_at", gmTime(r.Now)),
		kv("threshold", r.Threshold), kv("status", r.Status), kv("overall", r.Overall), kv("mean", r.Mean),
		kv("weakest", weakest), kv("dimensions", r.dimensionsDoc()), kv("not_applicable", r.notApplicableDoc()),
		kv("pillars", r.pillarsDoc()), kv("functions", r.functionsDoc()), kv("dimension_pillar", r.crossDoc()),
		kv("attestations", r.Attestations.doc()), kv("controls", r.controlsDoc()),
		kv("regressions_total", r.regressionsDoc()))
}

func (r *Result) dimensionsDoc() *pv.Map {
	m := pv.NewMap()
	for _, d := range r.Dims {
		m.Set(d.ID, obj(kv("title", d.Title), kv("order", d.Order), kv("owner", d.Owner), kv("threshold", d.Threshold),
			kv("pillars", texts(d.Pillars)), kv("functions", texts(d.Functions)), kv("score", d.Score), kv("status", d.Status),
			kv("weight_total", d.WeightTotal), kv("weight_passed", d.WeightPassed), kv("controls", int64(d.Controls)),
			kv("failing", texts(d.Failing))))
	}
	return m
}

func (r *Result) notApplicableDoc() *pv.Map {
	m := pv.NewMap()
	for _, d := range r.NotApplic {
		m.Set(d.ID, obj(kv("title", d.Title), kv("order", d.Order), kv("reason", d.Reason),
			kv("controls", int64(d.Controls))))
	}
	return m
}

func (r *Result) pillarsDoc() *pv.Map {
	m := pv.NewMap()
	for _, p := range r.Pillars {
		m.Set(p.Key, obj(kv("score", p.Score), kv("controls", int64(p.Controls)), kv("status", p.Status),
			kv("failing", texts(p.Failing))))
	}
	return m
}

func (r *Result) functionsDoc() *pv.Map {
	m := pv.NewMap()
	for _, f := range r.Functions {
		m.Set(f.Key, obj(kv("title", f.Title), kv("score", f.Score), kv("controls", int64(f.Controls))))
	}
	return m
}

func (r *Result) crossDoc() *pv.Map {
	m := pv.NewMap()
	for k, v := range r.Cross {
		m.Set(k, v)
	}
	return m
}

func (a AttestationCounts) doc() *pv.Map {
	return obj(kv("valid", int64(a.Valid)), kv("expiring", int64(a.Expiring)), kv("expired", int64(a.Expired)),
		kv("missing", int64(a.Missing)))
}

func (r *Result) regressionsDoc() *pv.Map {
	if r.Regressions == nil {
		return pv.NewMap()
	}
	return r.Regressions
}

func (r *Result) controlsDoc() []any {
	out := make([]any, 0, len(r.Controls))
	for _, c := range r.Controls {
		var expires any
		if c.Expires != 0 {
			expires = gmDate(c.Expires)
		}
		out = append(out, obj(kv("id", c.ID), kv("dimension", c.Dimension), kv("title", c.get("title")),
			kv("pillars", c.get("pillars")), kv("csf", c.get("csf")), kv("function", c.Function), kv("cis", c.get("cis")),
			kv("check", c.get("check")), kv("weight", c.get("weight")), kv("status", c.Status), kv("detail", c.Detail),
			kv("needs_human", pv.Truthy(c.get("needs_human")) || c.isAttested()), kv("attestable", attestable(c)),
			kv("question", c.get("question")), kv("remediation", c.raw.GetOr("remediation", "")), kv("expires", expires)))
	}
	return out
}
