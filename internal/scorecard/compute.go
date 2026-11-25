package scorecard

import (
	"context"
	"regexp"

	pv "github.com/MIERAI/security-platform/internal/pyvalue"
)

// variable is a ${name} reference in a control's source. Compiled once, never written.
var variable = regexp.MustCompile(`\$\{([a-zA-Z0-9_]+)\}`)

// Options are the inputs of one compute (SPEC §1-2).
type Options struct {
	Data          string  // the data directory, absolute
	Product       string  // the product tree (its scorecard/catalog, relative evidence paths, ${product})
	Home          string  // the user's home directory, for ~ in paths; "" = no expansion
	Instance      any     // the decoded instance configuration; nil when there is none
	Now           float64 // epoch seconds
	ExtraCatalogs []string
	Version       string // the scorecard component version (scorecard/VERSION)
	GitLog        GitLog
}

// scorecardSection is the instance's `scorecard:` block (empty when absent).
func scorecardSection(inst any) (*pv.Map, error) {
	root, ok := orEmpty(inst)
	if !ok {
		return nil, configErr("the instance is not a mapping")
	}
	return section(root, "scorecard", "")
}

// Compute evaluates every control and scores the dimensions, pillars and functions. It changes nothing on
// disk (the regression state and the reports are written by Run).
func Compute(ctx context.Context, o Options) (*Result, error) {
	sc, err := scorecardSection(o.Instance)
	if err != nil {
		return nil, err
	}
	threshold, err := pv.ToFloat(sc.GetOr("threshold", int64(75)))
	if err != nil {
		return nil, configErr("scorecard.threshold: %v", err)
	}
	dirs, err := catalogDirs(sc, o.Product, o.Home, o.ExtraCatalogs)
	if err != nil {
		return nil, err
	}
	cat, err := LoadCatalog(dirs, sc)
	if err != nil {
		return nil, err
	}
	e, err := newEvaluator(ctx, o, sc, cat)
	if err != nil {
		return nil, err
	}
	dimNA, err := dimensionsNotApplicable(cat, o.Instance, e.in)
	if err != nil {
		return nil, err
	}
	if errs := lintInstance(sc); len(errs) > 0 {
		return nil, configErr("instance scorecard: %s", errs[0])
	}
	if err := e.evaluateAll(sc, o.Instance, dimNA); err != nil {
		return nil, err
	}
	return buildResult(cat, dimNA, threshold, e, o)
}

func newEvaluator(ctx context.Context, o Options, sc *pv.Map, cat *Catalog) (*evaluator, error) {
	for _, c := range cat.Controls {
		if err := validateForCompute(c); err != nil {
			return nil, err
		}
	}
	att, err := loadAttestations(o.Data)
	if err != nil {
		return nil, err
	}
	in, err := loadInputs(o.Data)
	if err != nil {
		return nil, err
	}
	git := o.GitLog
	if git == nil {
		git = func(context.Context, string, string) string { return "" }
	}
	return &evaluator{ctx: ctx, now: o.Now, in: in, att: att, controls: cat.Controls,
		pillars: sc.GetOr("pillars", stringsToValues(pillarOrder())), data: o.Data, product: o.Product, home: o.Home,
		gitLog: git}, nil
}

// dimensionsNotApplicable maps every dimension whose applies_when does not hold to the reason.
func dimensionsNotApplicable(cat *Catalog, inst any, in *inputs) (map[string]string, error) {
	out := map[string]string{}
	for _, d := range cat.Dims {
		ok, why, err := applicable(d.raw.Value("applies_when"), inst, in)
		if err != nil {
			return nil, err
		}
		if !ok {
			out[d.ID] = why
		}
	}
	return out, nil
}

// evaluateAll decides every control in report order; builtin sources last, in report order.
func (e *evaluator) evaluateAll(sc *pv.Map, inst any, dimNA map[string]string) error {
	vars, err := buildVars(sc, e.data, e.product)
	if err != nil {
		return err
	}
	scope, err := newScope(sc, inst, e.in)
	if err != nil {
		return err
	}
	type deferredSource struct {
		c   *Control
		src *pv.Map
	}
	var later []deferredSource
	for _, c := range e.controls {
		src, done, err := e.decideWithoutSource(c, scope, inst, dimNA, vars)
		if err != nil {
			return err
		}
		if done {
			continue
		}
		if pv.Equal(src.Value("type"), "builtin") {
			later = append(later, deferredSource{c, src})
			continue
		}
		if err := e.run(c, src); err != nil {
			return err
		}
	}
	for _, d := range later {
		if err := e.run(d.c, d.src); err != nil {
			return err
		}
	}
	return nil
}

func (e *evaluator) run(c *Control, src *pv.Map) error {
	e.current = c
	out, err := e.evaluate(src)
	if err != nil {
		return configErr("%s: %v", c.ID, err)
	}
	c.Status, c.Detail = out.status, out.detail
	return nil
}
