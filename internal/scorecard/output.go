package scorecard

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	pv "github.com/MIERAI/security-platform/internal/scorecard/pyvalue"
)

// File modes. The report and the metrics are private (failing controls are attacker intelligence); the
// regression state and the directories follow the umask, as the reference implementation's do (a metrics
// reader may run as another user).
const (
	privateMode = 0o600
	stateMode   = 0o666
	dirMode     = 0o777
)

// UpdateRegressions applies the result to the regression state (<data>/state/scorecard.json, SPEC §5): a
// dimension that passed on the previous compute and fails now counts one regression; the first compute is a
// baseline. It writes the state and sets r.Regressions.
func UpdateRegressions(data string, r *Result) error {
	p := filepath.Join(data, "state", "scorecard.json")
	def := pv.NewMap()
	def.Set("below", pv.NewMap())
	def.Set("regressions_total", pv.NewMap())
	v := readJSONFile(p, def)
	st, err := regressionState(v)
	if err != nil {
		return err
	}
	below, total := st.below, st.total
	for _, d := range r.Dims {
		failing := d.Status == "FAIL"
		prev, isBool := below.Value(d.ID).(bool)
		wasPassing := isBool && !prev
		n := total.SetDefault(d.ID, int64(0))
		if wasPassing && failing {
			next, sumErr := pv.Sum([]any{n, int64(1)})
			if sumErr != nil {
				return configErr("state/scorecard.json: regressions_total.%s: %v", d.ID, sumErr)
			}
			total.Set(d.ID, next)
		}
		below.Set(d.ID, failing)
	}
	text, err := pv.EncodeJSON(st.doc, true)
	if err != nil {
		return err
	}
	if err := writeAtomic(p, text, stateMode); err != nil {
		return err
	}
	r.Regressions = total.Copy()
	return nil
}

// regressions is the regression state document and its two mappings.
type regressions struct {
	doc, below, total *pv.Map
}

func regressionState(v any) (regressions, error) {
	doc, ok := v.(*pv.Map)
	if !ok {
		return regressions{}, configErr("state/scorecard.json is not an object")
	}
	below, ok1 := doc.Value("below").(*pv.Map)
	total, ok2 := doc.Value("regressions_total").(*pv.Map)
	if !ok1 || !ok2 {
		return regressions{}, configErr("state/scorecard.json needs below and regressions_total objects")
	}
	return regressions{doc: doc, below: below, total: total}, nil
}

// writeAtomic writes path through path.tmp and a rename, creating the directory.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), dirMode); err != nil { // #nosec G301 -- the umask decides, as for every data directory
		return fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove stale %s: %w", tmp, err)
	}
	if err := os.WriteFile(tmp, data, mode); err != nil { // #nosec G306 -- mode chosen per file, see the constants
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// WriteOutputs writes the report (JSON and Markdown) and the metrics (SPEC §5).
func WriteOutputs(data string, r *Result) error {
	doc, encErr := pv.EncodeJSON(r.Document(), false)
	if encErr != nil {
		return encErr
	}
	md, mdErr := r.Markdown()
	if mdErr != nil {
		return mdErr
	}
	files := []struct {
		rel  string
		text []byte
	}{
		{"reports/scorecard.json", doc},
		{"reports/scorecard.md", []byte(md)},
		{"metrics/scorecard.prom", []byte(r.Prometheus())},
	}
	for _, f := range files {
		if err := writeAtomic(filepath.Join(data, filepath.FromSlash(f.rel)), f.text, privateMode); err != nil {
			return err
		}
	}
	return nil
}
