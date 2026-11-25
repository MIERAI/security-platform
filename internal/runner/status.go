//go:build unix

package runner

import (
	"fmt"

	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Status is contract §5: job name -> its state plus `due` (the reason of §3) and `schedule`, as Python's
// json.dumps(..., indent=1, sort_keys=True).
func (r *Runner) Status() ([]byte, error) {
	out := map[string]any{}
	now := r.clock.Decision()
	for _, j := range r.inst.Jobs {
		st := r.LoadState(j.Name)
		m := map[string]any{}
		for k, v := range st {
			m[k] = v
		}
		m["due"] = Due(j, st, now, r.loc).Reason
		m["schedule"] = j.Schedule.String()
		out[j.Name] = m
	}
	data, err := pyvalue.EncodeJSON(toPy(out), true)
	if err != nil {
		return nil, fmt.Errorf("status: %w", err)
	}
	return data, nil
}

// decodeSite reads state/sites/<site>.json (written by an ingest job): the site's label and its jobs' public
// states in the file's order.
func decodeSite(data []byte) (siteFile, bool) {
	doc, err := pyvalue.DecodeJSON(data)
	if err != nil {
		return siteFile{}, false
	}
	m, ok := doc.(*pyvalue.Map)
	if !ok {
		return siteFile{}, false
	}
	site, ok := m.Value("site").(string)
	if !ok {
		return siteFile{}, false
	}
	sf := siteFile{site: site}
	if jobs, ok := m.Value("jobs").(*pyvalue.Map); ok {
		sf.names = jobs.Keys()
		sf.jobs, _ = fromPy(jobs).(map[string]any) // a *pyvalue.Map always converts to a map
	}
	return sf, true
}

// siteFile is state/sites/<site>.json: a site's label and its jobs' public states in the file's order.
type siteFile struct {
	site  string
	names []string
	jobs  map[string]any
}
