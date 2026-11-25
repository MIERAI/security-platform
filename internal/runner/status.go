//go:build unix

package runner

import (
	"github.com/MIERAI/security-platform/internal/runner/config"
	"github.com/MIERAI/security-platform/internal/runner/pyfmt"
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
	return pyfmt.JSONIndent1(out)
}

// decodeSite reads state/sites/<site>.json (written by an ingest job): the site's label and its jobs' public
// states in the file's order.
func decodeSite(data []byte) (siteFile, bool) {
	doc, err := config.Parse(data)
	if err != nil {
		return siteFile{}, false
	}
	m, ok := doc.(*config.Map)
	if !ok {
		return siteFile{}, false
	}
	site, ok := m.Get("site").(string)
	if !ok {
		return siteFile{}, false
	}
	sf := siteFile{site: site}
	if jobs, ok := m.Get("jobs").(*config.Map); ok {
		sf.names, sf.jobs = jobs.Keys, jobs.Plain()
	}
	return sf, true
}

// siteFile is state/sites/<site>.json: a site's label and its jobs' public states in the file's order.
type siteFile struct {
	site  string
	names []string
	jobs  map[string]any
}
