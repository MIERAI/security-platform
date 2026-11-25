package ledger

import (
	"sort"

	"github.com/MIERAI/security-platform/internal/ledger/instant"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// exceptionState is what an exceptions.yaml entry means now.
type exceptionState int

const (
	excIgnored exceptionState = iota // no human or no expiry (or an expiry that is not a date): not an exception
	excValid
	excExpired
)

// evaluate classifies one exception (finding or coverage) at time now.
func (m *merger) evaluate(key string, x pyjson.Value) (exceptionState, *pyjson.Object) {
	o, ok := x.(*pyjson.Object)
	if !ok || !o.Truthy("approved_by") || !o.Truthy("expires") {
		return excIgnored, nil
	}
	expires, _ := o.Get("expires")
	t, err := instant.Parse(pyjson.Str(expires))
	if err != nil {
		m.warn("exception %q: ignored: expires %s is not a date", key, pyjson.Repr(expires))
		return excIgnored, nil
	}
	if t > m.opt.Now {
		return excValid, o
	}
	return excExpired, o
}

// asStrings is {k: str(v)}: the exception as the ledger records it.
func asStrings(o *pyjson.Object) *pyjson.Object {
	out := pyjson.NewObject()
	for _, k := range o.Keys() {
		v, _ := o.Get(k)
		out.Set(k, pyjson.Str(v))
	}
	return out
}

// applyExceptions applies §5 and returns how many finding exceptions are expired. LEDGER-D5: an accepted entry
// that no valid exception names any more is open again.
func (m *merger) applyExceptions(exc *pyjson.Object) int64 {
	var expired int64
	valid := map[string]bool{}
	if exc != nil {
		for _, id := range exc.Keys() {
			x, _ := exc.Get(id)
			switch m.applyException(id, x) {
			case excValid:
				valid[id] = true
			case excExpired:
				expired++
			case excIgnored:
			}
		}
	}
	if !m.opt.Reference[DeviationRemovedException] {
		m.reopenUnexcepted(valid)
	}
	return expired
}

// applyException applies one exceptions.yaml entry to its ledger entry (fixed entries stay fixed).
func (m *merger) applyException(id string, x pyjson.Value) exceptionState {
	e := m.entries.Obj(id)
	if e == nil || e.Str("status") == statusFixed {
		return excIgnored
	}
	state, o := m.evaluate(id, x)
	switch state {
	case excValid:
		e.Set("status", statusAccepted)
		e.Set("exception", asStrings(o))
	case excExpired:
		rec := asStrings(o)
		rec.Set("expired", true)
		e.Set("status", statusOpen)
		e.Set("exception", rec)
	case excIgnored:
	}
	return state
}

// reopenUnexcepted is LEDGER-D5: acceptance holds only while a valid exception says so.
func (m *merger) reopenUnexcepted(valid map[string]bool) {
	for _, id := range m.entries.Keys() {
		if e := m.entries.Obj(id); e != nil && e.Str("status") == statusAccepted && !valid[id] {
			e.Set("status", statusOpen)
			e.Delete("exception")
		}
	}
}

// gapCounts are the coverage gaps of the current documents (§6).
type gapCounts struct {
	total, excepted, expired int64
	byCollector              map[string]int64
}

// countGaps counts the gaps of docs, minus those under a valid coverage exception.
func (m *merger) countGaps(docs []document, cexc *pyjson.Object) gapCounts {
	g := gapCounts{byCollector: map[string]int64{}}
	for _, d := range docs {
		g.byCollector[d.collector] += 0
		for _, c := range d.coverage {
			if c.Str("status") != "gap" {
				continue
			}
			switch m.coverageException(cexc, d.collector, c.Str("asset")) {
			case excValid:
				g.excepted++
				continue
			case excExpired:
				g.expired++
			case excIgnored:
			}
			g.total++
			g.byCollector[d.collector]++
		}
	}
	return g
}

func (m *merger) coverageException(cexc *pyjson.Object, collector, asset string) exceptionState {
	if cexc == nil {
		return excIgnored
	}
	key := collector + "|" + asset
	x, _ := cexc.Get(key)
	if !pyjson.Truthy(x) {
		key = asset
		x, _ = cexc.Get(asset)
	}
	state, _ := m.evaluate(key, x)
	return state
}

// updateCollectors records last_run and last_good_run of every collector merged in this run.
func (m *merger) updateCollectors(docs []document) {
	cols := m.ledger.GetOrCreateObj("collectors")
	for _, d := range docs {
		c := cols.GetOrCreateObj(d.collector)
		c.Set("last_run", d.finished)
		for _, cov := range d.coverage {
			if cov.Str("status") == "ok" {
				c.Set("last_good_run", d.finished)
				break
			}
		}
	}
}

func sortedKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
