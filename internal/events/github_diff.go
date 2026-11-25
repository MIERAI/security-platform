package events

import (
	"context"
	"fmt"
	"sort"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// diff compares the previous snapshot with this one: keys, hooks, deploy keys and installations added or removed,
// repositories whose visibility changed or that were created public. A kind readable on one side only is skipped.
func (g *ghRun) diff(prev *pyvalue.Map) ([]*event, error) {
	kinds := map[string]bool{}
	for _, k := range append(prev.Keys(), g.snap.Keys()...) {
		kinds[k] = true
	}
	names := make([]string, 0, len(kinds))
	for k := range kinds {
		names = append(names, k)
	}
	sort.Strings(names)
	var evs []*event
	for _, kind := range names {
		if !prev.Has(kind) || !g.snap.Has(kind) {
			continue
		}
		old, cur := rundoc.MapOr(prev.Value(kind)), rundoc.MapOr(g.snap.Value(kind))
		var add []*event
		var err error
		if kind == "repo" {
			add, err = g.repoChanges(old, cur)
		} else {
			add, err = g.addedRemoved(kind, old, cur)
		}
		if err != nil {
			return nil, err
		}
		evs = append(evs, add...)
	}
	return evs, nil
}

func (g *ghRun) repoChanges(old, cur *pyvalue.Map) ([]*event, error) {
	var evs []*event
	for _, name := range cur.Keys() {
		r := rundoc.MapOr(cur.Value(name))
		was := old.Value(name)
		switch {
		case pyvalue.Truthy(was):
			e, err := g.visibilityChange(name, r, was)
			if err != nil {
				return nil, err
			}
			if e != nil {
				evs = append(evs, e)
			}
		case r.Value("visibility") == "public":
			e, err := g.ev("repo_created_public", name, r)
			if err != nil {
				return nil, err
			}
			evs = append(evs, e)
		}
	}
	return evs, nil
}

func (g *ghRun) addedRemoved(kind string, old, cur *pyvalue.Map) ([]*event, error) {
	var evs []*event
	for _, side := range []struct {
		suffix   string
		from, in *pyvalue.Map
	}{{"_added", cur, old}, {"_removed", old, cur}} {
		var keys []string
		for _, k := range side.from.Keys() {
			if !side.in.Has(k) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			rec, err := getOr(side.from.Value(k), "repo", "")
			if err != nil {
				return nil, err
			}
			e, err := g.ev(kind+side.suffix, pyvalue.Str(or(rec, "")), rundoc.MapOr(side.from.Value(k)))
			if err != nil {
				return nil, err
			}
			evs = append(evs, e)
		}
	}
	return evs, nil
}

// ev is ship.py GitHubAccountSource.ev: the record with its event, as a compact JSON line.
func (g *ghRun) ev(name string, repo any, rec *pyvalue.Map) (*event, error) {
	line := rec.Copy()
	line.Set("event", name)
	text, err := dumps(line, lineJSON())
	if err != nil {
		return nil, fmt.Errorf("encode record: %w", err)
	}
	meta := pyvalue.NewMap()
	meta.Set("event", name)
	meta.Set("actor", g.login)
	meta.Set("repo", or(repo, ""))
	return &event{ts: g.s.now, line: text, meta: meta}, nil
}

// publicEvents reads the account's public events: a PublicEvent (a repository became public) not seen before is an
// event, a second signal independent of the snapshot. The first run only remembers them.
func (g *ghRun) publicEvents(ctx context.Context) ([]*event, []any, error) {
	ans, err := g.api.get(ctx, "/users/"+pyvalue.Str(g.login)+"/events?per_page=100", true)
	st, body, _ := ans.status, ans.body, ans.link
	if err != nil {
		return nil, nil, err
	}
	list, isList := body.([]any)
	if st != 200 || !isList {
		return nil, nil, nil
	}
	return g.publicRecords(list)
}

// publicRecords turns the PublicEvent records of an events page into events; ids of every PublicEvent seen.
func (g *ghRun) publicRecords(list []any) ([]*event, []any, error) {
	seen := seenIDs(g.s.state.Value("events_seen"))
	var ids []any
	var out []*event
	for _, e := range list {
		em, err := getOr(e, "type", nil)
		if err != nil {
			return nil, nil, err
		}
		if em != "PublicEvent" {
			continue
		}
		id, err := item(e, "id")
		if err != nil {
			return nil, nil, err
		}
		ids = append(ids, id)
		if g.s.first || hashable(id) && seen[id] {
			continue
		}
		ev, err := g.publicEvent(rundoc.MapOr(e))
		if err != nil {
			return nil, nil, err
		}
		out = append(out, ev)
	}
	return out, ids, nil
}

func hashable(v any) bool {
	switch v.(type) {
	case string, int64, bool, nil, float64:
		return true
	}
	return false
}

func (g *ghRun) publicEvent(e *pyvalue.Map) (*event, error) {
	repo, err := getOr(e.GetOr("repo", pyvalue.NewMap()), "name", nil)
	if err != nil {
		return nil, err
	}
	actor, err := getOr(e.GetOr("actor", pyvalue.NewMap()), "login", "")
	if err != nil {
		return nil, err
	}
	rec := pyvalue.NewMap()
	rec.Set("type", "PublicEvent")
	rec.Set("repo", repo)
	rec.Set("created_at", e.Value("created_at"))
	text, err := dumps(rec, lineJSON())
	if err != nil {
		return nil, fmt.Errorf("encode record: %w", err)
	}
	ts, ok, err := isoTS(e.Value("created_at"), g.s.d.loc)
	if err != nil {
		return nil, err
	}
	if !ok || ts == 0 {
		ts = g.s.now
	}
	meta := pyvalue.NewMap()
	meta.Set("event", "repo_made_public")
	meta.Set("actor", actor)
	meta.Set("repo", or(repo, ""))
	return &event{ts: ts, line: text, meta: meta}, nil
}

// visibilityChange is the event of a repository whose visibility changed (nil when it did not).
func (g *ghRun) visibilityChange(name string, r *pyvalue.Map, was any) (*event, error) {
	wasVis, err := item(was, "visibility")
	if err != nil {
		return nil, err
	}
	if pyvalue.Equal(wasVis, r.Value("visibility")) {
		return nil, nil //nolint:nilnil // unchanged: no event
	}
	ev := "repo_made_" + pyvalue.Str(r.Value("visibility"))
	if r.Value("visibility") == "public" {
		ev = "repo_made_public"
	}
	rec := pyvalue.NewMap()
	rec.Set("repo", name)
	rec.Set("from", wasVis)
	rec.Set("to", r.Value("visibility"))
	return g.ev(ev, name, rec)
}

// seenIDs is the set of event ids already seen (ids that cannot be set members are left out).
func seenIDs(v any) map[any]bool {
	seen := map[any]bool{}
	for _, x := range rundoc.List(v) {
		if hashable(x) {
			seen[x] = true
		}
	}
	return seen
}
