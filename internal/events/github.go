package events

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// nextRx finds the next page in a Link header. Never written after initialisation.
var nextRx = regexp.MustCompile(`<([^>]+)>;[\t\n\x0b\x0c\r ]*rel="next"`)

// nextLink is ship.py next_link.
func nextLink(link string) string {
	if m := nextRx.FindStringSubmatch(link); m != nil {
		return m[1]
	}
	return ""
}

// keyEndpoints are the account's keys, in the reference's order.
func keyEndpoints() [][2]string {
	return [][2]string{{"ssh_key", "/user/keys"}, {"gpg_key", "/user/gpg_keys"}, {"signing_key", "/user/ssh_signing_keys"}}
}

// tokenFrom is ship.py token_from: token_file (0600) or the named environment variable (GH_TOKEN by default).
func (s *source) tokenFrom() (string, error) {
	if f := s.cfg.Value("token_file"); pyvalue.Truthy(f) {
		return readSecret(pyvalue.Str(f), s.d.home)
	}
	return s.d.getenv(pyvalue.Str(s.getOr("token_env", "GH_TOKEN"))), nil
}

// ghRun is one github-account collection.
type ghRun struct {
	s           *source
	api         *apiClient
	login       any
	snap, unsup *pyvalue.Map
}

// github snapshots the account (keys, repository visibility, deploy keys and hooks of its own repositories, app
// installations) and reports the differences with the previous snapshot, plus PublicEvent records.
func (s *source) github(ctx context.Context) ([]*event, *pyvalue.Map, error) {
	token, err := s.tokenFrom()
	if err != nil {
		return nil, nil, err
	}
	cache := rundoc.MapOr(s.state.Value("http_cache")).Copy()
	g := &ghRun{s: s, snap: pyvalue.NewMap(), unsup: pyvalue.NewMap(), api: &apiClient{
		base: strings.TrimRight(pyvalue.Str(s.getOr("api", "https://api.github.com")), "/"), token: token,
		agent: "security-platform-events/" + Version, cache: cache, http: s.d.client()}}
	if serr := g.snapshot(ctx); serr != nil {
		return nil, nil, serr
	}
	var evs []*event
	if prev, ok := s.state.Get("snapshot"); ok && prev != nil {
		if evs, err = g.diff(rundoc.MapOr(prev)); err != nil {
			return nil, nil, err
		}
	}
	pub, ids, err := g.publicEvents(ctx)
	if err != nil {
		return nil, nil, err
	}
	evs = append(evs, pub...)
	next := s.state.Copy()
	next.Set("snapshot", g.snap)
	next.Set("http_cache", cache)
	next.Set("unsupported", g.unsup)
	next.Set("api_calls", g.api.calls)
	all, err := sortedIDs(unionIDs(rundoc.List(s.state.Value("events_seen")), ids))
	if err != nil {
		return nil, nil, err
	}
	next.Set("events_seen", tail(all, 500))
	return evs, next, nil
}

func (g *ghRun) snapshot(ctx context.Context) error {
	ans, err := g.api.get(ctx, "/user", true)
	st, me, _ := ans.status, ans.body, ans.link
	if err != nil {
		return err
	}
	if st != 200 {
		return pyErr("RuntimeError", fmt.Sprintf("/user: HTTP %d", st))
	}
	if g.login, err = item(me, "login"); err != nil {
		return err
	}
	for _, kp := range keyEndpoints() {
		if kerr := g.keys(ctx, kp[0], kp[1]); kerr != nil {
			return kerr
		}
	}
	repos, err := g.repos(ctx)
	if err != nil {
		return err
	}
	if err := g.repoKeysAndHooks(ctx, repos); err != nil {
		return err
	}
	return g.installations(ctx)
}

func (g *ghRun) keys(ctx context.Context, kind, path string) error {
	ans, err := g.api.get(ctx, path, true)
	st, body, _ := ans.status, ans.body, ans.link
	if err != nil {
		return err
	}
	if st != 200 {
		g.unsup.Set(path, int64(st))
		return nil
	}
	items, err := iterate(body)
	if err != nil {
		return err
	}
	out := pyvalue.NewMap()
	for _, k := range items {
		id, err := item(k, "id")
		if err != nil {
			return err
		}
		km := rundoc.MapOr(k)
		rec := pyvalue.NewMap()
		rec.Set("id", id)
		rec.Set("title", or(km.Value("title"), km.Value("name"), km.GetOr("key_id", "")))
		rec.Set("created_at", km.Value("created_at"))
		out.Set(pyvalue.Str(id), rec)
	}
	g.snap.Set(kind, out)
	return nil
}

func (g *ghRun) repos(ctx context.Context) ([]any, error) {
	var repos []any
	for u := "/user/repos?affiliation=owner&per_page=100"; u != ""; {
		ans, err := g.api.get(ctx, u, true)
		st, body, link := ans.status, ans.body, ans.link
		if err != nil {
			return nil, err
		}
		if st != 200 {
			return nil, pyErr("RuntimeError", fmt.Sprintf("/user/repos: HTTP %d", st))
		}
		page, err := iterate(body)
		if err != nil {
			return nil, err
		}
		repos = append(repos, page...)
		u = nextLink(link)
	}
	out := pyvalue.NewMap()
	for _, r := range repos {
		name, err := item(r, "full_name")
		if err != nil {
			return nil, err
		}
		rm := rundoc.MapOr(r)
		vis := rm.Value("visibility")
		if !pyvalue.Truthy(vis) {
			vis = "public"
			if pyvalue.Truthy(rm.Value("private")) {
				vis = "private"
			}
		}
		rec := pyvalue.NewMap()
		rec.Set("full_name", name)
		rec.Set("visibility", vis)
		out.Set(pyvalue.Str(name), rec)
	}
	g.snap.Set("repo", out)
	return repos, nil
}

// owned are the account's own, not archived repositories, most recently pushed first, at most max_repos.
func (g *ghRun) owned(repos []any) ([]*pyvalue.Map, error) {
	var out []*pyvalue.Map
	for _, r := range repos {
		owner, err := getOr(r, "owner", pyvalue.NewMap())
		if err != nil {
			return nil, err
		}
		login, err := getOr(owner, "login", nil)
		if err != nil {
			return nil, err
		}
		rm := rundoc.MapOr(r)
		if pyvalue.Equal(login, g.login) && !pyvalue.Truthy(rm.Value("archived")) {
			out = append(out, rm)
		}
	}
	pushed := func(m *pyvalue.Map) string { return pyvalue.Str(or(m.Value("pushed_at"), "")) }
	sort.SliceStable(out, func(i, j int) bool { return pushed(out[i]) > pushed(out[j]) })
	limit, err := g.s.intOr("max_repos", 50)
	if err != nil {
		return nil, err
	}
	return out[:sliceEnd(len(out), limit)], nil
}

// sliceEnd is the end index of l[:n] (a negative n counts from the end).
func sliceEnd(length int, n int64) int {
	switch {
	case n < 0:
		return max(0, length+int(max(n, int64(-length))))
	case n > int64(length):
		return length
	}
	return int(n)
}

func (g *ghRun) repoKeysAndHooks(ctx context.Context, repos []any) error {
	owned, err := g.owned(repos)
	if err != nil {
		return err
	}
	for _, kind := range [][2]string{{"deploy_key", "keys"}, {"hook", "hooks"}} {
		items := pyvalue.NewMap()
		for _, r := range owned {
			if err := g.repoItems(ctx, r, kind, items); err != nil {
				return err
			}
		}
		g.snap.Set(kind[0], items)
	}
	return nil
}

func (g *ghRun) repoItems(ctx context.Context, r *pyvalue.Map, kind [2]string, items *pyvalue.Map) error {
	full := pyvalue.Str(r.Value("full_name"))
	ans, err := g.api.get(ctx, "/repos/"+full+"/"+kind[1]+"?per_page=100", true)
	st, body, _ := ans.status, ans.body, ans.link
	if err != nil {
		return err
	}
	if st != 200 {
		g.unsup.Set("/repos/*/"+kind[1], int64(st))
		return nil
	}
	list, err := iterate(body)
	if err != nil {
		return err
	}
	for _, k := range list {
		id, err := item(k, "id")
		if err != nil {
			return err
		}
		km := rundoc.MapOr(k)
		rec := pyvalue.NewMap()
		rec.Set("id", id)
		rec.Set("repo", r.Value("full_name"))
		rec.Set("created_at", km.Value("created_at"))
		if kind[0] == "deploy_key" {
			rec.Set("title", km.Value("title"))
			rec.Set("read_only", km.Value("read_only"))
		} else {
			rec.Set("events", km.Value("events"))
			rec.Set("active", km.Value("active"))
			rec.Set("target", hookHost(textOf(rundoc.MapOr(km.Value("config")).Value("url"))))
		}
		items.Set(full+"#"+pyvalue.Str(id), rec)
	}
	return nil
}

// hookHost is where a webhook delivers: host[:port] of its URL, WITHOUT the user information a URL may carry
// (https://user:password@host/...): that is a credential and never leaves the shipper (EVENTS-D2).
func hookHost(u string) string {
	i := strings.Index(u, "//")
	if i < 0 || i > 0 && !strings.HasSuffix(u[:i], ":") {
		return ""
	}
	rest := u[i+2:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	return rest
}

func (g *ghRun) installations(ctx context.Context) error {
	ans, err := g.api.get(ctx, "/user/installations", true)
	st, body, _ := ans.status, ans.body, ans.link
	if err != nil {
		return err
	}
	if st != 200 {
		g.unsup.Set("/user/installations", int64(st))
		return nil
	}
	list, err := getOr(body, "installations", []any{})
	if err != nil {
		return err
	}
	items, err := iterate(list)
	if err != nil {
		return err
	}
	out := pyvalue.NewMap()
	for _, i := range items {
		id, err := item(i, "id")
		if err != nil {
			return err
		}
		im := rundoc.MapOr(i)
		rec := pyvalue.NewMap()
		rec.Set("id", id)
		rec.Set("app_slug", im.Value("app_slug"))
		rec.Set("created_at", im.Value("created_at"))
		out.Set(pyvalue.Str(id), rec)
	}
	g.snap.Set("app_installation", out)
	return nil
}
