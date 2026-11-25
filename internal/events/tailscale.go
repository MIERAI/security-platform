package events

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// notSlug is what an unknown record's event name keeps. Never written after initialisation.
var notSlug = regexp.MustCompile(`[^a-z0-9]+`)

const defaultTailscaleAPI = "https://api.tailscale.com"

func upperOf(m *pyvalue.Map, key string) string {
	return strings.ToUpper(textOf(m.Value(key)))
}

// mapRecord is ship.py TailscaleAuditSource.map: a configuration-log record -> an event name.
func mapRecord(r *pyvalue.Map) (string, error) {
	t := rundoc.Map(r.Value("target"))
	tt, prop := upperOf(t, "type"), upperOf(t, "property")
	act := strings.ToUpper(textOf(or(r.Value("type"), r.Value("action"), "")))
	nv := r.Value("new")
	newText, err := dumps(nv, defaultJSON())
	if err != nil {
		return "", pyErr("TypeError", "Object of type "+pyvalue.TypeName(nv)+" is not JSON serializable")
	}
	if tt == "NODE" {
		if ev := nodeEvent(act, prop, nv, newText); ev != "" {
			return ev, nil
		}
	}
	if ev := otherEvent(tt, act, prop); ev != "" {
		return ev, nil
	}
	slug := strings.Trim(notSlug.ReplaceAllString(strings.ToLower(tt+"_"+act), "_"), "_")
	if slug == "" {
		return "other", nil
	}
	return slug, nil
}

// tailscaleToken is ship.py TailscaleAuditSource.token: an OAuth client (secret in a 0600 file) exchanged for a
// short-lived token, else an API access token from a 0600 file.
func (s *source) tailscaleToken(ctx context.Context, api string) (string, error) {
	if f := s.cfg.Value("oauth_client_secret_file"); pyvalue.Truthy(f) {
		id, ok := s.cfg.Get("oauth_client_id")
		if !ok {
			return "", keyError("oauth_client_id")
		}
		secret, err := readSecret(pyvalue.Str(f), s.d.home)
		if err != nil {
			return "", err
		}
		tokenURL := api + "/api/v2/oauth/token"
		form := "client_id=" + url.QueryEscape(pyvalue.Str(id)) + "&client_secret=" + url.QueryEscape(secret)
		body, err := postForm(ctx, s.d.client(tokenURL), tokenURL, form)
		if err != nil {
			return "", err
		}
		tok, err := item(body, "access_token")
		if err != nil {
			return "", err
		}
		return pyvalue.Str(tok), nil
	}
	f, ok := s.cfg.Get("token_file")
	if !ok {
		return "", keyError("token_file")
	}
	return readSecret(pyvalue.Str(f), s.d.home)
}

// tailscale reads the configuration audit log since the cursor (overlapping 5 minutes, de-duplicated by record id).
func (s *source) tailscale(ctx context.Context) ([]*event, *pyvalue.Map, error) {
	cursor, hasCursor := pyvalue.ToFloat64(s.state.Value("cursor"))
	start := cursor
	if !hasCursor {
		look, err := parseDur(s.getOr("lookback", "1h"))
		if err != nil {
			return nil, nil, err
		}
		start = s.now - look
	}
	api := pyvalue.Str(s.getOr("api", defaultTailscaleAPI))
	token, err := s.tailscaleToken(ctx, api)
	if err != nil {
		return nil, nil, err
	}
	c := &apiClient{base: strings.TrimRight(api, "/"), token: token, agent: "security-platform-events/" + Version,
		cache: pyvalue.NewMap(), http: s.d.client()}
	q := "start=" + url.QueryEscape(fmtUTC(start)) + "&end=" + url.QueryEscape(fmtUTC(s.now))
	tailnet := pyvalue.Str(s.getOr("tailnet", "-"))
	ans, err := c.get(ctx, "/api/v2/tailnet/"+tailnet+"/logging/configuration?"+q, false)
	st, body, _ := ans.status, ans.body, ans.link
	if err != nil {
		return nil, nil, err
	}
	if st != 200 {
		return nil, nil, pyErr("RuntimeError", fmt.Sprintf("configuration log: HTTP %d", st))
	}
	evs, ids, err := s.auditRecords(body)
	if err != nil {
		return nil, nil, err
	}
	next := s.state.Copy()
	next.Set("cursor", s.now-300)
	all, err := sortedIDs(unionIDs(ids, rundoc.List(s.state.Value("edge"))))
	if err != nil {
		return nil, nil, err
	}
	next.Set("edge", tail(all, 1000))
	if s.first {
		evs = nil // baseline: history before the first run is not "new"
	}
	return evs, next, nil
}

func (s *source) auditRecords(body any) ([]*event, []any, error) {
	logs, err := getOr(or(body, pyvalue.NewMap()), "logs", []any{})
	if err != nil {
		return nil, nil, err
	}
	records, err := iterate(logs)
	if err != nil {
		return nil, nil, err
	}
	seen := stringSet(s.state.Value("edge"))
	var evs []*event
	var ids []any
	for _, x := range records {
		e, id, err := s.auditRecord(x, seen)
		if err != nil {
			return nil, nil, err
		}
		if e != nil {
			evs = append(evs, e)
			ids = append(ids, id)
		}
	}
	return evs, ids, nil
}

func (s *source) auditRecord(x any, seen map[string]bool) (*event, string, error) {
	r, ok := x.(*pyvalue.Map)
	if !ok {
		return nil, "", pyErr("AttributeError", "'"+pyvalue.TypeName(x)+"' object has no attribute 'get'")
	}
	target, err := dumps(r.Value("target"), sortedJSON())
	if err != nil {
		return nil, "", pyErr("TypeError", err.Error())
	}
	rid := pyvalue.Str(r.GetOr("eventGroupID", "")) + "|" + target
	ts, ok, err := isoTS(r.Value("eventTime"), s.d.loc)
	if err != nil {
		return nil, "", err
	}
	if !ok || ts == 0 {
		ts = s.now
	}
	if seen[rid] {
		return nil, "", nil
	}
	a := rundoc.Map(or(r.Value("actor"), pyvalue.NewMap()))
	rec := pyvalue.NewMap()
	for _, k := range []string{"eventTime", "origin", "type", "target", "old", "new", "eventGroupID"} {
		rec.Set(k, r.Value(k))
	}
	rec.Set("actor", or(a.Value("loginName"), a.Value("displayName"), a.Value("id")))
	name, err := mapRecord(r)
	if err != nil {
		return nil, "", err
	}
	line, err := dumps(rec, lineJSON())
	if err != nil {
		return nil, "", pyErr("TypeError", err.Error())
	}
	meta := pyvalue.NewMap()
	meta.Set("event", name)
	meta.Set("actor", or(rec.Value("actor"), ""))
	return &event{ts: ts, line: line, meta: meta, id: rid}, rid, nil
}

// nodeEvent is the event of a NODE record ("" when none of the node rules applies).
func nodeEvent(act, prop string, nv any, newText string) string {
	switch {
	case act == "CREATE":
		return "node_added"
	case keyExpiryDisabled(prop, nv):
		return "node_key_expiry_disabled"
	case strings.Contains(prop, "ROUTE") || strings.Contains(prop, "EXIT"):
		if strings.Contains(newText, "0.0.0.0/0") || strings.Contains(newText, "::/0") || strings.Contains(prop, "EXIT") {
			return "exit_node_enabled"
		}
		return "subnet_routes_changed"
	}
	return ""
}

// otherEvent is the event of a policy, key or user record ("" when none applies).
func otherEvent(tt, act, prop string) string {
	switch {
	case slices.Contains([]string{"ACL", "POLICY", "POLICY_FILE"}, tt) || prop == "ACL" || prop == "POLICY":
		return "policy_changed"
	case slices.Contains([]string{"API_KEY", "AUTH_KEY", "KEY"}, tt) && act == "CREATE":
		return "auth_key_created"
	case tt == "USER" && act == "CREATE":
		return "user_added"
	case tt == "USER" && strings.Contains(prop, "ROLE"):
		return "user_role_changed"
	}
	return ""
}

// keyExpiryDisabled: a KEY_EXPIRY property set so that the node key never expires (…_DISABLED = true, or the
// expiry itself switched off).
func keyExpiryDisabled(prop string, nv any) bool {
	if !strings.Contains(prop, "KEY_EXPIRY") {
		return false
	}
	if strings.Contains(prop, "DISABLED") {
		return pyvalue.Equal(nv, true) || nv == "true"
	}
	return pyvalue.Equal(nv, false) || nv == "false" || nv == "disabled"
}
