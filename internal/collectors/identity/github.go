package identity

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const defaultGitHubAPI = "https://api.github.com"

// errProvider marks a provider-level failure: the provider is a gap ("identity-provider:<type>") with this reason.
var errProvider = errors.New("provider failed")

func providerError(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{errProvider}, args...)...)
}

// github is the code-host provider (adapters/identity.py: GitHub): the accounts' own 2FA and tokens, the
// organisations in scope (2FA policy, members, outside collaborators, members without 2FA), the repositories of
// repos_owner (collaborators, deploy keys, the fork-PR approval policy). Read-only GET requests only.
type github struct {
	cfg   *pyvalue.Map
	cache string
	r     *runtime
}

// ghAccount is one configured account and the client that reads with its token.
type ghAccount struct {
	user string
	api  *ghAPI
	cred *pyjson.Object // the token's metadata record (no value)
}

func (p *github) collect(ctx context.Context) (*snapshot, error) {
	s := &snapshot{}
	base, err := apiBase(rundoc.Str(p.cfg.GetOr("api_url", defaultGitHubAPI)))
	if err != nil {
		return nil, providerError("%v", err)
	}
	orgsSeen, reposDone := map[string]bool{}, false
	for _, a := range rundoc.List(p.cfg.Value("accounts")) {
		am := rundoc.Map(a)
		if !am.Has("gh_user") {
			return nil, providerError("KeyError: 'gh_user'")
		}
		acct, ok, err := p.account(ctx, am, base, s)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		p.orgs(ctx, acct, orgsSeen, s)
		owner := rundoc.Str(p.cfg.Value("repos_owner"))
		if owner != "" && !reposDone && acct.user == rundoc.Str(p.cfg.GetOr("repos_via", acct.user)) {
			reposDone = true
			if err := p.repos(ctx, acct, owner, s); err != nil {
				return nil, err
			}
		}
	}
	return s, nil
}

// account reads /user and records the account, its 2FA state and its token's metadata.
func (p *github) account(ctx context.Context, am *pyvalue.Map, base *url.URL, s *snapshot) (*ghAccount, bool, error) {
	user := rundoc.Str(am.Value("gh_user"))
	tok, cred, err := p.r.token(ctx, am, user)
	if err != nil {
		s.gap("identity:github/"+user, err.Error())
		return nil, false, nil
	}
	api := &ghAPI{base: base, token: tok, client: p.r.client, agent: "security-platform-identity/" + Version}
	if p.cache != "" {
		api.cache = filepath.Join(p.cache, user)
	}
	me := api.get(ctx, "/user")
	if me.data == nil {
		reason := me.err
		if reason == "" {
			reason = "no /user"
		}
		s.gap("identity:github/"+user, reason)
		return nil, false, nil
	}
	if !has(me.data, "login") {
		return nil, false, providerError("KeyError: 'login'")
	}
	s.cover("identity:github/" + user)
	mfa := get(me.data, "two_factor_authentication")
	kind := "human"
	if pyStr(get(me.data, "type")) == "Bot" {
		kind = "bot"
	}
	s.accounts = append(s.accounts, object("provider", "github", "id", get(me.data, "login"), "kind", kind, "mfa", mfa,
		"mfa_methods", nil, "admin", nil, "created_at", get(me.data, "created_at"), "last_active", nil))
	if isNone(mfa) {
		s.gap("identity-mfa:github/"+user,
			"the API does not tell 2FA status to this token (needs the `user` scope): attest instead")
	} else {
		s.cover("identity-mfa:github/" + user)
	}
	cred.Set("kind", tokenKind(tok))
	cred.Set("scopes", strList(splitScopes(me.headers["x-oauth-scopes"])))
	cred.Set("expires_at", headerOrNone(me.headers, "github-authentication-token-expiration"))
	s.credentials = append(s.credentials, cred)
	return &ghAccount{user: user, api: api, cred: cred}, true, nil
}

func headerOrNone(h map[string]string, k string) pyjson.Value {
	if v, ok := h[k]; ok {
		return v
	}
	return nil
}

func splitScopes(h string) []string {
	out := []string{}
	for _, x := range strings.Split(h, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// tokenKind is the kind of a code-host token by its prefix (the value itself is never kept).
func tokenKind(tok string) string {
	switch {
	case strings.HasPrefix(tok, "gho_"), strings.HasPrefix(tok, "ghu_"):
		return "oauth_token"
	case strings.HasPrefix(tok, "ghp_"):
		return "pat_classic"
	case strings.HasPrefix(tok, "github_pat_"):
		return "pat_fine_grained"
	default:
		return "token"
	}
}

// orgs reads the account's organisations that are in scope (`orgs:`; others are never read).
func (p *github) orgs(ctx context.Context, a *ghAccount, seen map[string]bool, s *snapshot) {
	ans := a.api.getAll(ctx, "/user/orgs")
	if ans.err != "" {
		s.gap("orgs:github/"+a.user, ans.err)
		return
	}
	scope, scoped := p.cfg.Get("orgs")
	scoped = scoped && scope != nil
	allowed := map[string]bool{}
	for _, o := range rundoc.Strings(scope) {
		allowed[o] = true
	}
	for _, o := range list(ans.data) {
		name := pyStr(get(o, "login"))
		if seen[name] || scoped && !allowed[name] {
			continue
		}
		seen[name] = true
		p.org(ctx, a, name, s)
	}
}

func (p *github) org(ctx context.Context, a *ghAccount, name string, s *snapshot) {
	asset := "org:github/" + name
	od := a.api.get(ctx, "/orgs/"+name)
	if od.data == nil {
		s.gap(asset, od.err)
		return
	}
	outside := a.api.getAll(ctx, "/orgs/"+name+"/outside_collaborators?per_page=100")
	members := a.api.getAll(ctx, "/orgs/"+name+"/members?per_page=100")
	s.orgs = append(s.orgs, object("provider", "github", "id", name,
		"mfa_required", get(od.data, "two_factor_requirement_enabled"),
		"members", countOrNone(members), "outside_collaborators", countOrNone(outside)))
	s.cover(asset)
	listingGap(s, asset+"/outside_collaborators", outside)
	listingGap(s, asset+"/members", members)
	for _, m := range list(members.data) {
		s.grants = append(s.grants, object("provider", "github", "resource", asset, "principal", get(m, "login"),
			"kind", "member", "permission", "member", "read_only", nil))
	}
	p.members2FA(ctx, a, name, s)
}

func countOrNone(a ghAnswer) pyjson.Value {
	if a.err != "" || a.data == nil {
		return nil
	}
	return int64(len(list(a.data)))
}

// listingGap records a listing that failed or was cut at maxPages.
func listingGap(s *snapshot, asset string, a ghAnswer) {
	switch {
	case a.err != "":
		s.gap(asset, a.err)
	case a.partial:
		s.gap(asset, fmt.Sprintf("listing longer than %d pages: the rest was not read", maxPages))
	}
}

// members2FA reads the organisation's members without 2FA (owners only); they become accounts with mfa false.
func (p *github) members2FA(ctx context.Context, a *ghAccount, org string, s *snapshot) {
	ans := a.api.getAll(ctx, "/orgs/"+org+"/members?filter=2fa_disabled&per_page=100")
	if ans.err != "" || ans.partial {
		listingGap(s, "org:github/"+org+"/members-2fa", ans)
		return
	}
	for _, m := range list(ans.data) {
		id := get(m, "login")
		if acct := findAccount(s, pyStr(id)); acct != nil {
			if isNone(get(acct, "mfa")) {
				acct.Set("mfa", false)
			}
			continue
		}
		s.accounts = append(s.accounts, object("provider", "github", "id", id, "kind", "human", "mfa", false,
			"mfa_methods", nil, "admin", nil, "created_at", nil, "last_active", nil))
	}
}

func findAccount(s *snapshot, id string) *pyjson.Object {
	for _, a := range s.accounts {
		if pyStr(get(a, "provider")) == "github" && pyStr(get(a, "id")) == id {
			return a
		}
	}
	return nil
}

// fileMeta is a token file's age (its modification time) as created_at.
func fileMeta(path string) pyjson.Value {
	fi, err := os.Stat(path)
	if err != nil {
		return nil
	}
	return iso(float64(fi.ModTime().Unix()))
}
