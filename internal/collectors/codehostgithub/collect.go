// Package codehostgithub is the codehost-github collector (collectors/codehost-github): repository and supply-chain
// posture through the GitHub REST API, READ-ONLY (GET only, no redirect to another origin, page links followed on the
// configured server only). The token comes from a 0600 file (token_file) or a named environment variable (token_env),
// never from a command line; secret-scanning alerts are reduced to counts and type names as they are read, so an
// alert's secret value is never kept. The local gh accounts (`gh auth status`: names and token scopes) are assessed
// when gh is installed.
package codehostgithub

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/codehost"
	"github.com/MIERAI/security-platform/internal/collectors/credential"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Version is the collector's version (collectors/codehost-github/VERSION; TestVersionMatchesTree keeps them equal).
const Version = "0.2.0"

// Name is the collector's name.
const Name = "codehost-github"

const (
	defaultAPI = "https://api.github.com"
	timeout    = 60 * time.Second
)

// Main is `sp codehost-github collect`.
func Main(ctx context.Context, env *rundoc.Env, args []string, stdout io.Writer) int {
	return rundoc.Main(ctx, &rundoc.Collector{Name: Name, Version: Version, Collect: collect}, args, env, stdout)
}

// collect is one run (collector protocol); the caller writes the document.
func collect(ctx context.Context, run *rundoc.Run, env *rundoc.Env) error {
	return collectWith(ctx, run, env, deps{status: ghStatus})
}

// deps are what a run reaches outside the process: gh, and the HTTP transport (tests replace both).
type deps struct {
	status    func(context.Context) (string, bool)
	transport http.RoundTripper
}

func collectWith(ctx context.Context, run *rundoc.Run, env *rundoc.Env, d deps) error {
	c := &collector{runDir: run.Dir, run: run, doc: run.Doc, env: env, deps: d, now: env.Clock()()}
	if err := c.localAccounts(ctx); err != nil {
		return err
	}
	for _, v := range rundoc.List(run.Instance.Value("codehost")) {
		ch, ok := v.(*pyvalue.Map)
		if !ok || rundoc.Text(ch.Value("type")) != "github" {
			continue // another code host: its own collector covers it
		}
		if err := c.owner(ctx, ch); err != nil {
			return err
		}
	}
	return nil
}

type collector struct {
	runDir string // SP_RUN_DIR: the evidence goes under it
	doc    *rundoc.Document
	run    *rundoc.Run
	env    *rundoc.Env
	deps   deps
	now    time.Time
}

// riskyScopes are classic OAuth scopes that let a stolen local token do lasting damage.
func riskyScopes() []string {
	return []string{"delete_repo", "admin:org", "admin:public_key", "admin:repo_hook", "workflow", "write:packages",
		"admin:enterprise"}
}

func (c *collector) localAccounts(ctx context.Context) error {
	text, ok := c.deps.status(ctx)
	accounts := []Account{}
	if ok {
		accounts = ParseAuthStatus(text)
	}
	values := make([]any, len(accounts))
	for i := range accounts {
		values[i] = accounts[i].value()
	}
	ev, err := c.doc.Raw(c.runDir, "gh-auth.json", rundoc.JSON(values))
	if err != nil {
		return err
	}
	for i := range accounts {
		a := &accounts[i]
		asset := "identity:github/" + a.Account + "@local-gh"
		c.doc.OK(asset, "")
		var risky []string
		for _, s := range a.Scopes {
			if contains(riskyScopes(), s) {
				risky = append(risky, s)
			}
		}
		if contains(a.Scopes, "repo") {
			risky = append(risky, "repo(full)")
		}
		if len(risky) > 0 {
			c.doc.AddFinding(&rundoc.Finding{Layer: "identity", Asset: asset, Check: "github.token_broad_scopes",
				Title: "local gh token for " + a.Account + " has broad scopes: " + strings.Join(risky, ", ") +
					" (classic OAuth token, no expiry)", Severity: "medium", Evidence: ev, NeedsHuman: true,
				Remediation: "use fine-grained, repo-scoped, expiring tokens for automation; keep this one for interactive use only"})

		}
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// token is the API token of a codehost entry: token_file (0600) or token_env; "" with the gap reason otherwise.
func (c *collector) token(ch *pyvalue.Map) (tok, problem string) {
	if tf := rundoc.Text(ch.Value("token_file")); tf != "" {
		t, err := credential.File(rundoc.ExpandUser(tf, c.env.Home()))
		if err != nil {
			return "", "token_file: " + err.Error()
		}
		return t, ""
	}
	if name := rundoc.Text(ch.Value("token_env")); name != "" {
		t, err := credential.Env(c.env.Getenv, name)
		if err != nil {
			return "", "token_env: " + err.Error()
		}
		return t, ""
	}
	return "", "no token_file or token_env configured (the Go implementation reads the API token from a 0600 file or a " +
		"named environment variable; it does not run gh auth token)"
}

func (c *collector) owner(ctx context.Context, ch *pyvalue.Map) error {
	owner := pyvalue.Str(ch.Value("owner"))
	scope := "codehost:github/" + owner
	tok, problem := c.token(ch)
	if problem != "" {
		c.doc.Gap(scope, problem, nil)
		return nil
	}
	api, err := codehost.New(codehost.Options{Base: rundoc.StrOr(ch.Value("api"), defaultAPI), Timeout: timeout,
		Transport: c.deps.transport, Header: http.Header{"Accept": {"application/vnd.github+json"},
			"Authorization": {"Bearer " + tok}, "User-Agent": {"security-platform-" + Name + "/" + Version}}})
	if err != nil {
		c.doc.Gap(scope, err.Error(), nil)
		return nil
	}
	o := &ownerScan{c: c, api: api, owner: owner}
	repos, err := o.list(ctx, "/users/"+codehost.Quote(owner)+"/repos?per_page=100&type=owner")
	if err != nil {
		c.doc.Gap(scope, rundoc.Cut(err.Error(), 200), nil)
		return nil
	}
	mine, err := o.list(ctx, "/user/repos?per_page=100&affiliation=owner")
	if err != nil {
		mine = nil // the token's own private repositories: optional, as in the reference
	}
	return o.scan(ctx, append(repos, mine...))
}
