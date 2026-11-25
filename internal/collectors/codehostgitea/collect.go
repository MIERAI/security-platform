// Package codehostgitea is the codehost-gitea collector (collectors/codehost-gitea): repository posture on a Gitea
// or Forgejo server through its REST API, READ-ONLY (GET only; the token, from a 0600 file, goes to the configured
// server and nowhere else: a redirect to another origin is not followed).
package codehostgitea

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/codehost"
	"github.com/MIERAI/security-platform/internal/collectors/credential"
	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// Version is the collector's version (collectors/codehost-gitea/VERSION; TestVersionMatchesTree keeps them equal).
const Version = "0.2.0"

// Name is the collector's name.
const Name = "codehost-gitea"

const (
	pageSize = 50
	timeout  = 30 * time.Second
)

// Main is `sp codehost-gitea collect`.
func Main(ctx context.Context, env rundoc.Env, args []string) int {
	return rundoc.Main(ctx, env, args, Name, Collect)
}

// Collect is one run (collector protocol).
func Collect(ctx context.Context, env rundoc.Env) error {
	run, err := rundoc.Start(env, Name, Version)
	if err != nil {
		return err
	}
	c := &collector{doc: run.Doc, home: env.Home()}
	for _, v := range rundoc.List(run.Instance.Value("codehost")) {
		ch, ok := v.(*pyvalue.Map)
		if !ok {
			continue
		}
		if t := rundoc.Str(ch.Value("type")); t == "gitea" || t == "forgejo" {
			if err := c.scan(ctx, ch); err != nil {
				return err
			}
		}
	}
	return run.Finish()
}

type collector struct {
	doc  *rundoc.Document
	home string
}

// tokenError is the gap reason of an unusable token file, worded as the reference words it.
func tokenError(configured, expanded string, err error) string {
	switch {
	case errors.Is(err, credential.ErrPermissive):
		return "PermissionError: " + configured + " must be mode 0600"
	case errors.Is(err, fs.ErrNotExist):
		return "FileNotFoundError: [Errno 2] No such file or directory: '" + expanded + "'"
	default:
		return "OSError: " + err.Error()
	}
}

func (c *collector) client(ch *pyvalue.Map) (*codehost.Client, string) {
	header := http.Header{"Accept": {"application/json"}, "User-Agent": {"security-platform-" + Name + "/" + Version}}
	if tf := rundoc.Str(ch.Value("token_file")); tf != "" {
		p := rundoc.ExpandUser(tf, c.home)
		tok, err := credential.File(p)
		if err != nil {
			return nil, tokenError(tf, p, err)
		}
		header.Set("Authorization", "token "+tok)
	}
	ca := rundoc.Str(ch.Value("ca_file"))
	if ca != "" {
		ca = rundoc.ExpandUser(ca, c.home)
	}
	api, err := codehost.New(codehost.Options{Base: strings.TrimRight(rundoc.Str(ch.Value("url")), "/") + "/api/v1",
		Header: header, CAFile: ca, Timeout: timeout})
	if err != nil {
		return nil, "OSError: " + err.Error()
	}
	return api, ""
}

// errText is the reference's error text: "HTTP <status>" for an answer, "<kind>: <detail>" otherwise.
func errText(err error) string {
	if s := codehost.Status(err); s != 0 {
		return "HTTP " + strconv.Itoa(s)
	}
	return "URLError: " + rundoc.Cut(err.Error(), 120)
}

// list reads a paginated listing as the server pages it (limit=50; Link, X-Total-Count).
func list(ctx context.Context, api *codehost.Client, path string) ([]any, string) {
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	at := func(page int) string {
		return path + sep + "limit=" + strconv.Itoa(pageSize) + "&page=" + strconv.Itoa(page)
	}
	items, err := api.GetAll(ctx, at(1), pageSize, at)
	if err != nil {
		return nil, errText(err)
	}
	if items == nil {
		items = []any{}
	}
	return items, ""
}

func (c *collector) scan(ctx context.Context, ch *pyvalue.Map) error {
	kind, owner := rundoc.Str(ch.Value("type")), pyvalue.Str(ch.Value("owner"))
	if !ch.Has("url") || !ch.Has("owner") {
		return fmt.Errorf("%w: codehost %s entry without url or owner", rundoc.ErrUsage, kind)
	}
	scope := "codehost:" + kind + "/" + owner
	api, problem := c.client(ch)
	if problem != "" {
		c.doc.Gap(scope, problem)
		return nil
	}
	repos, errS := list(ctx, api, "/orgs/"+codehost.Quote(owner)+"/repos")
	if repos == nil {
		repos, errS = list(ctx, api, "/users/"+codehost.Quote(owner)+"/repos")
	}
	if repos == nil {
		c.doc.Gap(scope, "cannot list repositories: "+errS)
		return nil
	}
	s := &ownerScan{c: c, api: api, kind: kind, host: hostOf(rundoc.Str(ch.Value("url"))), summary: map[string]any{}}
	includePrivate := ch.Value("include_private") != false
	sort.SliceStable(repos, func(i, j int) bool {
		return rundoc.Str(rundoc.Get(repos[i], "full_name")) < rundoc.Str(rundoc.Get(repos[j], "full_name"))
	})
	for _, v := range repos {
		r := rundoc.Map(v)
		if pyvalue.Truthy(r.Value("archived")) || (pyvalue.Truthy(r.Value("private")) && !includePrivate) {
			continue
		}
		if err := s.repo(ctx, r); err != nil {
			return err
		}
	}
	if _, err := c.doc.Raw("repos.json", s.summary); err != nil {
		return err
	}
	c.doc.Metric("security_repos_public_without_protection", float64(s.publicUnprotected),
		"Public repos whose default branch has no protection/ruleset", [2]string{"owner", owner})
	c.doc.Metric("security_repos_total", float64(len(s.summary)), "Repos checked", [2]string{"owner", owner})
	return nil
}

// hostOf is urllib.parse.urlparse(u).hostname or "gitea".
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "gitea"
	}
	return strings.ToLower(u.Hostname())
}
