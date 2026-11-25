package identity

import (
	"context"

	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
)

// permOrder ranks repository permissions; the highest granted one is the collaborator's permission.
func permRank(p string) int {
	for i, x := range []string{"pull", "triage", "push", "maintain", "admin"} {
		if x == p {
			return i
		}
	}
	return -1
}

// repos reads the repositories the account owns under owner: collaborators, deploy keys, and for public ones the
// fork-PR approval policy. A permission name outside the known ones fails the provider, as in the Python adapter.
func (p *github) repos(ctx context.Context, a *ghAccount, owner string, s *snapshot) error {
	ans := a.api.getAll(ctx, "/user/repos?per_page=100&affiliation=owner")
	if ans.err != "" || ans.data == nil {
		reason := ans.err
		if reason == "" {
			reason = "None"
		}
		s.gap("repos:github/"+owner, reason)
		return nil
	}
	listingGap(s, "repos:github/"+owner, ans)
	for _, r := range list(ans.data) {
		if pyStr(get(get(r, "owner"), "login")) != owner || truthy(get(r, "archived")) || truthy(get(r, "disabled")) {
			continue
		}
		if err := p.repo(ctx, a, r, s); err != nil {
			return err
		}
	}
	return nil
}

func (p *github) repo(ctx context.Context, a *ghAccount, r pyjson.Value, s *snapshot) error {
	full := pyStr(get(r, "full_name"))
	res := "repo:github/" + full
	collab := a.api.getAll(ctx, "/repos/"+full+"/collaborators?affiliation=direct&per_page=100")
	if collab.err != "" || collab.data == nil {
		s.gap(res+"/collaborators", orNone(collab.err))
	} else {
		listingGap(s, res+"/collaborators", collab)
		s.cover(res + "/collaborators")
		for _, c := range list(collab.data) {
			perm, err := permission(get(c, "permissions"))
			if err != nil {
				return err
			}
			s.grants = append(s.grants, object("provider", "github", "resource", res, "principal", get(c, "login"),
				"kind", "collaborator", "permission", perm, "read_only", perm == "pull" || perm == "triage"))
		}
	}
	keys := a.api.getAll(ctx, "/repos/"+full+"/keys")
	listingGap(s, res+"/deploy-key", keys)
	for _, k := range list(keys.data) {
		perm := "write"
		if truthy(get(k, "read_only")) {
			perm = "read"
		}
		s.grants = append(s.grants, object("provider", "github", "resource", res,
			"principal", "deploy-key/"+pyStr(get(k, "title")), "kind", "deploy_key", "permission", perm,
			"read_only", get(k, "read_only"), "created_at", get(k, "created_at"), "last_used", get(k, "last_used")))
	}
	if pyStr(get(r, "visibility")) == "public" {
		ap := a.api.get(ctx, "/repos/"+full+"/actions/permissions/fork-pr-contributor-approval")
		if ap.data == nil {
			s.gap(res+"/actions", orNone(ap.err), "identity.fork_pr_approval_weak")
		} else {
			s.policies = append(s.policies, object("provider", "github", "resource", res, "name", "fork_pr_approval",
				"value", get(ap.data, "approval_policy"), "public", true))
		}
	}
	return nil
}

func orNone(reason string) string {
	if reason == "" {
		return "None"
	}
	return reason
}

// permission is the highest permission set to a true value ("pull" when none is).
func permission(perms pyjson.Value) (string, error) {
	best, rank := "pull", 0
	o, ok := perms.(*pyjson.Object)
	if !ok || o == nil {
		return best, nil
	}
	found := false
	for _, k := range o.Keys() {
		v, _ := o.Get(k)
		if !truthy(v) {
			continue
		}
		r := permRank(k)
		if r < 0 {
			return "", providerError("ValueError: %s is not in list", reprString(k))
		}
		if !found || r > rank {
			best, rank, found = k, r, true
		}
	}
	return best, nil
}
