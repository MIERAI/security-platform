package identity

import "github.com/MIERAI/security-platform/internal/ledger/pyjson"

// gapEntry is a coverage gap a provider reports; checks (may be nil) make it narrow.
type gapEntry struct {
	asset, reason string
	checks        []string
}

// snapshot is what providers and local stores return (adapters/identity.py: Snapshot), records as JSON objects:
//
//	account     {provider, id, kind, mfa: true|false|null, mfa_methods, admin, created_at, last_active}
//	org         {provider, id, mfa_required, members, outside_collaborators}
//	grant       {provider, resource, principal, kind, permission, read_only, created_at?, last_used?}
//	credential  {store, id (a name, never the value), kind, location, scopes, created_at, expires_at, last_used, ...}
//	policy      {provider, resource, name, value, public}
type snapshot struct {
	accounts, orgs, grants, credentials, policies []*pyjson.Object
	gaps                                          []gapEntry
	covered                                       []string
}

func (s *snapshot) gap(asset, reason string, checks ...string) {
	s.gaps = append(s.gaps, gapEntry{asset: asset, reason: reason, checks: checks})
}

func (s *snapshot) cover(asset string) { s.covered = append(s.covered, asset) }

func (s *snapshot) add(o *snapshot) {
	s.accounts = append(s.accounts, o.accounts...)
	s.orgs = append(s.orgs, o.orgs...)
	s.grants = append(s.grants, o.grants...)
	s.credentials = append(s.credentials, o.credentials...)
	s.policies = append(s.policies, o.policies...)
}

func objects(l []*pyjson.Object) []pyjson.Value {
	out := make([]pyjson.Value, len(l))
	for i, o := range l {
		out[i] = o
	}
	return out
}
