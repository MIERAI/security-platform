package identity

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

// FuzzGitHubAnswer: any API answer (status, body, Link, rate-limit headers) is data or a gap reason, never a panic,
// and a next page never leaves the API host.
func FuzzGitHubAnswer(f *testing.F) {
	f.Add(200, `[{"login": "a", "permissions": {"admin": true}}]`, `<https://api.example.com/x?page=2>; rel="next"`, "")
	f.Add(403, `{"message": "API rate limit exceeded"}`, "", "0")
	f.Add(200, `{"two_factor_authentication": null}`, `<https://evil.example/x>; rel=next`, "")
	f.Add(304, ``, "", "")
	f.Fuzz(func(t *testing.T, status int, body, link, remaining string) {
		base, _ := url.Parse("https://api.example.com")
		g := &ghAPI{base: base}
		h := http.Header{}
		h.Set("Link", link)
		h.Set("X-RateLimit-Remaining", remaining)
		a := g.answer(&response{status: status, header: h, body: []byte(body)}, "/x", nil, "")
		if next := g.nextPage(a.link); next != "" {
			u, err := url.Parse(base.String() + next)
			if err != nil || u.Host != base.Host {
				t.Fatalf("next page %q leaves the API host", next)
			}
		}
		_, _ = permission(a.data)
	})
}

// FuzzStamp: dates of any provider, read as Python's ts().
func FuzzStamp(f *testing.F) {
	for _, s := range []string{"2026-01-02T03:04:05Z", "2026-1-2", "2026-02-30", " 2026-01-01", "9999-12-31T23:59:60"} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) { _, _ = stamp(s) })
}

// FuzzCertificate: kubeconfig client-certificate-data.
func FuzzCertificate(f *testing.F) {
	if b, err := os.ReadFile(filepath.Join("testdata", "client-cert.b64")); err == nil {
		f.Add(string(b))
	}
	f.Add("LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCg==")
	f.Add("!!!=")
	f.Fuzz(func(_ *testing.T, s string) { _, _ = certNotAfter(s) })
}

// FuzzFnmatch: glob patterns of the instance config.
func FuzzFnmatch(f *testing.F) {
	for _, s := range []string{"*.token", "[!a]x", "[x", "[]]", "[!]-a]", "?\\*"} {
		f.Add(s, "a.token")
	}
	f.Fuzz(func(_ *testing.T, pat, name string) {
		if rx, err := fnmatchRegexp(pat); err == nil {
			_ = matchName(name, pat, rx)
		}
	})
}

// FuzzOverlayJSON: the overlay network's API answers (ACL) and its CLI's status.
func FuzzOverlayJSON(f *testing.F) {
	f.Add(`{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}], "grants": [{"src": "*", "dst": ["*"]}]}`)
	f.Add(`{"Peer": {"k": {"HostName": "h", "KeyExpiry": "2026-01-01T00:00:00Z", "Online": true}}}`)
	f.Add(`[1, null]`)
	f.Fuzz(func(_ *testing.T, s string) {
		v, kind := parseStatus(rundoc.Result{Stdout: s})
		if kind == "" {
			_ = aclAllowsAll(v)
		}
	})
}

// FuzzLocalStores: kubeconfig YAML and docker config JSON files.
func FuzzLocalStores(f *testing.F) {
	f.Add("users:\n- name: a\n  user: {token: x}\n- name: b\n  user: {exec: {command: /bin/aws}}\n")
	f.Add(`{"auths": {"r.example": {"auth": "eA=="}}, "credsStore": "osxkeychain"}`)
	f.Add("users: 3\n")
	f.Fuzz(func(t *testing.T, s string) {
		dir := t.TempDir()
		p := filepath.Join(dir, "config")
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		l := newLocal(pyvalue.NewMap(), dir)
		snap := &snapshot{}
		l.kubeconfig(p, snap)
		l.docker(p, snap)
	})
}
