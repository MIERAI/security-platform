package codehostgithub

import (
	"context"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/collectors/execadapter"
)

const ghTimeout = 30 * time.Second

// Account is one local gh login as `gh auth status` lists it: names only, never the token (gh prints it masked).
type Account struct {
	Host, Account, Storage string
	Scopes                 []string
	HasScopes, HasActive   bool
	Active                 bool
}

// ghStatus runs `gh auth status` (read-only, no shell) and returns its stdout and stderr; ok is false when gh is not
// installed (there are then no local gh tokens to assess).
func ghStatus(ctx context.Context) (text string, ok bool) {
	ex, err := execadapter.New(nil, nil)
	if err != nil {
		return "", false
	}
	res := ex.Output(ctx, []string{"gh", "auth", "status"}, ghTimeout)
	if res.RC == execadapter.StatusNotFound && res.Out == "" {
		return "", false
	}
	return res.Out + res.Err, true
}

// ParseAuthStatus reads the account list of `gh auth status` as the reference does: a "Logged in to <host> account
// <name> (<storage>)" line starts an account; "- Token scopes: 'a', 'b'" and "- Active account: true|false" belong to
// the last one. Every other line (the masked token among them) is ignored.
func ParseAuthStatus(text string) []Account {
	var out []Account
	for _, raw := range strings.Split(text, "\n") {
		l := strings.TrimSpace(raw)
		cur := len(out) - 1
		switch {
		case strings.Contains(l, "Logged in to") && strings.Contains(l, "account"):
			if a, ok := loginLine(l); ok {
				out = append(out, a)
			}
		case strings.HasPrefix(l, "- Token scopes:") && cur >= 0:
			_, list, _ := strings.Cut(l, ":")
			out[cur].Scopes, out[cur].HasScopes = scopes(list), true
		case strings.HasPrefix(l, "- Active account:") && cur >= 0:
			out[cur].Active, out[cur].HasActive = strings.HasSuffix(l, "true"), true
		}
	}
	return out
}

func loginLine(l string) (Account, bool) {
	_, afterHost, ok1 := strings.Cut(l, "Logged in to ")
	_, afterAcct, ok2 := strings.Cut(l, "account ")
	host, acct := strings.Fields(afterHost), strings.Fields(afterAcct)
	if !ok1 || !ok2 || len(host) == 0 || len(acct) == 0 {
		return Account{}, false // the reference fails on such a line; it carries no account to assess
	}
	parts := strings.Split(l, "(")
	return Account{Host: host[0], Account: acct[0], Storage: strings.TrimRight(parts[len(parts)-1], ")")}, true
}

// scopes is [s.strip(" '") for s in list.split(",")].
func scopes(list string) []string {
	parts := strings.Split(list, ",")
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = strings.Trim(p, " '")
	}
	return out
}

func (a *Account) value() map[string]any {
	m := map[string]any{"host": a.Host, "account": a.Account, "storage": a.Storage}
	if a.HasScopes {
		m["scopes"] = toAny(a.Scopes)
	}
	if a.HasActive {
		m["active"] = a.Active
	}
	return m
}

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
