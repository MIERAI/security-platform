package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/MIERAI/security-platform/internal/collectors/rundoc"
	"github.com/MIERAI/security-platform/internal/ledger/pyjson"
	"github.com/MIERAI/security-platform/internal/pyvalue"
)

const (
	defaultTailscaleAPI = "https://api.tailscale.com/api/v2"
	maxStatus           = 16 << 20
)

// tailscale is the overlay-network provider (adapters/identity.py: Tailscale): with a read-only API key or an OAuth
// client (secret files, mode 0600) the users, devices and ACL; without one, or when the API fails, the local CLI's
// device list (the ACL is then a gap).
type tailscale struct {
	cfg *pyvalue.Map
	r   *runtime
}

// apiError is an API failure, named as the Python adapter names its exception (the gap reason).
type apiError struct{ kind, msg string }

func (e *apiError) Error() string { return e.kind + ": " + e.msg }

func (p *tailscale) collect(ctx context.Context) (*snapshot, error) {
	s := &snapshot{}
	kfCfg := p.cfg.Value("oauth_client_secret_file")
	if !truthy(kfCfg) {
		kfCfg = p.cfg.Value("api_key_file")
	}
	key := ""
	if truthy(kfCfg) {
		key = p.secret(ctx, rundoc.Str(kfCfg), s)
	}
	if key != "" {
		done, err := p.api(ctx, key, s)
		if err != nil {
			return nil, err
		}
		if done {
			return s, nil
		}
		return p.cli(ctx, s)
	}
	if !truthy(kfCfg) {
		s.gap("identity-provider:tailscale", "no read-only API key configured: ACL and users cannot be checked")
	}
	return p.cli(ctx, s)
}

// secret reads the configured secret file and, for an OAuth client, exchanges it for an access token; failures
// are gaps ("" returned).
func (p *tailscale) secret(ctx context.Context, kf string, s *snapshot) string {
	path := rundoc.ExpandUser(kf, p.r.home)
	base := filepath.Base(kf)
	fi, err := os.Stat(path)
	switch {
	case err != nil:
		s.gap("identity-provider:tailscale", base+" missing")
		return ""
	case fi.Mode().Perm()&0o077 != 0 && !windowsPerms():
		s.gap("identity-provider:tailscale", base+" must be mode 0600 (refused)")
		return ""
	}
	data, err := rundoc.ReadLimited(path, maxTokenFile)
	if err != nil {
		s.gap("identity-provider:tailscale", base+" unreadable")
		return ""
	}
	secret := strings.TrimSpace(string(data))
	if !truthy(p.cfg.Value("oauth_client_secret_file")) {
		return secret
	}
	tok, err := p.oauth(ctx, rundoc.Str(p.cfg.Value("oauth_client_id")), secret)
	if err != nil {
		s.gap("identity-provider:tailscale", "OAuth token exchange: "+errKind(err))
		return ""
	}
	return tok
}

func (p *tailscale) base() (*url.URL, error) {
	return apiBase(rundoc.Str(p.cfg.GetOr("api_url", defaultTailscaleAPI)))
}

// oauth exchanges the OAuth client's credentials for a short-lived access token with the client's (read-only)
// scopes. This POST is the only non-GET request the collector sends.
func (p *tailscale) oauth(ctx context.Context, clientID, secret string) (string, error) {
	base, err := p.base()
	if err != nil {
		return "", err
	}
	form := url.Values{"client_id": {clientID}, "client_secret": {secret}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+"/oauth/token", strings.NewReader(form))
	if err != nil {
		return "", &apiError{"ValueError", "request"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	v, err := p.call(ctx, req)
	if err != nil {
		return "", err
	}
	tok, ok := get(v, "access_token").(string)
	if !ok {
		return "", &apiError{"KeyError", "'access_token'"}
	}
	return tok, nil
}

// call sends a request and decodes the JSON answer; errors are apiErrors.
func (p *tailscale) call(ctx context.Context, req *http.Request) (pyjson.Value, error) {
	req.Header.Set("User-Agent", "security-platform-identity/"+Version)
	resp, err := do(ctx, p.r.client, req)
	if err != nil {
		return nil, &apiError{"URLError", "<urlopen error " + rundoc.Cut(errors.Unwrap(err).Error(), 100) + ">"}
	}
	if resp.status/100 != 2 {
		return nil, &apiError{"HTTPError", "HTTP Error " + strconv.Itoa(resp.status) + ": " + resp.reason}
	}
	v, err := pyjson.Decode(resp.body)
	if err != nil {
		return nil, &apiError{"JSONDecodeError", "the answer is not JSON"}
	}
	return v, nil
}

func errKind(err error) string {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.kind
	}
	return "ValueError"
}

func (p *tailscale) get(ctx context.Context, path, key string) (pyjson.Value, error) {
	base, err := p.base()
	if err != nil {
		return nil, &apiError{"ValueError", err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+path, http.NoBody)
	if err != nil {
		return nil, &apiError{"ValueError", "request"}
	}
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	return p.call(ctx, req)
}

// api reads devices, users and the ACL. done is false when the API failed (a gap; the CLI is asked instead).
func (p *tailscale) api(ctx context.Context, key string, s *snapshot) (bool, error) {
	tn := url.PathEscape(rundoc.Str(p.cfg.GetOr("tailnet", "-")))
	var answers [3]pyjson.Value
	for i, path := range []string{"/tailnet/" + tn + "/devices?fields=all", "/tailnet/" + tn + "/users", "/tailnet/" + tn + "/acl"} {
		v, err := p.get(ctx, path, key)
		if err == nil && i < 2 {
			if _, isObj := v.(*pyjson.Object); !isObj {
				err = &apiError{"AttributeError", fmt.Sprintf("'%s' object has no attribute 'get'", pyTypeName(v))}
			}
		}
		if err != nil {
			s.gap("identity-provider:tailscale", "API: "+rundoc.Cut(err.Error(), len(errKind(err))+2+120))
			return false, nil
		}
		answers[i] = v
	}
	if _, isObj := answers[2].(*pyjson.Object); !isObj {
		return false, providerError("AttributeError: '%s' object has no attribute 'get'", pyTypeName(answers[2]))
	}
	s.cover("identity-provider:tailscale")
	for _, u := range list(getOr(answers[1], "users")) {
		role := pyStr(get(u, "role"))
		s.accounts = append(s.accounts, object("provider", "tailscale", "id", get(u, "loginName"), "kind", "human",
			"mfa", nil, "mfa_methods", nil, "admin", role == "owner" || role == "admin",
			"created_at", get(u, "created"), "last_active", get(u, "lastSeen")))
	}
	for _, d := range list(getOr(answers[0], "devices")) {
		disabled := truthy(get(d, "keyExpiryDisabled"))
		var expires pyjson.Value
		notes := ""
		if disabled {
			notes = "key expiry disabled"
		} else {
			expires = get(d, "expires")
		}
		s.credentials = append(s.credentials, object("store", "tailscale", "id", "device/"+pyStr(get(d, "hostname")),
			"kind", "device_key", "location", "tailnet", "scopes", nil, "created_at", get(d, "created"),
			"expires_at", expires, "last_used", get(d, "lastSeen"), "notes", notes))
	}
	s.policies = append(s.policies, object("provider", "tailscale", "resource", "identity-provider:tailscale",
		"name", "acl_allow_all", "value", aclAllowsAll(answers[2]), "public", false))
	return true, nil
}

// getOr is dict.get(key, []) (a present null stays null).
func getOr(v pyjson.Value, key string) pyjson.Value {
	if !has(v, key) {
		return []pyjson.Value{}
	}
	return get(v, key)
}

func pyTypeName(v pyjson.Value) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case string:
		return "str"
	case int64, pyjson.BigInt:
		return "int"
	case float64:
		return "float"
	case []pyjson.Value:
		return "list"
	default:
		return "dict"
	}
}

// aclAllowsAll is true when an ACL rule or grant lets every source reach every destination (the default policy).
func aclAllowsAll(acl pyjson.Value) bool {
	for _, r := range list(orEmpty(get(acl, "acls"))) {
		if pyStr(get(r, "action")) != "accept" || !pyIn("*", orEmpty(get(r, "src"))) {
			continue
		}
		for _, d := range iterStrings(orEmpty(get(r, "dst"))) {
			if strings.HasPrefix(d, "*:") || d == "*" {
				return true
			}
		}
	}
	for _, g := range list(orEmpty(get(acl, "grants"))) {
		if pyIn("*", orEmpty(get(g, "src"))) && pyIn("*", orEmpty(get(g, "dst"))) {
			return true
		}
	}
	return false
}

// orEmpty is `v or []`.
func orEmpty(v pyjson.Value) pyjson.Value {
	if !truthy(v) {
		return []pyjson.Value{}
	}
	return v
}

// cli is the local CLI's view (`tailscale status --json`): peers and their key expiry.
func (p *tailscale) cli(ctx context.Context, s *snapshot) (*snapshot, error) {
	res := rundoc.Exec(ctx, &rundoc.Cmd{Argv: []string{"tailscale", "status", "--json"}, Env: p.r.env.Environ,
		Timeout: toolTimeout, MaxOut: maxStatus})
	st, kind := parseStatus(res)
	if kind != "" {
		s.gap("identity-devices:tailscale", "tailscale CLI: "+kind)
		return s, nil
	}
	if _, isObj := st.(*pyjson.Object); !isObj {
		return nil, providerError("AttributeError: '%s' object has no attribute 'get'", pyTypeName(st))
	}
	s.cover("identity-devices:tailscale")
	peers, _ := orEmptyObject(get(st, "Peer")).(*pyjson.Object)
	if peers == nil {
		return nil, providerError("AttributeError: 'list' object has no attribute 'values'")
	}
	now := iso(float64(p.r.now().Unix()))
	for _, k := range peers.Keys() {
		pv, _ := peers.Get(k)
		last := get(pv, "LastSeen")
		if truthy(get(pv, "Online")) {
			last = now
		}
		notes := ""
		if !truthy(get(pv, "KeyExpiry")) {
			notes = "key expiry disabled"
		}
		s.credentials = append(s.credentials, object("store", "tailscale", "id", "device/"+pyStr(get(pv, "HostName")),
			"kind", "device_key", "location", "tailnet", "scopes", nil, "created_at", get(pv, "Created"),
			"expires_at", get(pv, "KeyExpiry"), "last_used", last, "notes", notes))
	}
	return s, nil
}

// parseStatus decodes the CLI's output; kind names the failure as Python's exception class would.
func parseStatus(res rundoc.Result) (pyjson.Value, string) {
	switch res.RC {
	case rundoc.RCNotFound:
		return nil, "FileNotFoundError"
	case rundoc.RCTimeout:
		return nil, "TimeoutExpired"
	}
	if res.Truncated {
		return nil, "JSONDecodeError"
	}
	v, err := decodeLoose([]byte(res.Stdout))
	if err != nil {
		return nil, "JSONDecodeError"
	}
	return v, ""
}

// decodeLoose is json.loads: surrounding whitespace allowed.
func decodeLoose(data []byte) (pyjson.Value, error) {
	if !json.Valid(data) {
		return nil, errors.New("not JSON")
	}
	return pyjson.Decode(data)
}

// orEmptyObject is `v or {}`.
func orEmptyObject(v pyjson.Value) pyjson.Value {
	if !truthy(v) {
		return pyjson.NewObject()
	}
	return v
}
