// Package cloud is the cloud adapter: cloud accounts (AWS accounts, GCP projects, Azure subscriptions) reached with
// SHORT-LIVED, READ-ONLY credentials only, through the providers' official SDKs (aws-sdk-go-v2,
// golang.org/x/oauth2/google + google.golang.org/api, the Azure SDK for Go). It is the Go implementation of
// adapters/cloud.py with the same configuration keys, the same refusals and the same coverage-gap reasons
// (docs/cloud.md). Credentials live in memory only and are never logged, printed or put in an error.
package cloud

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

// Timing of credentials and calls.
const (
	RefreshMargin  = 5 * time.Minute  // cached credentials are renewed this long before they expire
	SessionSeconds = 3600             // default lifetime of the platform's own session/token
	callTimeout    = 30 * time.Second // one provider API call
)

// Account is one entry of the instance's `cloud.accounts` (or a `discovery: gcp` entry): loosely typed, as in the
// instance config. Numbers are json.Number (dyn.Decode).
type Account map[string]any

// Str is `cfg.get(key) or ""` as text.
func (a Account) Str(key string) string { return dyn.Text(a, key) }

// StrOr is `cfg.get(key) or def`.
func (a Account) StrOr(key, def string) string { return dyn.Or(a.Str(key), def) }

// List is `cfg.get(key) or []` as text values.
func (a Account) List(key string) []string { return dyn.Strings(a[key]) }

// Map is `cfg.get(key) or {}`.
func (a Account) Map(key string) map[string]any { return dyn.Map(a[key]) }

// Has reports whether the key is present (even with an empty value).
func (a Account) Has(key string) bool {
	_, ok := a[key]
	return ok
}

// Bool is `cfg.get(key, def)` judged by Python truthiness.
func (a Account) Bool(key string, def bool) bool {
	v, ok := a[key]
	if !ok {
		return def
	}
	return dyn.Truthy(v)
}

// Int is `int(cfg.get(key, def))` for a whole number (def when absent or not a number).
func (a Account) Int(key string, def int) int {
	var n int
	if _, err := fmt.Sscan(dyn.Str(a[key]), &n); err != nil {
		return def
	}
	return n
}

// Deps is everything the adapter reads from its process, injected (docs/go.md: no global state).
type Deps struct {
	Getenv     func(string) string
	Now        func() time.Time
	HTTP       *http.Client // base client for every provider call; nil = a default one with timeouts
	Executable string       // this program (sp): engines call back into it for credentials
	GOOS       string       // runtime.GOOS
}

func (d Deps) now() time.Time {
	if d.Now == nil {
		return time.Now()
	}
	return d.Now()
}

func (d Deps) getenv(k string) string {
	if d.Getenv == nil {
		return ""
	}
	return d.Getenv(k)
}

// home is the user's home directory from the environment (HOME, USERPROFILE on Windows).
func (d Deps) home() string {
	if h := d.getenv("HOME"); h != "" {
		return h
	}
	return d.getenv("USERPROFILE")
}

// ExpandUser is Python's os.path.expanduser for "~" and "~/...".
func ExpandUser(p, home string) string {
	if home == "" || (p != "~" && !strings.HasPrefix(p, "~/") && !strings.HasPrefix(p, `~\`)) {
		return p
	}
	return filepath.Join(home, p[1:])
}

// Identity is the identity the platform runs as (evidence: principal and account; GCP also its source).
type Identity struct {
	Principal string
	Account   string
	Source    string // gcp only: workload_identity | adc
}

// Evidence is the identity as it is written to the evidence file.
func (i Identity) Evidence() map[string]any {
	m := map[string]any{"principal": i.Principal, "account": i.Account}
	if i.Source != "" {
		m["source"] = i.Source
	}
	return m
}

// Permissions is the result of the self-verification: what the identity holds and what of it can write.
type Permissions struct {
	Principal      string
	Method         string
	Grants         []string
	Conditional    []string // gcp: roles granted only under an IAM condition
	HasConditional bool     // gcp reports the conditional list (even when empty)
	WriteCapable   []string
}

// Evidence is the self-check as it is written to the evidence file.
func (p Permissions) Evidence() map[string]any {
	m := map[string]any{"principal": p.Principal, "method": p.Method, "grants": strs(p.Grants),
		"write_capable": strs(p.WriteCapable)}
	if p.HasConditional {
		m["conditional"] = strs(p.Conditional)
	}
	return m
}

func strs(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// EngineArgs tells an engine which accounts to scan and how its credentials were set up.
type EngineArgs struct {
	Profile                   string   // aws: the profile whose credential_process calls back into sp
	Regions                   []string // aws
	Projects                  []string // gcp
	Subscriptions             []string // azure
	GCPSource                 string   // gcp: "adc" when the operator's ADC is the source
	EngineAuth                string   // gcp adc: access_token | impersonate
	ImpersonateServiceAccount string   // gcp adc + engine_auth impersonate
}

// Provider is one cloud account reached with short-lived credentials.
type Provider interface {
	Kind() string    // aws | gcp | azure
	Account() string // account id / project id / subscription id
	Asset() string   // cloud:<kind>/<account>
	Identity(ctx context.Context) (Identity, error)
	Permissions(ctx context.Context) (Permissions, error)
	// EngineEnv is how an external engine authenticates: environment variables without any secret (the engine
	// calls back into sp for tokens) and the arguments it needs. Files go into tmpdir (private, removed by the
	// caller).
	EngineEnv(ctx context.Context, tmpdir string) (map[string]string, EngineArgs, error)
}

// Kinds lists the providers, in the order used in messages.
func Kinds() []string { return []string{"aws", "gcp", "azure"} }

// New returns the provider of one account entry (refusing long-lived keys and incomplete entries).
func New(cfg Account, deps Deps) (Provider, error) {
	switch kind := cfg.Str("provider"); kind {
	case "aws":
		return newAWS(cfg, deps)
	case "gcp":
		return newGCP(cfg, deps)
	case "azure":
		return newAzure(cfg, deps)
	default:
		return nil, failf("provider %s unknown (%s)", pyRepr(cfg["provider"]), strings.Join(Kinds(), ", "))
	}
}

// pyRepr is Python's repr() of a config value in a message ('x' for text, None when absent).
func pyRepr(v any) string {
	if v == nil {
		return "None"
	}
	if s, ok := v.(string); ok {
		return "'" + s + "'"
	}
	return dyn.Str(v)
}

// longLivedKeys are configuration keys that would hold a long-lived credential: refused.
func longLivedKeys() []string {
	return []string{"access_key_id", "secret_access_key", "aws_access_key_id", "aws_secret_access_key",
		"client_secret", "private_key", "service_account_key", "key_file", "password", "certificate_password"}
}

func refuseLongLived(cfg Account) error {
	var bad []string
	for k := range cfg {
		for _, l := range longLivedKeys() {
			if strings.EqualFold(k, l) {
				bad = append(bad, k)
			}
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return failf("long-lived credentials are not accepted (%s): use federation/short-lived roles", strings.Join(bad, ", "))
}

// base holds what every provider has.
type base struct {
	cfg     Account
	deps    Deps
	kind    string
	account string
}

func newBase(cfg Account, deps Deps, kind, idKey string) (base, error) {
	if err := refuseLongLived(cfg); err != nil {
		return base{}, err
	}
	b := base{cfg: cfg, deps: deps, kind: kind, account: cfg.Str(idKey)}
	if b.account == "" {
		return base{}, failf("%s: `%s` missing", kind, idKey)
	}
	return b, nil
}

func (b *base) Kind() string    { return b.kind }
func (b *base) Account() string { return b.account }
func (b *base) Asset() string   { return "cloud:" + b.kind + "/" + b.account }

// sessionSeconds is the configured session lifetime (default one hour).
func (b *base) sessionSeconds() int { return b.cfg.Int("session_seconds", SessionSeconds) }

// identityToken reads the workload's OIDC token fresh and pre-checks it (expiry, audience).
func (b *base) identityToken(ctx context.Context) (string, error) {
	tok, err := ReadIdentityToken(ctx, b.cfg.Map("identity_token"), b.deps)
	if err != nil {
		return "", err
	}
	if _, err := PrecheckToken(tok, b.cfg.Str("audience"), b.deps.now()); err != nil {
		return "", err
	}
	return tok, nil
}

// CleanEnv is the environment an engine starts from: ambient cloud credentials removed, so that only what
// EngineEnv grants is used (an administrator's shell keys must never reach a scan).
func CleanEnv(environ []string) map[string]string {
	drop := map[string]bool{}
	for _, k := range ambientKeys() {
		drop[k] = true
	}
	env := map[string]string{}
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if ok && !drop[k] {
			env[k] = v
		}
	}
	return env
}

func ambientKeys() []string {
	return []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN",
		"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_ROLE_ARN",
		"AWS_WEB_IDENTITY_TOKEN_FILE", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN",
		"CLOUDSDK_AUTH_ACCESS_TOKEN", "AZURE_CLIENT_SECRET", "AZURE_CLIENT_CERTIFICATE_PATH", "AZURE_USERNAME",
		"AZURE_PASSWORD", "AZURE_FEDERATED_TOKEN_FILE", "AZURE_CLIENT_ID", "AZURE_TENANT_ID"}
}
