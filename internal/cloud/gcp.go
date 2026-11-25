package cloud

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google/externalaccount"
)

const (
	gcpScope     = "https://www.googleapis.com/auth/cloud-platform"
	jwtTokenType = "urn:ietf:params:oauth:token-type:jwt" // #nosec G101 -- a token TYPE name (RFC 8693), not a credential
)

// gcpProvider: a GCP project reached as an audit service account, impersonated (iamcredentials
// generateAccessToken) from either the workload's OIDC token exchanged at Google's STS (workload identity
// federation, golang.org/x/oauth2/google/externalaccount) or the operator's gcloud Application Default Credentials
// (source adc: an authorized_user refresh token, read fresh per acquisition and never kept).
type gcpProvider struct {
	base
	source, engineAuth, audience, sa string
	stsURL, oauthURL, iamcredURL     string
	crmURL                           string
	http                             *http.Client
	cache                            tokenCache
}

func gcpSources() []string     { return []string{"workload_identity", "adc"} }
func gcpEngineAuths() []string { return []string{"access_token", "impersonate"} }

func newGCP(cfg Account, deps Deps) (*gcpProvider, error) {
	b, err := newBase(cfg, deps, "gcp", "project_id")
	if err != nil {
		return nil, err
	}
	p := &gcpProvider{base: b, source: cfg.StrOr("source", "workload_identity"),
		stsURL:     cfg.StrOr("sts_url", "https://sts.googleapis.com/v1/token"),
		oauthURL:   cfg.StrOr("oauth_token_url", "https://oauth2.googleapis.com/token"),
		iamcredURL: strings.TrimRight(cfg.StrOr("iamcredentials_url", "https://iamcredentials.googleapis.com/v1"), "/"),
		crmURL:     strings.TrimRight(cfg.StrOr("resourcemanager_url", "https://cloudresourcemanager.googleapis.com/v1"), "/"),
		engineAuth: cfg.StrOr("engine_auth", "access_token"), sa: cfg.Str("service_account")}
	if !containsStr(gcpSources(), p.source) {
		return nil, failf("gcp: source '%s' unknown (%s)", p.source, strings.Join(gcpSources(), ", "))
	}
	required := []string{"service_account"}
	if p.source == "workload_identity" {
		required = append(required, "workload_identity_provider")
	}
	for _, k := range required {
		if cfg.Str(k) == "" {
			return nil, failf("gcp: %s missing", k)
		}
	}
	if !containsStr(gcpEngineAuths(), p.engineAuth) {
		return nil, failf("gcp: engine_auth '%s' unknown (%s)", p.engineAuth, strings.Join(gcpEngineAuths(), ", "))
	}
	if p.source == "workload_identity" {
		p.audience = "//iam.googleapis.com/" + strings.TrimPrefix(cfg.Str("workload_identity_provider"), "//iam.googleapis.com/")
	}
	if p.http, err = p.httpClient(); err != nil {
		return nil, err
	}
	return p, nil
}

// token is the service account's access token, cached in memory and renewed RefreshMargin before expiry.
func (p *gcpProvider) token(ctx context.Context) (string, error) {
	return p.cache.get(ctx, p.deps.now, p.acquire)
}

// acquire mints a fresh service-account token with golang.org/x/oauth2/google: the source credential (the
// workload's OIDC token exchanged at Google's STS, or the operator's ADC refresh token) and the impersonation of the
// service account are the SDK's own flows. Nothing but the resulting token is kept.
func (p *gcpProvider) acquire(ctx context.Context) (string, time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*callTimeout)
	defer cancel()
	capture := &errorCapture{next: transportOf(p.http)}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, &http.Client{Transport: capture})
	supplier := &subjectSupplier{p: &p.base}
	var ts oauth2.TokenSource
	var err error
	if p.source == "adc" {
		ts, err = p.adcTokenSource(ctx)
	} else {
		ts, err = externalaccount.NewTokenSource(ctx, externalaccount.Config{Audience: p.audience,
			SubjectTokenType: jwtTokenType, TokenURL: p.stsURL, Scopes: []string{gcpScope}, SubjectTokenSupplier: supplier,
			ServiceAccountImpersonationURL:             p.impersonationURL(),
			ServiceAccountImpersonationLifetimeSeconds: p.sessionSeconds()})
	}
	if err != nil {
		return "", time.Time{}, p.setupError(err)
	}
	tok, err := ts.Token()
	switch {
	case supplier.err != nil:
		return "", time.Time{}, supplier.err
	case err != nil:
		return "", time.Time{}, p.acquireError(err, capture)
	case tok.AccessToken == "":
		return "", time.Time{}, failf("gcp impersonation of %s: no access token returned", p.sa)
	}
	return tok.AccessToken, tok.Expiry, nil
}

func (p *gcpProvider) impersonationURL() string {
	return p.iamcredURL + "/projects/-/serviceAccounts/" + p.sa + ":generateAccessToken"
}

func (p *gcpProvider) setupError(err error) error {
	var ce *Error
	if errors.As(err, &ce) {
		return ce
	}
	return failf("gcp credentials: %s", firstLine(err.Error()))
}

// acquireError names the step that failed (token exchange, ADC refresh, impersonation) and the provider's own
// reason, from the error response the SDK received.
func (p *gcpProvider) acquireError(err error, c *errorCapture) error {
	step, hint := "gcp impersonation of "+p.sa, ""
	switch c.url {
	case p.stsURL:
		step = "gcp sts token exchange"
	case p.oauthURL:
		step = "gcp adc refresh"
	}
	if c.status == 0 {
		return failf("%s: %s unreachable (%s)", step, hostOf(c.url), errorKind(err))
	}
	why := ErrText(c.body)
	switch {
	case c.url == p.oauthURL && containsAny(why, "invalid_grant", "invalid_rapt"):
		hint = " (expired, revoked or re-authentication required: " + adcHint + ")"
	case c.url != p.stsURL && c.url != p.oauthURL && c.status == http.StatusForbidden && p.source == "adc":
		hint = " (the operator needs roles/iam.serviceAccountTokenCreator on it)"
	}
	return failf("%s: HTTP %d %s%s", step, c.status, why, hint)
}

// subjectSupplier gives the SDK the workload's OIDC token (read fresh, pre-checked) and keeps the reason of a
// failure (the SDK turns it into text).
type subjectSupplier struct {
	p   *base
	err error
}

func (s *subjectSupplier) SubjectToken(ctx context.Context, _ externalaccount.SupplierOptions) (string, error) {
	tok, err := s.p.identityToken(ctx)
	s.err = err
	return tok, err
}

// bearerClient is an HTTP client that sends the given access token (and nothing else that could authenticate).
func (p *gcpProvider) bearerClient(ctx context.Context, token string) *http.Client {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.http)
	return oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token, TokenType: "Bearer"}))
}

func hostOf(rawURL string) string {
	rest := rawURL
	if _, after, ok := strings.Cut(rawURL, "://"); ok {
		rest = after
	}
	host, _, _ := strings.Cut(rest, "/")
	return host
}

// Identity is the service account the platform runs as and how it got there (never the operator's own account).
func (p *gcpProvider) Identity(ctx context.Context) (Identity, error) {
	if _, err := p.token(ctx); err != nil {
		return Identity{}, err
	}
	return Identity{Principal: "serviceAccount:" + p.sa, Account: p.account, Source: p.source}, nil
}

// tokenCache keeps one access token in memory and renews it RefreshMargin before it expires.
type tokenCache struct {
	mu  sync.Mutex
	tok string
	exp time.Time
}

func (c *tokenCache) get(ctx context.Context, now func() time.Time,
	acquire func(context.Context) (string, time.Time, error)) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tok != "" && c.exp.Sub(now()) > RefreshMargin {
		return c.tok, nil
	}
	tok, exp, err := acquire(ctx)
	if err != nil {
		return "", err
	}
	c.tok, c.exp = tok, exp
	return tok, nil
}
