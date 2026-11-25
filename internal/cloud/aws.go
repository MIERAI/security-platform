package cloud

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

const awsProfileName = "security-platform"

// awsProvider: an AWS account reached through STS AssumeRoleWithWebIdentity with the workload's OIDC token
// (optionally followed by an AssumeRole chain into the scanned account), or through an AWS CLI profile that
// yields temporary credentials (IAM Identity Center / SSO, a role). The SDK signs, retries, resolves endpoints and
// caches the credentials (renewed RefreshMargin before they expire).
type awsProvider struct {
	base
	region   string
	endpoint string
	mode     string
	http     *http.Client
	creds    *aws.CredentialsCache
}

func newAWS(cfg Account, deps Deps) (*awsProvider, error) {
	b, err := newBase(cfg, deps, "aws", "account_id")
	if err != nil {
		return nil, err
	}
	p := &awsProvider{base: b, endpoint: strings.TrimRight(cfg.Str("endpoint_url"), "/")}
	p.region = cfg.Str("region")
	if p.region == "" {
		p.region = dynFirst(cfg.List("regions"), "us-east-1")
	}
	p.mode = cfg.Str("mode")
	if p.mode == "" {
		p.mode = "web_identity"
		if cfg.Str("profile") != "" {
			p.mode = "profile"
		}
	}
	if p.http, err = p.httpClient(); err != nil {
		return nil, err
	}
	p.creds = aws.NewCredentialsCache(aws.CredentialsProviderFunc(p.acquire), func(o *aws.CredentialsCacheOptions) {
		o.ExpiryWindow = RefreshMargin
	})
	return p, nil
}

func dynFirst(list []string, def string) string {
	if len(list) > 0 {
		return list[0]
	}
	return def
}

func (p *awsProvider) stsClient(creds aws.CredentialsProvider) *sts.Client {
	return sts.New(sts.Options{Region: p.region, Credentials: creds, HTTPClient: p.http, BaseEndpoint: p.endpointPtr()})
}

func (p *awsProvider) endpointPtr() *string {
	if p.endpoint == "" {
		return nil
	}
	return aws.String(p.endpoint + "/")
}

// acquire obtains fresh temporary credentials (the cache calls it).
func (p *awsProvider) acquire(ctx context.Context) (aws.Credentials, error) {
	var src aws.CredentialsProvider
	switch p.mode {
	case "profile":
		src = aws.CredentialsProviderFunc(p.fromProfile)
	case "web_identity":
		if p.cfg.Str("role_arn") == "" {
			return aws.Credentials{}, failf("aws: role_arn missing")
		}
		src = stscreds.NewWebIdentityRoleProvider(p.stsClient(nil), p.cfg.Str("role_arn"),
			&tokenRetriever{ctx: ctx, p: &p.base}, func(o *stscreds.WebIdentityRoleOptions) {
				o.RoleSessionName = p.sessionName()
				o.Duration = time.Duration(p.sessionSeconds()) * time.Second
			})
	default:
		return aws.Credentials{}, failf("aws: mode %s unknown (web_identity, profile)", pyRepr(p.cfg["mode"]))
	}
	if chain := p.cfg.Str("chain_role_arn"); chain != "" {
		src = stscreds.NewAssumeRoleProvider(p.stsClient(src), chain, func(o *stscreds.AssumeRoleOptions) {
			o.RoleSessionName = p.sessionName()
			o.Duration = time.Duration(p.sessionSeconds()) * time.Second
			if ext := p.cfg.Str("external_id"); ext != "" {
				o.ExternalID = aws.String(ext)
			}
		})
	}
	c, err := src.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, &Error{Reason: awsReason(err)}
	}
	return c, nil
}

func (p *awsProvider) sessionName() string { return p.cfg.StrOr("session_name", "security-platform") }

// fromProfile resolves an AWS CLI profile with the SDK's own shared-config rules (SSO, role chains,
// credential_process) and refuses long-lived keys.
func (p *awsProvider) fromProfile(ctx context.Context) (aws.Credentials, error) {
	name := p.cfg.Str("profile")
	conf, err := config.LoadDefaultConfig(ctx, config.WithSharedConfigProfile(name), config.WithRegion(p.region),
		config.WithHTTPClient(p.http))
	if err != nil {
		return aws.Credentials{}, failf("aws profile %s: %s", name, firstLine(err.Error()))
	}
	c, err := conf.Credentials.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, failf("aws profile %s: no credentials (%s)", name, awsReason(err))
	}
	if c.SessionToken == "" || !c.CanExpire {
		return aws.Credentials{}, failf("aws profile %s yields long-lived keys: use SSO or a role", name)
	}
	return c, nil
}

// tokenRetriever gives the SDK the workload's OIDC token, read fresh and pre-checked at each call.
type tokenRetriever struct {
	ctx context.Context // the SDK's retriever interface takes no context: the acquisition's own
	p   *base
}

func (t *tokenRetriever) GetIdentityToken() ([]byte, error) {
	tok, err := t.p.identityToken(t.ctx)
	if err != nil {
		return nil, err
	}
	return []byte(tok), nil
}

// awsReason is a short reason for an SDK error: "<service> <operation>: HTTP <status> <code>: <message>".
func awsReason(err error) string {
	var ce *Error
	if errors.As(err, &ce) {
		return ce.Reason
	}
	service, op := "aws", "request"
	var oe *smithy.OperationError
	if errors.As(err, &oe) {
		service, op = strings.ToLower(oe.ServiceID), oe.OperationName
	}
	var ae smithy.APIError
	if !errors.As(err, &ae) {
		return fmt.Sprintf("%s %s: unreachable or failed (%s)", service, op, errorKind(err))
	}
	status := 0
	var re *awshttp.ResponseError
	if errors.As(err, &re) {
		status = re.HTTPStatusCode()
	}
	return fmt.Sprintf("%s %s: HTTP %d %s", service, op, status, dyn.Cut(ae.ErrorCode()+": "+ae.ErrorMessage(), 200))
}

// errorKind names a transport failure without its text (which may carry a URL with a query string).
func errorKind(err error) string {
	var nerr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.As(err, &nerr) && nerr.Timeout():
		return "timeout"
	case errors.As(err, &nerr):
		return "connection failed"
	default:
		return "request failed"
	}
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return dyn.Cut(line, 200)
}

// Identity is the caller's ARN and account; credentials for another account than configured are refused.
func (p *awsProvider) Identity(ctx context.Context) (Identity, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*callTimeout)
	defer cancel()
	out, err := p.stsClient(p.creds).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return Identity{}, &Error{Reason: awsReason(err)}
	}
	arn, acct := aws.ToString(out.Arn), aws.ToString(out.Account)
	if acct != "" && acct != p.account {
		return Identity{}, failf("aws: credentials are for account %s, expected %s", acct, p.account)
	}
	return Identity{Principal: arn, Account: acct}, nil
}

// Credentials returns the cached temporary credentials (the credential_process callback prints them).
func (p *awsProvider) Credentials(ctx context.Context) (aws.Credentials, error) {
	c, err := p.creds.Retrieve(ctx)
	if err != nil {
		return aws.Credentials{}, &Error{Reason: awsReason(err)}
	}
	return c, nil
}
