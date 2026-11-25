package cloud

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	azcloud "github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

// azureReadOnlyRoles and azureKnownWriteRoles name built-in role definition ids in the evidence.
func azureReadOnlyRoles() map[string]string {
	return map[string]string{"acdd72a7-3385-48ef-bd42-f606fba81ae7": "Reader",
		"39bc4728-0917-49c7-9d2c-d95423bc2eb4": "Security Reader"}
}

func azureKnownWriteRoles() map[string]string {
	return map[string]string{"8e3af657-a8ff-443c-a75c-2fe8c4bcb635": "Owner",
		"b24988ac-6180-42a0-ab88-20f7382dd24c": "Contributor",
		"18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": "User Access Administrator"}
}

// azureProvider: an Azure subscription reached with workload identity federation: the workload's OIDC token is
// the client assertion of an app registration (azidentity ClientAssertionCredential; MSAL caches the token in
// memory and renews it before expiry). The SDK requires https for the authority (an emulator needs TLS and, for a
// private CA, `ca_file`).
type azureProvider struct {
	base
	authority, arm, scope string
	http                  *http.Client
	cred                  *azidentity.ClientAssertionCredential
	mu                    sync.Mutex
	assertErr             error // why the last assertion could not be produced (the SDK keeps only its text)
}

func newAzure(cfg Account, deps Deps) (*azureProvider, error) {
	b, err := newBase(cfg, deps, "azure", "subscription_id")
	if err != nil {
		return nil, err
	}
	for _, k := range []string{"tenant_id", "client_id"} {
		if cfg.Str(k) == "" {
			return nil, failf("azure: %s missing", k)
		}
	}
	p := &azureProvider{base: b,
		authority: strings.TrimRight(cfg.StrOr("authority_host", "https://login.microsoftonline.com"), "/"),
		arm:       strings.TrimRight(cfg.StrOr("arm_url", "https://management.azure.com"), "/"),
		scope:     cfg.StrOr("scope", "https://management.azure.com/.default")}
	if p.http, err = p.httpClient(); err != nil {
		return nil, err
	}
	opts := &azidentity.ClientAssertionCredentialOptions{ClientOptions: p.clientOptions(), DisableInstanceDiscovery: true}
	p.cred, err = azidentity.NewClientAssertionCredential(cfg.Str("tenant_id"), cfg.Str("client_id"), p.assertion, opts)
	if err != nil {
		return nil, failf("azure: %s", firstLine(err.Error()))
	}
	return p, nil
}

func (p *azureProvider) clientOptions() azcore.ClientOptions {
	audience := strings.TrimSuffix(p.scope, "/.default")
	return azcore.ClientOptions{Transport: p.http, Cloud: azcloud.Configuration{
		ActiveDirectoryAuthorityHost: p.authority + "/",
		Services: map[azcloud.ServiceName]azcloud.ServiceConfiguration{
			azcloud.ResourceManager: {Endpoint: p.arm, Audience: audience}}}}
}

// assertion is the workload's OIDC token, read fresh and pre-checked, for the SDK.
func (p *azureProvider) assertion(ctx context.Context) (string, error) {
	tok, err := p.identityToken(ctx)
	p.mu.Lock()
	p.assertErr = err
	p.mu.Unlock()
	return tok, err
}

// accessToken is the platform's ARM access token.
func (p *azureProvider) accessToken(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*callTimeout)
	defer cancel()
	tok, err := p.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{p.scope}})
	if err == nil {
		return tok.Token, nil
	}
	p.mu.Lock()
	aerr := p.assertErr
	p.mu.Unlock()
	if aerr != nil {
		return "", aerr
	}
	var af *azidentity.AuthenticationFailedError
	if errors.As(err, &af) && af.RawResponse != nil {
		return "", failf("azure federated token: HTTP %d %s", af.RawResponse.StatusCode, ErrText(payload(af.RawResponse)))
	}
	return "", failf("azure federated token: %s unreachable (%s)", hostOf(p.authority), errorKind(err))
}

// Identity is the principal (object id) of the platform's access token.
func (p *azureProvider) Identity(ctx context.Context) (Identity, error) {
	tok, err := p.accessToken(ctx)
	if err != nil {
		return Identity{}, err
	}
	c, err := JWTClaims(tok)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Principal: textOr(c, "oid", "sub"), Account: p.account}, nil
}

func textOr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := m[k].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// Permissions lists the role assignments of the platform's principal on the subscription (Reader can list them).
// Resource-provider auto-registration (a write) is disabled.
func (p *azureProvider) Permissions(ctx context.Context) (Permissions, error) {
	id, err := p.Identity(ctx)
	if err != nil {
		return Permissions{}, err
	}
	client, err := armauthorization.NewRoleAssignmentsClient(p.account, p.cred,
		&arm.ClientOptions{ClientOptions: p.clientOptions(), DisableRPRegistration: true})
	if err != nil {
		return Permissions{}, failf("azure role assignments: %s", firstLine(err.Error()))
	}
	ctx, cancel := context.WithTimeout(ctx, 3*callTimeout)
	defer cancel()
	filter := "assignedTo('" + id.Principal + "')"
	pager := client.NewListForSubscriptionPager(&armauthorization.RoleAssignmentsClientListForSubscriptionOptions{Filter: &filter})
	var roleIDs []string
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return Permissions{}, p.armError(err)
		}
		for _, a := range page.Value {
			roleIDs = append(roleIDs, roleDefinitionID(a))
		}
	}
	return judgeAssignments(id.Principal, roleIDs), nil
}

func roleDefinitionID(a *armauthorization.RoleAssignment) string {
	if a == nil || a.Properties == nil || a.Properties.RoleDefinitionID == nil {
		return ""
	}
	id := *a.Properties.RoleDefinitionID
	return id[strings.LastIndex(id, "/")+1:]
}

func judgeAssignments(principal string, roleIDs []string) Permissions {
	ro, known := azureReadOnlyRoles(), azureKnownWriteRoles()
	grants, write := []string{}, map[string]bool{}
	for _, rid := range roleIDs {
		name := dynOr(ro[rid], known[rid], "role "+rid)
		grants = append(grants, name)
		if _, ok := ro[rid]; !ok {
			write[name] = true
		}
	}
	sort.Strings(grants)
	return Permissions{Principal: principal, Method: "subscription role assignments", Grants: grants,
		WriteCapable: sortedKeys(write)}
}

func dynOr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// payload is the body of an error response (empty when unreadable: the status is then the reason).
func payload(resp *http.Response) []byte {
	body, err := runtime.Payload(resp)
	if err != nil {
		return nil
	}
	return body
}

func (p *azureProvider) armError(err error) error {
	var re *azcore.ResponseError
	if errors.As(err, &re) && re.RawResponse != nil {
		return failf("azure role assignments: HTTP %d %s", re.StatusCode, ErrText(payload(re.RawResponse)))
	}
	return failf("azure role assignments: %s", Reason(err))
}

// EngineEnv: workload identity federation for azure-identity (WorkloadIdentityCredential). It needs the OIDC token
// in a FILE: a configured file is used as is; a command/env token is written to a 0600 file in the run's private
// directory (removed after the run). It is the short-lived workload assertion, not an Azure credential.
func (p *azureProvider) EngineEnv(ctx context.Context, tmpdir string) (map[string]string, EngineArgs, error) {
	src := p.cfg.Map("identity_token")
	var tokp string
	if t, ok := src["type"]; !ok || t == "file" {
		tokp = ExpandUser(textOr(src, "path"), p.deps.home())
	} else {
		tok, err := p.identityToken(ctx)
		if err != nil {
			return nil, EngineArgs{}, err
		}
		tokp = filepath.Join(tmpdir, "azure-"+p.account+".assertion")
		if err := writePrivate(tokp, []byte(tok)); err != nil {
			return nil, EngineArgs{}, err
		}
	}
	env := map[string]string{"AZURE_TENANT_ID": p.cfg.Str("tenant_id"), "AZURE_CLIENT_ID": p.cfg.Str("client_id"),
		"AZURE_FEDERATED_TOKEN_FILE": tokp}
	if p.cfg.Str("authority_host") != "" {
		env["AZURE_AUTHORITY_HOST"] = p.authority
	}
	subs := p.cfg.List("subscription_ids")
	if len(subs) == 0 {
		subs = []string{p.account}
	}
	return env, EngineArgs{Subscriptions: subs}, nil
}
