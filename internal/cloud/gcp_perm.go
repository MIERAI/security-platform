package cloud

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

// gcpWithCond is the synthetic role name Google returns for a conditional binding read at policy version 1.
var gcpWithCond = regexp.MustCompile(`_withcond_[0-9a-f]+$`)

// gcpReadOnlyRoles are the roles of the minimal read-only grant (docs/cloud.md).
func gcpReadOnlyRoles() map[string]bool {
	m := map[string]bool{}
	for _, r := range []string{"roles/iam.securityReviewer", "roles/viewer", "roles/browser", "roles/cloudasset.viewer",
		"roles/securitycenter.findingsViewer", "roles/securitycenter.adminViewer", "roles/logging.viewer",
		"roles/monitoring.viewer", "roles/serviceusage.serviceUsageConsumer", "roles/iam.roleViewer"} {
		m[r] = true
	}
	return m
}

// Permissions lists the roles bound to the service account on the project (getIamPolicy, allowed by Security
// Reviewer). Policy version 3 is requested: a binding with an IAM condition (e.g. an expiry, as recommended for
// audit access) is then returned with its real role and the condition, not as "<role>_withcond_<hash>" which no
// allow-list knows. A condition can only narrow a grant, so the base role is what is judged.
func (p *gcpProvider) Permissions(ctx context.Context) (Permissions, error) {
	tok, err := p.token(ctx)
	if err != nil {
		return Permissions{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*callTimeout)
	defer cancel()
	var pol struct {
		Bindings []binding `json:"bindings"`
	}
	in := map[string]any{"options": map[string]any{"requestedPolicyVersion": 3}}
	endpoint := p.crmURL + "/projects/" + url.PathEscape(p.account) + ":getIamPolicy"
	if err := googleJSON(ctx, p.bearerClient(ctx, tok), apiRequest{http.MethodPost, endpoint, in}, &pol); err != nil {
		return Permissions{}, failf("gcp getIamPolicy %s: %s", p.account, googleReason(err, p.crmURL))
	}
	return judgeBindings("serviceAccount:"+p.sa, pol.Bindings), nil
}

// binding is one role binding of an IAM policy (version 3: with its condition).
type binding struct {
	Role      string         `json:"role"`
	Members   []string       `json:"members"`
	Condition map[string]any `json:"condition"`
}

// judgeBindings is the self-check of a member's project bindings.
func judgeBindings(member string, bindings []binding) Permissions {
	roles, conditional := map[string]bool{}, map[string]bool{}
	for _, b := range bindings {
		if !containsStr(b.Members, member) {
			continue
		}
		role := gcpWithCond.ReplaceAllString(b.Role, "")
		roles[role] = true
		if len(b.Condition) > 0 || role != b.Role {
			conditional[role] = true
		}
	}
	perm := Permissions{Principal: member, Method: "project IAM policy bindings (policy version 3)",
		Grants: sortedKeys(roles), Conditional: sortedKeys(conditional), HasConditional: true, WriteCapable: []string{}}
	ro := gcpReadOnlyRoles()
	for _, r := range perm.Grants {
		if !ro[r] {
			perm.WriteCapable = append(perm.WriteCapable, r)
		}
	}
	return perm
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// EngineEnv: workload_identity: an external-account config (no key; google-auth exchanges the OIDC token itself
// and impersonates the service account, refreshing as needed). adc: the engine must act as the SERVICE ACCOUNT and
// never hold the operator's refresh token: gcloud's configuration directory is an empty private one, and
// engine_auth access_token (default) hands a freshly minted service-account token over in
// CLOUDSDK_AUTH_ACCESS_TOKEN (process environment only); engine_auth impersonate gives Prowler the operator's ADC
// file with --impersonate-service-account (refreshes for long scans; the engine process reads the refresh token).
func (p *gcpProvider) EngineEnv(ctx context.Context, tmpdir string) (map[string]string, EngineArgs, error) {
	projects := p.cfg.List("project_ids")
	if len(projects) == 0 {
		projects = []string{p.account}
	}
	if p.source == "adc" {
		return p.adcEngineEnv(ctx, tmpdir, projects)
	}
	src := p.cfg.Map("identity_token")
	env := map[string]string{}
	var credSource map[string]any
	if t, ok := src["type"]; !ok || dyn.Str(t) == "file" {
		if _, ok := src["path"]; !ok {
			return nil, EngineArgs{}, failf("identity token unavailable: KeyError")
		}
		credSource = map[string]any{"file": ExpandUser(dyn.Str(src["path"]), p.deps.home())}
	} else {
		acct := filepath.Join(tmpdir, "gcp-"+p.account+".json")
		if err := writeJSONPrivate(acct, p.cfg); err != nil {
			return nil, EngineArgs{}, err
		}
		credSource = map[string]any{"executable": map[string]any{
			"command": p.deps.Executable + " cloud executable-token " + acct, "timeout_millis": 30000}}
		env["GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"] = "1"
	}
	conf := map[string]any{"type": "external_account", "audience": p.audience, "subject_token_type": jwtTokenType,
		"token_url": p.stsURL, "credential_source": credSource,
		"service_account_impersonation_url": p.iamcredURL + "/projects/-/serviceAccounts/" + p.sa + ":generateAccessToken"}
	path := filepath.Join(tmpdir, "gcp-"+p.account+".external-account.json")
	if err := writeJSONPrivate(path, conf); err != nil {
		return nil, EngineArgs{}, err
	}
	env["GOOGLE_APPLICATION_CREDENTIALS"] = path
	env["GOOGLE_CLOUD_PROJECT"] = p.account
	return env, EngineArgs{Projects: projects}, nil
}

func (p *gcpProvider) adcEngineEnv(ctx context.Context, tmpdir string, projects []string) (map[string]string, EngineArgs, error) {
	empty := filepath.Join(tmpdir, "gcloud-config")
	if err := os.MkdirAll(empty, 0o700); err != nil {
		return nil, EngineArgs{}, failf("engine credentials: cannot create a private directory: %s", pyExcName(err))
	}
	env := map[string]string{"CLOUDSDK_CONFIG": empty, "GOOGLE_CLOUD_PROJECT": p.account,
		"CLOUDSDK_CORE_PROJECT": p.account}
	args := EngineArgs{Projects: projects, GCPSource: "adc", EngineAuth: p.engineAuth}
	if p.engineAuth == "access_token" {
		tok, _, err := p.acquire(ctx) // a fresh token: its full lifetime for the scan
		if err != nil {
			return nil, EngineArgs{}, err
		}
		env["CLOUDSDK_AUTH_ACCESS_TOKEN"] = tok
	} else {
		env["GOOGLE_APPLICATION_CREDENTIALS"], _ = ADCPath(p.cfg, p.deps)
		args.ImpersonateServiceAccount = p.sa
	}
	return env, args, nil
}
