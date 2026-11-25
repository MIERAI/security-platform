package cloud

import (
	"context"
	"errors"
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"

	"github.com/MIERAI/security-platform/internal/cloud/dyn"
)

// awsReadOnlyPolicies are the managed policies of the minimal read-only grant (docs/cloud.md).
func awsReadOnlyPolicies() map[string]bool {
	return map[string]bool{"arn:aws:iam::aws:policy/SecurityAudit": true,
		"arn:aws:iam::aws:policy/job-function/ViewOnlyAccess": true}
}

func awsReadVerbs() []string {
	return []string{"Get", "List", "Describe", "BatchGet", "Search", "Lookup", "View", "Head", "Query", "Select",
		"Generate", "Simulate", "Check", "Validate", "Preview", "Estimate"}
}

func (p *awsProvider) iamClient() *iam.Client {
	return iam.New(iam.Options{Region: "us-east-1", Credentials: p.creds, HTTPClient: p.http,
		BaseEndpoint: p.endpointPtr()})
}

// Permissions inspects the role's attached and inline policies (SimulatePrincipalPolicy is not used: emulators do
// not implement it and it needs extra rights). The managed read-only policies pass; any other statement allowing
// a non-read verb, `*`, `service:*` or NotAction is write-capable.
func (p *awsProvider) Permissions(ctx context.Context) (Permissions, error) {
	id, err := p.Identity(ctx)
	if err != nil {
		return Permissions{}, err
	}
	arn := id.Principal
	parts := strings.Split(arnResource(arn), "/")
	if parts[0] != "assumed-role" || len(parts) < 2 {
		return Permissions{Principal: arn, Method: "n/a", Grants: []string{},
			WriteCapable: []string{"not a role session: " + parts[0]}}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*callTimeout)
	defer cancel()
	role, client := parts[1], p.iamClient()
	if _, err := client.GetRole(ctx, &iam.GetRoleInput{RoleName: aws.String(role)}); err != nil {
		var nse *iamtypes.NoSuchEntityException
		if errors.As(err, &nse) {
			return Permissions{}, failf("aws: role %s does not exist", role)
		}
		return Permissions{}, &Error{Reason: awsReason(err)}
	}
	perm := Permissions{Principal: arn, Method: "attached and inline role policies", Grants: []string{},
		WriteCapable: []string{}}
	if err := p.attachedPolicies(ctx, client, role, &perm); err != nil {
		return Permissions{}, err
	}
	if err := p.inlinePolicies(ctx, client, role, &perm); err != nil {
		return Permissions{}, err
	}
	return perm, nil
}

// arnResource is the part of an ARN after the fifth colon (the whole ARN when it has fewer parts).
func arnResource(arn string) string {
	parts := strings.SplitN(arn, ":", 6)
	return parts[len(parts)-1]
}

func (p *awsProvider) attachedPolicies(ctx context.Context, client *iam.Client, role string, perm *Permissions) error {
	pages := iam.NewListAttachedRolePoliciesPaginator(client, &iam.ListAttachedRolePoliciesInput{RoleName: aws.String(role)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return &Error{Reason: awsReason(err)}
		}
		for _, ap := range page.AttachedPolicies {
			if err := judgeManagedPolicy(ctx, client, aws.ToString(ap.PolicyArn), perm); err != nil {
				return err
			}
		}
	}
	return nil
}

// judgeManagedPolicy adds an attached managed policy to the grants; a policy other than the read-only ones is
// write-capable when its default version allows a non-read action.
func judgeManagedPolicy(ctx context.Context, client *iam.Client, parn string, perm *Permissions) error {
	if parn == "" {
		return nil
	}
	perm.Grants = append(perm.Grants, parn)
	if awsReadOnlyPolicies()[parn] {
		return nil
	}
	doc, err := managedPolicyDocument(ctx, client, parn)
	if err != nil {
		return err
	}
	if len(WriteActions(doc)) > 0 {
		perm.WriteCapable = append(perm.WriteCapable, parn)
	}
	return nil
}

func managedPolicyDocument(ctx context.Context, client *iam.Client, parn string) (string, error) {
	pol, err := client.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(parn)})
	if err != nil {
		return "", &Error{Reason: awsReason(err)}
	}
	var ver *string
	if pol.Policy != nil {
		ver = pol.Policy.DefaultVersionId
	}
	v, err := client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: aws.String(parn), VersionId: ver})
	if err != nil {
		return "", &Error{Reason: awsReason(err)}
	}
	if v.PolicyVersion == nil {
		return "{}", nil
	}
	return policyText(aws.ToString(v.PolicyVersion.Document)), nil
}

func (p *awsProvider) inlinePolicies(ctx context.Context, client *iam.Client, role string, perm *Permissions) error {
	pages := iam.NewListRolePoliciesPaginator(client, &iam.ListRolePoliciesInput{RoleName: aws.String(role)})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return &Error{Reason: awsReason(err)}
		}
		for _, name := range page.PolicyNames {
			if name == "" {
				continue
			}
			perm.Grants = append(perm.Grants, "inline:"+name)
			out, err := client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{RoleName: aws.String(role), PolicyName: aws.String(name)})
			if err != nil {
				return &Error{Reason: awsReason(err)}
			}
			if len(WriteActions(policyText(aws.ToString(out.PolicyDocument)))) > 0 {
				perm.WriteCapable = append(perm.WriteCapable, "inline:"+name)
			}
		}
	}
	return nil
}

// policyText decodes the URL-encoded policy document IAM returns (as Python's urllib.parse.unquote: "+" stays).
func policyText(doc string) string {
	if doc == "" {
		return "{}"
	}
	if s, err := url.PathUnescape(doc); err == nil {
		return s
	}
	return doc
}

// WriteActions lists the actions an IAM policy document ALLOWS that are not read-only (empty = read-only). A
// document or statement that cannot be read counts as write-capable.
func WriteActions(doc string) []string {
	v, err := dyn.Decode([]byte(doc))
	d, ok := v.(map[string]any)
	if err != nil || !ok {
		return []string{"<unparseable policy>"}
	}
	set := map[string]bool{}
	for _, st := range asList(d["Statement"]) {
		s, ok := st.(map[string]any)
		if !ok {
			set["<unparseable policy>"] = true
			continue
		}
		if dyn.Str(s["Effect"]) != "Allow" {
			continue
		}
		if _, ok := s["NotAction"]; ok {
			set["NotAction"] = true
			continue
		}
		for _, a := range asList(s["Action"]) {
			if act := dyn.Str(a); !readOnlyAction(act) {
				set[act] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// asList is `v or []`, a single value as a one-element list.
func asList(v any) []any {
	if !dyn.Truthy(v) {
		return nil
	}
	if l, ok := v.([]any); ok {
		return l
	}
	return []any{v}
}

func readOnlyAction(a string) bool {
	verb := a
	if _, after, ok := strings.Cut(a, ":"); ok {
		verb = after
	}
	if a == "*" || verb == "*" {
		return false
	}
	for _, v := range awsReadVerbs() {
		if strings.HasPrefix(verb, v) {
			return true
		}
	}
	return false
}

// EngineEnv: a profile whose credential_process calls back into sp (`sp cloud credential-process`): the engine
// (boto3, the Go SDK) gets temporary credentials in memory and asks again before they expire. The files hold no
// secret: the account entry (its token source) and the profile.
func (p *awsProvider) EngineEnv(_ context.Context, tmpdir string) (map[string]string, EngineArgs, error) {
	acct := filepath.Join(tmpdir, "aws-"+p.account+".json")
	if err := writeJSONPrivate(acct, p.cfg); err != nil {
		return nil, EngineArgs{}, err
	}
	cfgp := filepath.Join(tmpdir, "aws-"+p.account+".config")
	cmd := callbackCommand(p.deps, "credential-process", acct)
	body := "[profile " + awsProfileName + "]\ncredential_process = " + cmd + "\nregion = " + p.region + "\n"
	if err := writePrivate(cfgp, []byte(body)); err != nil {
		return nil, EngineArgs{}, err
	}
	env := map[string]string{"AWS_CONFIG_FILE": cfgp, "AWS_PROFILE": awsProfileName, "AWS_REGION": p.region,
		"AWS_DEFAULT_REGION": p.region, "AWS_SHARED_CREDENTIALS_FILE": devNull(p.deps.GOOS),
		"AWS_EC2_METADATA_DISABLED": "true"}
	if p.endpoint != "" {
		env["AWS_ENDPOINT_URL"] = p.endpoint
	}
	regions := p.cfg.List("regions")
	if len(regions) == 0 {
		regions = []string{p.region}
	}
	return env, EngineArgs{Profile: awsProfileName, Regions: regions}, nil
}
