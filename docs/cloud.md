# Cloud security posture (AWS, GCP, Azure)

The `cloud` collector checks cloud accounts (AWS accounts, GCP projects, Azure subscriptions) **read-only**, with
**short-lived credentials only**, through **any** check engine or the provider's own posture service, and lands every
result in the same ledger as the rest of the platform. Environments without cloud accounts need nothing: the cloud
scorecard dimension is then *not applicable* and never lowers a score.

```
            OIDC token (projected / CI / local issuer)   or, for a human-run GCP scan, the operator's gcloud ADC
                    │  short-lived, in memory
   adapters/cloud.py ── STS / token exchange / Entra ──▶ temporary credentials (refreshed before expiry)
        │  self-verification: are MY permissions read-only? (no → finding + refuse to scan)
        ▼
   collectors/cloud ─┬─ prowler    (external process, json-ocsf)     ┐
                     ├─ steampipe  (external process, our SQL pack)  ├─▶ generic controls ─▶ merge (resource, control)
                     ├─ scoutsuite (external process, results JSON)  │      (controls.py)       ─▶ ONE finding, N sources
                     └─ imports: Security Hub ASFF, SCC, Defender    ┘                          ─▶ ledger, scorecard
```

## What is validated where

| part | AWS | GCP | Azure |
|---|---|---|---|
| login with short-lived credentials (OIDC → STS / token exchange + impersonation / federated client assertion) | **e2e**: LocalStack STS `AssumeRoleWithWebIdentity` with a token from a real OIDC issuer (mock-oauth2-server); unit tests with a fake STS (+ `AssumeRole` chain, SigV4 checked against the AWS documentation's example) | **e2e** against `cloudmock.py` (our mock of `sts.googleapis.com` / `oauth2.googleapis.com` (ADC refresh) / `iamcredentials` / `getIamPolicy`, verifying the token's RS256 signature, issuer, expiry, audience, and which ADC user may impersonate which service account); unit tests | **e2e** against `cloudmock.py` (our mock of the Entra token endpoint and ARM role assignments); unit tests |
| refresh before expiry, nothing on disk | unit test (fake clock); e2e asserts no credential material in data, runs, home or temp, temp dirs removed | unit test | unit test |
| self-verification (read-only?) | **e2e**: attached + inline role policies via IAM (`SecurityAudit` + `ViewOnlyAccess` pass; `AdministratorAccess` → finding + refused) | **e2e** (mock bindings: Security Reviewer + Viewer pass; Editor refused) | **e2e** (mock assignments: Reader + Security Reader pass; Contributor refused) |
| failure modes → coverage gap with reason | **e2e**: expired token, wrong audience, missing role; unit: AssumeRole denied, STS expired-token | **e2e**: wrong audience (server side), denied impersonation, missing service account; `source: adc`: ADC missing, refresh token revoked (`invalid_grant`), a key file as ADC, impersonation denied (403), service account missing (404), over-privileged | **e2e**: wrong audience, unknown application |
| scanning engines | **e2e**: Prowler, Steampipe **and** ScoutSuite against LocalStack into ONE ledger, de-duplicated (ScoutSuite: S3 and IAM; it cannot enumerate EC2 regions on LocalStack); contract tests | contract tests (Prowler json-ocsf fixtures) | contract tests (Prowler json-ocsf fixtures) |
| native service import | e2e (an ASFF export file) + contract test | e2e (SCC export fixture) + contract test | e2e (Defender export fixture) + contract test |
| lifecycle (fixed on the next covered run) | **e2e** (public bucket, open SSH, console user without MFA fixed → `fixed`) | unit (ledger) | unit (ledger) |

Honest limits:

- **LocalStack community does not enforce IAM.** It accepts any web-identity token and any role ARN, and it does not
  implement `SimulatePrincipalPolicy`. Read-only is therefore verified by **policy inspection** (the role's attached
  and inline policies), never by attempting writes; trust-policy denial of `AssumeRole` is covered by unit tests
  against a fake STS, and expired/wrong-audience tokens are rejected by the adapter's own pre-checks (the real STS
  rejects them too).
- **LocalStack community does not emulate CloudTrail** (and several sub-APIs: snapshot/image block-public-access,
  instance metadata defaults, access-advisor, organizations). Prowler then reports "no multi-region trail" from an
  empty listing; Steampipe's query fails. The collector keeps the finding AND records `cloud:aws/<acct>/cloudtrail` as
  a coverage gap, so it is never "fixed" by a run that could not see CloudTrail. Root-account checks (credential
  report rows) are also not meaningful on LocalStack. Recent LocalStack images (2026.x) need an account token; the e2e
  pins the last community image that runs without one (4.14.0).
- **The GCP and Azure endpoints in the e2e are our mocks.** They validate the platform's flow (exchange, impersonation,
  assertions, error handling, permission inspection), not Google's or Microsoft's behaviour. No emulator exists for
  GCP IAM/Compute/firewall or Azure ARM, so GCP and Azure **scans** are validated with contract fixtures (Prowler's
  json-ocsf shape), not end to end. `fake-gcs-server` was not used: it covers objects, not bucket IAM, and would add
  nothing the contract test does not.
- **ScoutSuite** on LocalStack returns S3 and IAM verdicts but checks no EC2 resource (it cannot enumerate regions
  there); the collector records that as a blind service, which is not a gap while another engine covers EC2 cleanly.
- Everything a real account adds (organisations, many regions, real IAM evaluation, throttling, cost) needs a
  personal sandbox account: see [Validating against a real account](#validating-against-a-real-account).

## Permissions (minimal, read-only)

| provider | grant to the platform's identity | how the platform gets in (no stored key) |
|---|---|---|
| AWS | managed policies `SecurityAudit` + `job-function/ViewOnlyAccess` on a role | `AssumeRoleWithWebIdentity` with an OIDC token (IAM OIDC identity provider + trust policy on `aud`/`sub`); optionally an `AssumeRole` chain into each member account (`chain_role_arn`, `external_id`); or an IAM Identity Center (SSO) profile (`profile:`; `aws configure export-credentials`) |
| GCP | `roles/iam.securityReviewer` + `roles/viewer` (on the project, folder or organisation) to a service account | workload identity federation: a pool + OIDC provider, the federated principal may `roles/iam.workloadIdentityUser` on the service account; the platform impersonates it (`generateAccessToken`, 1 h). Human-run alternative `source: adc`: the operator's gcloud login may `roles/iam.serviceAccountTokenCreator` on the same service account ([below](#gcp-a-human-run-scan-with-your-own-login-source-adc)) |
| Azure | `Reader` + `Security Reader` on the subscription (or management group) to an app registration / user-assigned managed identity | a federated identity credential on the app (issuer + subject + audience `api://AzureADTokenExchange`); the OIDC token is the client assertion |

The self-verification runs before every scan. An identity with anything else (AWS: any policy beyond those two whose
statements allow a non-read verb, `*`, `service:*` or `NotAction`; GCP: any role outside the read-only set in
`adapters/cloud.py`; Azure: any role other than Reader / Security Reader) produces
`cloud.platform_credential_over_privileged` (people pillar; the `self` dimension's control
`self.cloud-credential-read-only`) and, by default, **the account is not scanned** (`refuse_over_privileged: false`
to scan anyway and only report). What the APIs cannot tell (e.g. the IAM evaluation of a permission boundary) is
not guessed: the evidence lists the grants it saw.

Refused configuration: `access_key_id`, `secret_access_key`, `client_secret`, `private_key`, ... in an account entry
(long-lived keys) are rejected with a coverage gap. Ambient keys in the runner's environment (`AWS_ACCESS_KEY_ID`,
`AZURE_CLIENT_SECRET`, `GOOGLE_APPLICATION_CREDENTIALS`, ...) are removed before an engine starts, so an
administrator's shell credentials can never be used for a scan. (With GCP `source: adc` the adapter itself reads the
operator's ADC, only to impersonate the audit service account; the engine still never acts as the operator.)

## Data handling

- **Credentials**: in memory only. Engines receive no secret: AWS engines get a profile whose `credential_process`
  calls back into `adapters/cloud.py` (temporary credentials on stdout, refreshed by the SDK before expiry); GCP
  engines get an *external account* config (token exchange + impersonation URLs, no key), or with `source: adc` the
  service account's short-lived access token in the process environment (see below); Azure engines get the
  workload-identity variables. The per-run temporary directory (0700) is removed after the run. For Azure with a
  `command`/`env` token source the OIDC assertion (not a cloud credential; minutes-lived) is written to a 0600 file in
  that directory, because the Azure SDK reads it from a file.
- **Evidence** (`raw/cloud/<provider>-<account>.json`, private): the identity's principal (for GCP also its `source`:
  `workload_identity` or `adc`; never the operator's own account) and grant names, engine
  versions and error messages, and per finding its sources (engine, engine check id, a short detail line). Never
  resource contents, never tokens.
- **Findings are attacker intelligence**: they stay in the private data directory; metrics carry aggregates only
  (`security_cloud_accounts{state}`, `security_cloud_engine_runs{source,result}`, `security_cloud_findings{pillar}`).
- **Offline ticks**: engines are installed once at deploy time (`render.py tool-env`); a tick never downloads. The
  scan itself needs the provider's API (if it is unreachable, the account is a coverage gap).

## Setup

### 1. Install the engines (deploy time)

```sh
I=~/.local/opt/security-platform
$I/current/deploy/render.py tool-env --install $I --tool prowler      # deploy/tools/prowler.lock (hashes, Python 3.12)
$I/current/deploy/render.py tool-env --install $I --tool steampipe    # optional: release + SHA-256 + pinned AWS plugin
$I/current/deploy/render.py tool-env --install $I --tool scoutsuite   # optional
```

Each tool lives in `$I/tools/<tool>/current`, separate from the runner's environment.

### 2. Give the platform an identity per provider

**AWS** (per account; or one audit account + `chain_role_arn` into members):

1. IAM → Identity providers → add an OpenID Connect provider for your workload's issuer (a Kubernetes cluster's
   service-account issuer, your CI's OIDC issuer), audience `sts.amazonaws.com`.
2. A role `security-platform-audit` with the managed policies `SecurityAudit` and `job-function/ViewOnlyAccess`, a
   trust policy allowing `sts:AssumeRoleWithWebIdentity` from that provider with conditions on `aud` and `sub`
   (e.g. `system:serviceaccount:security:scanner`), maximum session 1 h.
3. The workload's token: a projected service-account token with audience `sts.amazonaws.com`, or a command that
   prints one.

**GCP**: a workload identity pool and an OIDC provider for the issuer; a service account with `roles/iam.securityReviewer`
and `roles/viewer`; allow the federated principal (`principal://iam.googleapis.com/projects/N/locations/global/workloadIdentityPools/P/subject/<sub>`)
`roles/iam.workloadIdentityUser` on it. No service-account key.

#### GCP: a human-run scan with your own login (`source: adc`)

For a **trial or a one-off scan run by a person** (not for the daily unattended job: use workload identity federation
there), the platform can start from the operator's gcloud *Application Default Credentials* and impersonate the same
read-only audit service account:

```sh
gcloud auth application-default login            # once; writes ~/.config/gcloud/application_default_credentials.json
gcloud iam service-accounts add-iam-policy-binding audit@my-project.iam.gserviceaccount.com \
  --member user:<you> --role roles/iam.serviceAccountTokenCreator     # you may mint tokens for the audit SA
```

```yaml
    - provider: gcp
      project_id: my-project
      source: adc                                       # default: workload_identity
      service_account: audit@my-project.iam.gserviceaccount.com
```

- **Where the ADC comes from**: `adc_file` if set, else `GOOGLE_APPLICATION_CREDENTIALS`, else gcloud's well-known
  file (`$CLOUDSDK_CONFIG` or `~/.config/gcloud/application_default_credentials.json`). Only the `authorized_user`
  type (a user login) is accepted; a service-account **key file** is refused (long-lived), other types too. The file
  must not be readable by group/others.
- **Flow**: refresh token → user access token (`oauth2.googleapis.com/token`) → `generateAccessToken` for
  `service_account` (1 h, `cloud-platform` scope). The user token is used for that one call and dropped; the refresh
  token is read from the file on each acquisition and never kept, logged or written. Everything after that,
  including the same self-verification as above (refuse to scan when the service account can write), runs as the
  service account. Evidence records `principal: serviceAccount:audit@...` and `source: adc` only.
- **Engines never get your login**. gcloud's config directory is pointed at an empty private directory for the
  engine, so your ADC is invisible to it, and:
  - `engine_auth: access_token` (default): Prowler gets a freshly minted service-account access token in
    `CLOUDSDK_AUTH_ACCESS_TOKEN` (process environment, never a file). It is **not refreshed**: the scan must finish
    within `session_seconds` (default 3600; Google allows up to 12 h only with the
    `iam.allowServiceAccountCredentialLifetimeExtension` organisation policy). Services listed after expiry fail and
    become coverage gaps, never "fixed". Narrow `engines.prowler.checks` / `services` for large projects.
  - `engine_auth: impersonate`: Prowler's `--impersonate-service-account` with `GOOGLE_APPLICATION_CREDENTIALS`
    pointing at your existing ADC file (nothing is copied). Tokens refresh for long scans, but the Prowler process
    then reads your refresh token. Use it only when a scan cannot fit in the token lifetime.
  - ScoutSuite can neither impersonate nor take an access token (it only uses `google.auth.default()`, i.e. it would
    scan as you), so it is **not run** with `source: adc`: `.../engine:scoutsuite` is a coverage gap with that reason.
- **Failures are coverage gaps with a reason**: no ADC (`run gcloud auth application-default login`), refresh token
  expired/revoked or re-authentication required (`invalid_grant` / `invalid_rapt`), impersonation denied (HTTP 403:
  you lack `roles/iam.serviceAccountTokenCreator` on the service account), service account missing (HTTP 404).
- **adc vs workload identity**: ADC is tied to a person, expires with their session policy and needs their login on
  the machine: fine for a trial or an investigation, wrong for the scheduled job (a scan must not depend on someone
  being logged in, and a person's refresh token does not belong on a server). Workload identity federation has no
  long-lived secret at all.

**Azure**: an app registration (or user-assigned managed identity) with a federated credential (issuer, subject,
audience `api://AzureADTokenExchange`); role assignments `Reader` and `Security Reader` on the subscription. No secret.

### 3. Instance config

```yaml
cloud:
  refuse_over_privileged: true                      # default
  accounts:
    - provider: aws
      account_id: "123456789012"
      role_arn: arn:aws:iam::123456789012:role/security-platform-audit
      audience: sts.amazonaws.com                   # checked before sending (expired / wrong audience = gap)
      identity_token: {type: file, path: /var/run/secrets/tokens/aws}
      regions: [eu-west-1, us-east-1]
      engines: [prowler, steampipe]
    - provider: gcp
      project_id: my-project
      workload_identity_provider: projects/123/locations/global/workloadIdentityPools/security/providers/k8s
      service_account: security-audit@my-project.iam.gserviceaccount.com
      identity_token: {type: file, path: /var/run/secrets/tokens/gcp}
    # - {provider: gcp, project_id: my-project, source: adc, service_account: audit@my-project.iam.gserviceaccount.com}
    #   (a human-run scan with your gcloud login, see above)
    - provider: azure
      subscription_id: 00000000-0000-0000-0000-000000000000
      tenant_id: 00000000-0000-0000-0000-000000000000
      client_id: 00000000-0000-0000-0000-000000000000
      identity_token: {type: file, path: /var/run/secrets/tokens/azure}
  engines:
    prowler:   {path: ~/.local/opt/security-platform/tools/prowler/current/bin/prowler, timeout: 3h}
    steampipe: {path: ~/.local/opt/security-platform/tools/steampipe/current/bin/steampipe,
                install_dir: ~/.local/opt/security-platform/tools/steampipe/current/home, plugin: aws@1.34.1}
  imports:
    - {type: securityhub, file: ~/exports/securityhub.json, max_age: 2d, accounts: ["123456789012"]}
runner:
  jobs:
    cloud: {schedule: "30 4 * * *", timeout: 4h}
```

Every key: [instance-reference.md](instance-reference.md#cloud).

## Classification

Every engine check and native-service control maps onto a **generic control** (`collectors/cloud/controls.py`) with
its pillar, ledger layer and CIS Foundations Benchmark sections (AWS v3.0, GCP v2.0, Azure v2.0); the finding also
keeps every CIS reference the engine reported (`refs: cis-aws:3.0/5.2, ...`) and every source (`attributes.sources`).

| pillar | controls (examples) |
|---|---|
| network | `cloud.firewall_admin_port_open` (SSH/RDP from the internet), `cloud.firewall_open_to_internet`, `cloud.public_endpoint` |
| device / resource | `cloud.volume_unencrypted`, `cloud.instance_unpatched`, `cloud.instance_metadata_v1` |
| people / identity | `cloud.user_without_mfa`, `cloud.root_mfa_disabled`, `cloud.root_access_key`, `cloud.root_used`, `cloud.access_key_old`, `cloud.credential_unused`, `cloud.service_account_key_user_managed`, `cloud.admin_privileges_broad`, `cloud.platform_credential_over_privileged` |
| software / data | `cloud.storage_public`, `cloud.snapshot_public`, `cloud.storage_unencrypted`, `cloud.storage_insecure_transport`, `cloud.audit_log_disabled` |

An engine check without a generic control is still reported as `cloud.<provider>.<check id>` and classified by its
id prefix (nothing is dropped). Assets are canonical whichever tool saw the resource: `cloud:aws/<account>/<service>/<region>/<ARN resource>`,
`cloud:gcp/<project>/<api>/<name>`, `cloud:azure/<subscription>/<namespace>/<resource id>`.

**De-duplication**: the same resource with the same control (or sharing a CIS reference) from several engines and
imports is **one** finding, with the highest severity and every source listed; it is fixed when no source reports it
on a run that covered the account (and no service gap covers it).

**Coverage**: the account asset is `ok` when the platform logged in, its self-check passed and at least one engine ran
(or a fresh import covers it). A service that an engine could not list (errors and no verdict at all) and that no
other engine covered cleanly (verdicts without errors) is a gap `cloud:<provider>/<account>/<service>`: findings
under it are kept, never "fixed" blind. An engine that could not run
is a gap `.../engine:<name>`.

## Engines and licences

The product is Apache-2.0. Engines are **external processes** only: their code is never imported, linked, copied or
vendored here, and they are installed separately from their official releases at deploy time.

| engine | licence | how it is used | validated |
|---|---|---|---|
| [Prowler](https://github.com/prowler-cloud/prowler) | Apache-2.0 | `prowler <provider> ... --output-formats json-ocsf`; pinned in `deploy/tools/prowler.lock` | e2e (AWS/LocalStack); contract (GCP, Azure) |
| [Steampipe](https://github.com/turbot/steampipe) + AWS plugin | AGPL-3.0 (CLI), Apache-2.0 (plugin) | `steampipe query --output json` with **this product's own SQL** (`collectors/cloud/steampipe_queries.py`); no Steampipe mod is used | e2e (AWS/LocalStack) |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | GPL-2.0 | `scout <provider> --no-browser --report-dir ...`, results JSON parsed; pinned in `deploy/tools/scoutsuite.lock` | e2e (AWS/LocalStack: S3, IAM); contract test |
| Security Hub / Security Command Center / Defender for Cloud | provider services | an export file (ASFF / `gcloud scc findings list --format=json` / Resource Graph `securityresources` assessments) | contract tests; e2e import of export files |

Adding an engine: one function in `collectors/cloud/engines.py` (`ENGINES`) that returns tool-neutral results, plus
its check ids in `controls.py`; adding a provider: one class in `adapters/cloud.py` (`PROVIDERS`).

## The local end-to-end test

```sh
e2e/cloud-localstack/run.sh            # ~5 minutes; needs docker, python3, uv; tears everything down
```

LocalStack community (pinned by digest) seeded with a public bucket, an unencrypted bucket, a security group open on
22 to 0.0.0.0/0, an IAM user with an access key and a console password without MFA, and no CloudTrail; an OIDC issuer
(mock-oauth2-server, pinned); `cloudmock.py` for GCP/Azure. It scans with Prowler, Steampipe and ScoutSuite, imports a Security
Hub export and the SCC / Defender fixtures, asserts findings, pillars, de-duplication, the failure modes and the
scorecard, fixes three resources, scans again and asserts they are `fixed`. Result: `e2e/cloud-localstack/last-pass.json`.
`SP_CLOUD_E2E_IMPL=go` runs the Go implementation ([below](#go-implementation-sp-cloud)) and compares it with the
Python one after every scan.

## Go implementation (`sp cloud`)

The adapter (adapters/cloud.py), the collector (collectors/cloud) and `discovery: gcp` also exist in Go
(`internal/cloud`, `internal/collectors/cloud`, [go.md](go.md)), on the providers' **official SDKs**: aws-sdk-go-v2
(SigV4, STS web identity and `AssumeRole`, IAM paging, partitions and endpoints, SSO/shared-config profiles),
golang.org/x/oauth2/google (Google's STS token exchange, external-account credentials, ADC refresh and service-account
impersonation) and the Azure SDK for Go (MSAL federated client assertion, ARM paging). The rules of each provider's
authentication are then the SDK's, not ours. Same configuration keys, same refusals, same coverage-gap reasons, same
findings document: the Python and Go implementations produce byte-identical documents, evidence and metrics apart
from times (shown on every e2e run and by the parity tests on the shared fixtures).

```sh
sp cloud collect                                  # the collector (collector protocol: SP_RUN_DIR, SP_INSTANCE, ...)
sp cloud discover discovery-gcp.json              # discovery gcp: the VM instances as JSON on stdout
sp cloud credential-process ACCOUNT.json          # called by engines (AWS credential_process), not by people
sp cloud executable-token ACCOUNT.json            # called by engines (google-auth executable-sourced token)
```

It is not the default yet (the runner still runs collectors/cloud/collector.py). To run it, a `command` job:

```yaml
runner:
  jobs:
    cloud: {type: command, argv: [~/.local/bin/sp, cloud, collect], schedule: "30 4 * * *", timeout: 4h}
```

Conformance: `SP_IMPL_COLLECTOR_CLOUD="sp cloud collect" python3 conformance/run.py --component collector-cloud`.
End to end: `SP_CLOUD_E2E_IMPL=go e2e/cloud-localstack/run.sh` (also runs the Python implementation on the same state
after every scan and failure scenario and compares the outputs, `compare_impls.py`).

Differences an operator can notice:

- **Azure authority**: the SDK accepts only `https` and only the root of a host (`https://login.microsoftonline.com`,
  a sovereign cloud's authority, `https://<emulator>:<port>`); an emulator needs TLS and, with a private CA, `ca_file`.
- **`ca_file`** (any provider, Go only): extra CA certificates trusted for the account's endpoints.
- **GCP `source: adc`**: the impersonated service-account token lives Google's default hour (x/oauth2 takes no lifetime
  for impersonated user credentials); `session_seconds` still applies to workload identity federation.
- **AWS `mode: profile`**: the profile is resolved by the SDK's own shared-config rules (IAM Identity Center/SSO, role
  chains, `credential_process`) instead of `aws configure export-credentials`, so the AWS CLI is not needed; a profile
  that yields long-lived keys is still refused.
- **Retries**: the SDKs retry throttling and server errors with backoff (Python: one attempt). Azure resource-provider
  auto-registration (a write the ARM SDK would otherwise attempt on some errors) is disabled.
- **Network failures** read `<step>: <host> unreachable (connection failed|timeout)`.

## Validating against a real account

Only with a **personal sandbox account** (never an employer's or a customer's cloud), done by its owner:

1. Create the identity as in [Setup](#2-give-the-platform-an-identity-per-provider) with **only** the read-only
   grants; confirm in the console that no other policy/role is attached.
2. Provide the OIDC token source (a local issuer is not trusted by AWS unless its discovery document and JWKS are
   reachable over HTTPS: use a real issuer such as a cluster's service-account issuer or a CI provider).
3. Start with one region and a short check list (`engines.prowler.checks`), then widen.
4. Compare the result with the provider console (Security Hub / SCC / Defender), then enable the daily job.

Cost cautions: the scan itself only calls free read APIs, but **enabling** Security Hub, AWS Config (Security Hub's
dependency), GuardDuty, SCC Premium or Defender plans is billed per resource/evaluation; CloudTrail data events and
log storage cost money; API throttling grows with regions and services; a NAT gateway or a public IP left from a test
is billed hourly. Set a budget alert before starting and delete test resources afterwards.
