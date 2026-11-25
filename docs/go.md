# Go implementation: layout, transition and coding standard

The core is being rewritten in Go one component at a time. Python and Go ship together during the move; nothing
an operator relies on changes in one step (docs/upgrade.md, two-step changes).

## How the move works

- **One component at a time.** A Go implementation replaces its Python counterpart only after it passes the
  black-box conformance suite for that component (`contracts/`, `conformance/`): same inputs, same documents,
  same exit statuses, same metrics. Until then the Python implementation is what runs.
- **One binary.** `sp` (`cmd/sp`) is the single user-facing program, and every `sp` subcommand now runs in Go: the
  day-to-day commands (`init doctor run status findings explain digest notify`, `internal/cli`, contract cli) and the
  components (`ledger runner scorecard cloud version`). With `SP_CLI=python` (the way back; deprecated, kept through v0.4.x) the
  day-to-day commands and unknown ones are handed to the Python implementation (`cli/sp.py`) unchanged: the argument
  vector, standard input/output/error, the environment and the exit status. On Unix the `sp` process is
  *replaced* by Python (execve), so signals, the process id and the terminal behave exactly as with `bin/sp`; on
  Windows `sp` waits for a child process and exits with its status.
- **Where the Python implementation is found**, in this order: `$SP_PY_HOME` (if set, only there); the tree the
  binary sits in (`<tree>/bin/sp` or `<tree>/sp`, symbolic links resolved); the default install root
  `~/.local/opt/security-platform/current`. The interpreter is `$SP_PYTHON`, else `python3` (also `python` on
  Windows) from `PATH`; a program found only through a relative `PATH` entry such as `.` is refused.
- **What is implemented where**: `sp version` (or `sp version --json`, schema
  `security-platform/version/v1`) lists every component with its version and implementation (`go` or
  `python`), the Go subcommands, the binary's own release and the Python tree's. `sp --version` keeps the first
  line of the Python output (`sp <cli version> (security-platform <release>)`) and adds those details.
- **Shim exit statuses** (a delegated command's status is always passed through): 127 when there is no Python
  tree or interpreter to delegate to, 126 when it could not be started, 2 for a usage error in a Go subcommand.

A component moves to Go by adding it to `components.GoImplemented()` (and its subcommands to `shim`) in the same
pull request that makes its conformance suite run against the Go implementation.

## Layout

```
go.mod                 module github.com/MIERAI/security-platform (dependencies: below, "Dependencies")
cmd/sp/                the sp binary: wiring only (environment, streams, exit); end-to-end tests build it
internal/shim/         dispatch: Go subcommands, delegation to Python, `sp version`
internal/delegate/     running cli/sp.py: argument vector, execve on Unix, child process elsewhere
internal/pyhome/       locating the Python tree
internal/release/      product release names from product tags only (as cli/release.py), RELEASE files
internal/components/   the product's components (<dir>/VERSION) and their implementation
internal/buildinfo/    the binary's release (link time), commit and toolchain
internal/textsafe/     printing text read from files without terminal control characters
internal/cli/          `sp init|doctor|run|status|findings|explain|digest|notify` (contracts/cli); subpackages flags (the
                       command lines argparse accepts, its usage/help layout) and explain (explanations.json, embedded and
                       read by cli/explanations.py: the texts live in one file)
internal/notifier/     `sp notify`'s adapters (stdout, file, webhook, telegram, exec), as notifier/notifiers.py
internal/fakepython/   a stand-in interpreter for tests
internal/scorecard/    the scorecard (`sp scorecard compute|lint|list|version`; `attest` stays in Python)
internal/pyvalue/       documents as the reference reads them: YAML 1.1 typing, ordered JSON, number printing,
                       rounding (contracts/scorecard/SPEC.md §6); shared by every Go component
internal/ledger/       the ledger merge (`sp ledger merge`, contracts/ledger); VERSION (component internal/ledger)
  cli/                 `sp ledger merge|track|version`
  pyjson/              ledger.json / items.json as the reference writes them: key order, int vs float, integers
                       of any size, json.dumps with every option the ledger uses (also compact, ensure_ascii lines)
  yamlcfg/             exceptions.yaml, catalog-review.yaml, instance config, SLI catalog: pyvalue.DecodeYAML
  findings/            findings document validation (embedded copy of schema/findings-v1.schema.json)
  instant/ prom/ fileio/  UTC timestamps, Prometheus text, bounded reads and atomic writes
internal/runner/       `sp runner` (docs/runner.md): scheduling, locks, jobs, state, metrics; subpackages cron (schedules,
                       DST), config (the runner block of the instance), promtext (metrics text); files through pyvalue
internal/remediation/  track (`sp ledger track`): items, owners, SLO due dates, files and github-issues trackers
internal/cloud/        the cloud adapter (adapters/cloud.py): AWS, GCP, Azure on the official SDKs; discovery gcp
internal/collectors/cloud/  the cloud collector (`sp cloud collect`) and its engines, imports, controls, merge
internal/collectors/rundoc/  what sdk/spsdk is for Python collectors: the findings document, evidence and metrics byte for
                       byte as the SDK writes them, the protocol environment, private writes, child processes
internal/collectors/k8s/    the k8s collector (`sp k8s collect`): kubectl, read verbs only; image inventory
internal/collectors/vulnintel/  the vuln-intel collector (`sp vuln-intel collect`): feeds, trivy, image/host matching
internal/collectors/identity/   the identity collector (`sp identity collect`): code host, overlay network, local credentials
internal/<component>/  added per component as it moves (collectors/<name>, ...)
```

Everything is under `internal/`: the Go packages are not a public library API, the contracts (`schema/`,
`contracts/`) are.

## Coding standard

Enforced by CI (`.github/workflows/go.yml`, `.golangci.yml`) where a tool can check it, by review otherwise.

- **Small functions**: at most about 50 lines (revive `function-length`), cyclomatic complexity at most 12,
  cognitive complexity at most 15, at most 5 parameters and 3 results.
- **No global mutable state**: no package-level variables except compiled regular expressions, sentinel errors
  and the link-time release name; registries are functions that return a fresh value. Everything a function
  reads from the process (arguments, environment, streams, executable path) is passed in; only `cmd/*/main.go`
  reads the environment, prints to the process's streams or exits (forbidigo).
- **Errors are wrapped with context** (`fmt.Errorf("read release file: %w", err)`), compared with `errors.Is` /
  `errors.As`, and never ignored silently; an intentionally ignored error is assigned to `_` with a comment
  saying why.
- **No shell**: programs are run with an argument vector (`exec.CommandContext(ctx, "git", "-C", dir, ...)`),
  never through `sh -c` or a command line built by string concatenation. Arguments that come from outside and
  could be read as options are rejected (a ref starting with `-`).
- **Secrets are never logged**, printed or put in errors: not tokens, not passwords, not the values of
  environment variables or config keys that hold them; log that a value is set, never the value.
- **Text from outside is made safe before it reaches a terminal** (`textsafe.Line`): no escape sequences, no
  forged lines.
- **Bounded reads**: files and streams from outside are read through a size limit.
- **Time limits**: every call that can block (subprocess, network) takes a `context.Context` and has a timeout
  (`noctx`, `contextcheck`). The one deliberate exception is the delegated Python command, which enforces its
  own limits.
- **Tests**: table-driven (`tests := []struct{...}` + `t.Run`), parallel where possible, run with `-race`.
  **Every parser of external input has a fuzz test** (`FuzzXxx`) — product tags, RELEASE and VERSION files,
  YAML and JSON documents, scorecard catalogs and attestations, dates, durations, globs, the metrics text format,
  command lines — and CI runs each one briefly on every change.
- **Dependencies**: standard library only unless a dependency is justified in its pull request (what it
  replaces, its maintenance, its own dependencies); depguard enforces the allow-list. Tools are pinned by
  version and checksum; GitHub Actions by commit SHA. New tool and action versions wait about two weeks after
  their release before they are adopted.
- **Dependencies in use** (each pinned in `go.mod`/`go.sum`, allowed by depguard, checked by govulncheck):

  | module | version | why |
  |---|---|---|
  | `go.yaml.in/yaml/v3` | v3.0.6 (2026-10-13) | YAML catalogs, instances and attestations, which the reference reads with PyYAML. It replaces writing a YAML parser. It is the YAML organisation's maintained continuation of `gopkg.in/yaml.v3` (archived in 2025), same API; MIT/Apache-2.0; no dependencies of its own; pure Go without `unsafe`, `os` or network. Only its `Node` API is used: the scalar style and explicit tags it keeps let `pyvalue` apply the YAML 1.1 typing rules of the reference (`yes`/`on` booleans, `017` octal, dates), which no decoder into `any` does. Aliases are expanded by `pyvalue` with a node budget and a depth limit; files are read through a size limit. Not chosen: `gopkg.in/yaml.v3` (unmaintained), `go.yaml.in/yaml/v4` (v4.0.0 is three weeks old and a new API: revisit after it settles), `goccy/go-yaml` (larger, its own typing rules), `sigs.k8s.io/yaml` (converts to JSON: loses tags and order). Every Go component that reads YAML uses this one module. |

- **Toolchain**: the `toolchain` line of `go.mod` (currently go1.27.4) is the version CI and releases build with;
  `go` is the minimum language version.

## Cloud SDK dependencies

The cloud SDKs: only `internal/cloud` may import them, and only the packages listed in `.golangci.yml` (depguard
rule `cloud-sdks`, package by package); everything else stays standard library + this module + the YAML module above.
Each direct cloud module, what it
replaces and why it is worth it (versions in `go.mod`; each was released at least two weeks before it was adopted,
except `golang.org/x/crypto` v0.59.0, the first release with the fix for GO-2026-5932, taken on its 14th day):

| module (direct) | packages used | replaces / why |
|---|---|---|
| `github.com/aws/aws-sdk-go-v2` (+ `config`, `credentials`, `service/sts`, `service/iam`) | `aws`, `aws/transport/http`, `config`, `credentials/stscreds`, `service/sts`, `service/iam(/types)` | our SigV4 signer, STS/IAM Query-API XML handling, endpoint/partition rules; adds paging (IAM lists were read as one page), retries, credential caching with an expiry window, and the SDK's SSO/shared-config profile resolution (`mode: profile` no longer needs the AWS CLI). Maintained by AWS. |
| `github.com/aws/smithy-go` | `smithy-go` | the error model of the AWS SDK (`APIError`, operation errors): the coverage-gap reasons (`<service> <operation>: HTTP <status> <code>: <message>`). Maintained by AWS. |
| `golang.org/x/oauth2` | `oauth2`, `google`, `google/externalaccount` | our STS token exchange, ADC refresh-token grant and `generateAccessToken` impersonation: Google's own external-account and impersonated-credential flows. Maintained by the Go team with Google. |
| `github.com/Azure/azure-sdk-for-go/sdk/azcore`, `azidentity`, `resourcemanager/authorization/armauthorization/v2` | `azcore`, `azcore/arm`, `azcore/cloud`, `azcore/policy`, `azcore/runtime`, `azidentity`, `armauthorization/v2` | our Entra client-assertion token request and ARM role-assignment listing: MSAL's authority and token rules (https only, tenant discovery, token cache and refresh), ARM paging, retries. Maintained by Microsoft. |

Indirect modules come with these (`go mod graph`): the AWS SDK's internal modules and `sso`/`ssooidc`/`signin` (profile
resolution), MSAL for Go, `golang-jwt/jwt/v5`, `google/uuid`, `kylelemons/godebug`, `pkg/browser` (Azure SDK),
`cloud.google.com/go/compute/metadata` (x/oauth2/google), `golang.org/x/{crypto,net,sync,sys,text}`.

**Considered and not used: `google.golang.org/api`** (and `cloud.google.com/go/*`). After authentication the adapter
makes three read-only Google calls (`getIamPolicy` with `requestedPolicyVersion: 3`, Cloud Asset
`searchAllResources`, Compute `instances.aggregatedList`): plain JSON over HTTPS. The generated clients bring gRPC,
protobuf, OpenTelemetry, S2A, the enterprise-certificate proxy and gax as transitive dependencies, and made `sp` 24 MB
instead of 12.6 MB (linux/amd64, stripped; `compute/v1` alone is several megabytes). They would not carry the rule that
started this rewrite either: the policy version is an explicit request option in the client too. The provider rules
that do matter for GCP (token exchange, impersonation, ADC) come from `golang.org/x/oauth2/google`.

Binary size of `sp` (linux/amd64, `-trimpath -ldflags="-s -w"`): 3.3 MB without the cloud code, 12.6 MB with it.
Each SDK measured alone on a small program: AWS (sts, iam, stscreds, config) +2.8 MB, Azure (azidentity, armauthorization)
+3.1 MB, x/oauth2/google +2.5 MB (partly shared code such as x/net); the adapter and collector are the rest.

Checks: `go mod verify`, `go mod tidy -diff` and govulncheck in CI (`.github/workflows/go.yml`); every parser of
provider responses and engine output has a fuzz test.

## Go collectors: k8s, vuln-intel, identity

`sp k8s collect`, `sp vuln-intel collect` and `sp identity collect` implement the collectors of the same names behind
the collector protocol, with the same configuration keys, the same data-directory layout (one data directory works
with either implementation, in both directions) and byte-identical documents, evidence, inventories and metrics on
every conformance case without a deviation id (`tests/test_collectors_go.py` runs both implementations in identical
sandboxes and compares every file of the run directory, times and the sandbox path masked). Where the Python
collector has a recorded defect (contracts/collector-protocol/SPEC.md, "Known deviations": K8S-D*, VULN-D*,
IDENTITY-D*) the Go one has the target behaviour, and its conformance runs have no expected failures. The Python
collectors stay the default; as for the cloud collector, a `command` job selects the Go one:

```yaml
runner:
  jobs:
    k8s: {type: command, argv: [~/.local/bin/sp, k8s, collect], schedule: "15 */6 * * *", timeout: 30m}
    vuln-intel: {type: command, argv: [~/.local/bin/sp, vuln-intel, collect], schedule: "0 5 * * *", timeout: 2h}
    identity: {type: command, argv: [~/.local/bin/sp, identity, collect], schedule: "0 6 * * *", timeout: 30m}
```

(`collector:` defaults to the job name; with `as:` the collector reports under `SP_COLLECTOR_NAME`, as in Python.)

**Kubernetes access: kubectl, not client-go.** The k8s collector runs the operator's `kubectl` with an argument vector,
exactly as the Python collector does, instead of linking `k8s.io/client-go`:

- *Correctness*: the kubeconfig is the operator's, with whatever authentication it carries (exec credential plugins
  for EKS/GKE/AKS, OIDC, client certificates, in-cluster ServiceAccount). kubectl is the reference implementation of
  all of them; with client-go every plugin path would be ours to configure and test. The collector reads lists only,
  so the API machinery client-go adds (informers, watch, apply, protobuf) buys nothing here.
- *Dependencies*: a program that lists pods with the typed clientset is 38 MB (linux/amd64, stripped), with the
  dynamic client 12 MB, against 14.5 MB for all of `sp`; client-go brings 77 modules (k8s.io/api, apimachinery, klog,
  kube-openapi, structured-merge-diff, gnostic, json-iterator, gogo/protobuf, ...) that govulncheck and depguard would
  have to cover. depguard stays as it is: the collectors use the standard library and this module only.
- *Read-only by construction*: every call goes through one function that builds the argument vector and refuses every
  verb except `get` and `auth whoami` (unit-tested); the conformance cases replay recorded API answers through a fake
  kubectl that logs every call, and assert that nothing but those verbs was ever called. Pod specs are decoded into
  structs that have no field for environment values, so they cannot reach an output.

**vuln-intel**: the feeds (CISA KEV, EPSS, OSV per ecosystem, Android bulletins, Apple security releases, MSRC CVRF)
are fetched with `net/http`: conditional GET with the Python implementation's cache files and ETag/Last-Modified
metadata, TLS 1.2+ only (plain http only to a loopback mirror, also for redirects), a size limit per download and per
inflated archive (gzip, zip: total size, entry count, entry size), and the payload is parsed before it replaces the
cached copy. Trivy stays an external engine (argument vectors as in Python; registry credentials only in
`TRIVY_USERNAME`/`TRIVY_PASSWORD`). Not in Go: feed `vendor-advisories` (unstructured pages, the advisor, the human
review state) and `code_repos` (code-host listings and clones): an instance that uses them is refused with exit 2 and
keeps the Python collector.

**identity**: the code host's REST API and the overlay network's API directly over `net/http` (no `gh api`): GET
only (plus the OAuth token exchange of the overlay network), redirects never followed (the token would follow),
proxies from the run's environment except for loopback hosts, Link-header pagination bounded to 100 pages, the Python
adapter's ETag cache files; certificates of kubeconfig users are read with `crypto/x509` and printed in OpenSSL's
form, so both implementations write the same groups and expiry.

kube-bench (part `cis`) runs on a node through `host_exec` (`local`, or `ssh` with batch mode and strict host key
checking): the same script as the Python collector, with the benchmark name checked against
`^[A-Za-z0-9][A-Za-z0-9._-]*$` first, because it becomes part of that script.

## Working locally

```sh
gofmt -l . && go vet ./... && go test -race -cover ./...
golangci-lint run ./...                         # the version in .github/workflows/go.yml
go test -run='^$' -fuzz='^FuzzParseFile$' -fuzztime=30s ./internal/release
conformance/impl/go/run.sh                      # the conformance suite against the Go ledger and cli (no expected failures)
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
scripts/build-release.sh v0.0.0-local dist-go   # the release build, see docs/install.md
```
