# Go implementation: layout, transition and coding standard

The core is being rewritten in Go one component at a time. Python and Go ship together during the move; nothing
an operator relies on changes in one step (docs/upgrade.md, two-step changes).

## How the move works

- **One component at a time.** A Go implementation replaces its Python counterpart only after it passes the
  black-box conformance suite for that component (`contracts/`, `conformance/`): same inputs, same documents,
  same exit statuses, same metrics. Until then the Python implementation is what runs.
- **One binary.** `sp` (`cmd/sp`) is the single user-facing program. A subcommand with a Go implementation runs
  in Go; every other invocation is handed to the Python implementation (`cli/sp.py`) unchanged: the argument
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
go.mod                 module github.com/MIERAI/security-platform (one dependency: go.yaml.in/yaml/v3, below)
cmd/sp/                the sp binary: wiring only (environment, streams, exit); end-to-end tests build it
internal/shim/         dispatch: Go subcommands, delegation to Python, `sp version`
internal/delegate/     running cli/sp.py: argument vector, execve on Unix, child process elsewhere
internal/pyhome/       locating the Python tree
internal/release/      product release names from product tags only (as cli/release.py), RELEASE files
internal/components/   the product's components (<dir>/VERSION) and their implementation
internal/buildinfo/    the binary's release (link time), commit and toolchain
internal/textsafe/     printing text read from files without terminal control characters
internal/fakepython/   a stand-in interpreter for tests
internal/ledger/       the ledger component (contracts/ledger): merge (`sp ledger merge`); VERSION
  cli/                 `sp ledger merge|track|version`
  pyjson/              JSON as the reference sees it: key order, int vs float, json.dumps output, Python semantics
  yamlcfg/             YAML 1.2 files (exceptions.yaml, catalog-review.yaml, instance config) to pyjson values
  findings/            findings document validation (embedded copy of schema/findings-v1.schema.json)
  instant/ prom/ fileio/  UTC timestamps, Prometheus text, bounded reads and atomic writes
internal/remediation/  track (`sp ledger track`): items, owners, SLO due dates, files and github-issues trackers
internal/<component>/  added per component as it moves (runner, scorecard, collectors/<name>, ...)
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
  **Every parser of external input has a fuzz test** (`FuzzXxx`) — product tags, RELEASE and VERSION files so
  far — and CI runs each one briefly on every change.
- **Dependencies**: standard library only unless a dependency is justified in its pull request (what it
  replaces, its maintenance, its own dependencies); depguard enforces the allow-list, govulncheck checks it. Today:
  - `go.yaml.in/yaml/v3` v3.0.5 (pinned in go.mod/go.sum; released 2026-07): the YAML parser for operator-written
    files (`exceptions.yaml`, `catalog-review.yaml`, the instance config) and the bundled SLI catalog. Operators
    write block and flow style with anchors and merge keys; a hand-written subset parser would misread some of it
    — for exceptions, silently, which is worse than failing. It replaces nothing in this module. It is the YAML
    organisation's maintained continuation of `gopkg.in/yaml.v3` (the parser most Go projects, Kubernetes
    included, depend on), pure Go, with no dependencies of its own. It is used through one package
    (`internal/ledger/yamlcfg`) at the node level: YAML 1.2 core-schema scalars (timestamps stay text), mapping keys
    as text, alias expansion bounded (`yamlcfg.MaxNodes`), one document per file; fuzzed there. Tools are pinned by
  version and checksum; GitHub Actions by commit SHA. New tool and action versions wait about two weeks after
  their release before they are adopted.
- **Toolchain**: the `toolchain` line of `go.mod` (currently go1.27.4) is the version CI and releases build with;
  `go` is the minimum language version.

## Working locally

```sh
gofmt -l . && go vet ./... && go test -race -cover ./...
golangci-lint run ./...                         # the version in .github/workflows/go.yml
go test -run='^$' -fuzz='^FuzzParseFile$' -fuzztime=30s ./internal/release
conformance/impl/go/run.sh                      # the conformance suite against `sp ledger` (no expected failures)
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
scripts/build-release.sh v0.0.0-local dist-go   # the release build, see docs/install.md
```
