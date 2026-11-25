# Contract: events — version 1.0

| | |
|---|---|
| contract | `events`, version **1.0** |
| implementations | `events/ship.py` (reference), `sp events ship` (Go, `internal/events`) |
| caller | the runner's `events` job (contracts/runner), or any scheduler |
| consumer | the log store and the detection rules (`detections/catalog.yaml`), the `detection` collector (expected sources) |
| conformance | `conformance/cases/events/*` (impl: `SP_IMPL_EVENTS`) |

The key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

The events shipper reads security events from hosts and SaaS control planes and pushes them to a Loki-compatible push
endpoint. It is not a collector: it writes no findings document.

## 1. Invocation

```
<impl> --config FILE --state DIR [--summary FILE] [--now EPOCH] [--dry-run]
```

- `--config`: JSON, `{"loki": {"url", "token_file"?, "batch"?, "timeout"?}, "heartbeat"?: bool, "sources": [...]}`.
  A source is `{"name", "type": command | file-integrity | github-account | tailscale-audit, "host"?, "heartbeat"?, ...}`
  (the keys of each type: `events/ship.py`, docs/detection.md "Log contract").
- `--state`: a directory the shipper owns; one `<name>.json` per source (cursor, edge hashes, snapshot, seen
  addresses, conditional-request cache). Created when missing.
- `--now`: the run's clock (epoch seconds); default the real clock.
- `--dry-run`: print the push bodies (`{"streams": [...]}`) on stdout; push nothing, store no state.
- A source `name` MUST consist of letters, digits, `.`, `_`, `-` (it names a state file); another name ends the run
  with a non-zero exit when it is reached (the Go shipper checks every name before it ships anything).

## 2. Delivery

- For every source, in order: read what is new since its state, normalise, push, and only **after a successful push**
  write the new state (atomically, mode 0600). A failed push keeps the old state: the next run sends the same events
  again (**at least once**).
- One failing source MUST NOT stop the others. Exit 0 when every source shipped, 1 when any failed.
- The **first run** of a source (no state) is a baseline: the cursor, snapshot or seen addresses are recorded; nothing
  is reported as new or novel (`novel: "false"`).
- Unless `heartbeat` is false (source, else config), every successful source also pushes one line
  `{"heartbeat": "<name>", "events": <n>}` with `event: heartbeat` — proof that the source is collected even when
  nothing happened (the `detection` collector counts it as delivery; no rule matches it).

## 3. What is pushed (log contract)

One stream per source and push: labels `source` (`auth` for command and file-integrity, `codehost` for
github-account, `overlay-network` for tailscale-audit) and `host` (the source's `host`, default its name). Values are
`[<ns timestamp as text>, <line>, <structured metadata>?]`, sorted by time; metadata keys per label: auth `event`,
`user`, `src_ip`, `novel`; codehost `event`, `actor`, `repo`; overlay-network `event`, `actor`; empty values omitted.
The line is the raw log line (auth) or a compact JSON record of the API object. Batches of at most `loki.batch`
(default 500) values per request.

## 4. Summary

With `--summary FILE`: `{"version": <component version>, "sources": {<name>: {"ok": true, "shipped": n, "events":
{<event>: n}, "baseline": bool, "unsupported": {<endpoint>: <status>}} | {"ok": false, "error": "<Type>: <text>"}}}`,
JSON with indent 1 and sorted keys.

## 5. Secrets and requests

- Tokens come from files that only their owner can read (`token_file`, `oauth_client_secret_file`: a file readable
  by group or others is refused, the source fails) or from a named environment variable (`token_env`). A secret MUST
  NOT appear in a pushed line, the state, the summary, stdout/stderr or an error text.
- Requests to the APIs read (GET); the only POSTs are the push to `loki.url` and the OAuth token exchange of
  tailscale-audit. A credential MUST NOT be sent to another origin than the one it is configured for.

## Known deviations

| id | what | target |
|---|---|---|
| EVENTS-D1 | `events/ship.py` (urllib) copies the `Authorization` header to the target of a redirect, whatever its host. | A redirect to another origin is not followed with the credential (the Go shipper does not follow it). Case `events/credentials-not-sent-to-another-host`. |

## History

| version | change |
|---|---|
| 1.0 | first formal version (documents events/ship.py 0.1.1 and its Go implementation) |
