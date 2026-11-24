# Writing an adapter or a collector

Your environment has something the platform does not support yet: another code host, a cloud, an asset inventory,
an identity provider, a chat tool. You add a **plugin**; you never change the core (ledger, runner, scorecard). This
page is the recipe. The interfaces themselves are listed in `adapters/README.md`.

## Which kind of plugin?

| you want to... | write | size | example |
|---|---|---|---|
| find assets somewhere new (cloud API, CMDB, inventory file) | a **discovery** adapter (`adapters/discovery.py`) | 20-40 lines | `static`, `file`, `tailscale` |
| run read-only commands on machines a new way (SSM, osquery, an agent) | an **exec** adapter (`adapters/exec.py`) | 20-40 lines | `local`, `ssh` |
| deliver metrics somewhere new | a **sink** (`adapters/sinks.py`) | 20-60 lines | `textfile`, `kubernetes-configmap`, `remote_write` |
| send the daily summary somewhere new | a **notifier** (`notifier/notifiers.py`) | 10-20 lines | `telegram`, `webhook`, `exec` |
| check a new kind of system (a code host, a cloud account, an IdP) | a **collector** (`collectors/<name>/`) | 100-200 lines | `codehost-gitea` |
| wrap a third-party scanner you already run | a `command` job (no code in this repository) | — | `runner.jobs.x: {type: command, argv: [...]}` |

Rule of thumb: if the *checks* stay the same and only the *way to reach* things changes, it is an adapter. If you
need new checks, it is a collector (which uses adapters).

## Rules every plugin follows

1. **Read-only.** A plugin never changes the target. No POST/PUT/DELETE, no writes on hosts, no auto-fix.
2. **Non-interactive.** Never prompt. A missing permission or a password prompt is a failure that the collector
   records as a *coverage gap* (so the dashboard says "could not check", not "safe").
3. **Secrets from 0600 files, never logged.** Read tokens with a helper that refuses group/world-readable files;
   reduce errors to a status code (an HTTP error message may contain the URL, and the URL may contain the token).
4. **No environment in the code.** No host names, addresses, organisation names or accounts. Everything specific
   comes from the instance config. `bin/check-residue` enforces this in CI.
5. **Stdlib first.** The runner must work offline on minimal hosts. A heavy dependency belongs in the external tool
   the collector wraps (nmap, trivy), not in Python.
6. **Generic names.** Check names describe the problem, not the vendor, so the same SLI and dashboard work for every
   implementation (the Gitea collector reuses `repo.default_branch_unprotected` from GitHub).

## A discovery adapter, step by step

```python
# adapters/discovery.py
def netbox(cfg):
    """{type: netbox, url, token_file, filter?: "status=active"} -> devices from a NetBox inventory."""
    tok = _secret(cfg["token_file"])
    rows = _get_json(f"{cfg['url'].rstrip('/')}/api/dcim/devices/?{cfg.get('filter', 'status=active')}", tok)
    return [dict(name=d["name"], address=(d.get("primary_ip4") or {}).get("address", "").split("/")[0] or None,
                 os=(d.get("platform") or {}).get("slug", ""), online=True, attrs={})
            for d in rows["results"]]

ADAPTERS = {..., "netbox": netbox}
```

Then:

1. Add a unit test that serves a fake API from an in-process HTTP server (see `tests/test_adapters_generic.py`): no
   network in tests.
2. Bump `VERSION` in the module (minor for a new adapter) and add a CHANGELOG line.
3. Document the config keys in `docs/instance-reference.md`.
4. Use it: `exposure: {discovery: [{type: netbox, url: ..., token_file: ...}]}`.

## A collector, step by step

A collector is a script that reads the instance config, looks at something through adapters, and writes **one
findings document** per run with the SDK. Start from `collectors/codehost-gitea/collector.py` (stdlib, an HTTP API,
a token file):

```python
import spsdk
c = spsdk.Collector("codehost-gitlab", VERSION)           # name = directory name
for cfg in inst.get("codehost") or []:
    if cfg.get("type") != "gitlab":
        continue                                            # another collector handles other types
    ...
    c.ok(asset)                                             # "I looked at this asset" (enables fixed-detection)
    c.gap(asset, "HTTP 403")                                # "I could not look" (never a silent pass)
    c.finding("supply-chain", asset, "repo.default_branch_unprotected", title, "high", evidence_pointer,
              "add a protected-branch rule ...")            # layer, asset, check, title, severity, evidence, fix
    c.metric("security_repos_total", n, "Repos checked", owner=cfg["owner"])   # aggregate labels only
c.write()
```

Checklist (CI enforces the first four):

- [ ] `collectors/<name>/VERSION` (start at `0.1.0`) and a fixture `tests/fixtures/<name>.findings.json`
      (`tests/make_fixture.py` generates a synthetic one) — the contract test fails without them.
- [ ] Metric labels from the allowed set only (`tests/test_outputs.py`): never an asset, address, port or id.
- [ ] Every check name has a plain-language entry in `cli/explanations.py` (what / why / fix / verify);
      `tests/test_cli.py` fails otherwise.
- [ ] `generators/gen.py` regenerated (`dist/` gets a freshness SLO for the new collector).
- [ ] A unit test against a fake (HTTP server, fake kubectl, fake exec), never the real service.
- [ ] `coverage`: call `c.ok()` only for assets you really looked at, `c.gap()` for everything in scope you could not.
      The ledger marks a finding fixed only when its asset was covered.
- [ ] Evidence: store filtered facts (`c.raw(...)`), never secret values; HTTP bodies at most a short snippet.
- [ ] The job: `runner.jobs.<name>: {schedule: ...}`; tools the collector needs go into `COLLECTOR_TOOLS` in
      `cli/sp.py` so `sp doctor` can check them.

## A notifier

```python
# notifier/notifiers.py
def matrix(cfg, text):
    """{type: matrix, homeserver, room_id, token_file}"""
    tok = secret(cfg["token_file"])
    url = f"{cfg['homeserver'].rstrip('/')}/_matrix/client/v3/rooms/{cfg['room_id']}/send/m.room.message/{int(time.time()*1000)}"
    _put(url, json.dumps({"msgtype": "m.text", "body": text}).encode(), tok)

ADAPTERS = {..., "matrix": matrix}
```

The text you receive is already safe to leave the private boundary (aggregates only). Do not add details to it.

## Versions and compatibility

Each adapter module and each collector has its own version; a new adapter or check is a minor bump, a fix a patch.
Changing a check's name or a config key's meaning is breaking: do it in two steps ([upgrade.md](upgrade.md)).
Contributions: one plugin per pull request, with its test and documentation.
