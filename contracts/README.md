# Contracts

Every component of security-platform is defined by **language-neutral contracts**: what it is given, what it must
produce, and the rules in between. Any implementation, in any language, that passes the black-box conformance suite
(`conformance/`) for a component may replace it. How to do that safely: [docs/contracts.md](../docs/contracts.md).

| contract | version | what | schemas | conformance components |
|---|---|---|---|---|
| [findings](findings/SPEC.md) | 1.2 | the document every collector run produces; OCSF mapping | `findings-v1` | through `ledger`, `collector-*` |
| [collector-protocol](collector-protocol/SPEC.md) | 1.0 | a collector as an executable: invocation, env, outputs, exit codes, what it must never do | — | `collector-*`, `runner` |
| [ledger](ledger/SPEC.md) | 1.0 | merge (lifecycle open/fixed/accepted/reopened, retirement, narrow gaps, exceptions, time to fix/know) and track (owners, due dates) | `ledger-v1`, `tracker-v1`, `exceptions-v1` | `ledger`, `remediation` |
| [scorecard](scorecard/SPEC.md) | 1.1 | controls → dimensions → weakest-link score; attestations; not applicable | `scorecard-v1`, `catalog-v1`, `attestations-v1` | `scorecard` |
| [runner](runner/SPEC.md) | 1.1 | schedule (catch-up once, jitter, retries, max_delay), no overlap, state, publish; implementation switch and shadow runs | `runner-config-v1`, `runner-state-v1`, `runner-status-v1` | `runner` |
| [metrics](metrics/SPEC.md) | 1.0 | Prometheus names, types, labels: the API of dashboards, alerts and SLOs | `registry.json` | `prom` checks in every component |
| [cli](cli/SPEC.md) | 1.0 | the `sp` command: what scripts may parse, exit codes, what it never prints | `findings-json-v1` | `cli` |

`index.json` is the same table for tools, with the known deviations and the conformance case that specifies each
target.

**Versioning.** Each contract has its own `MAJOR.MINOR` (the files it defines carry the major in their schema name,
e.g. `security-platform/ledger/v1`). A minor adds optional things; consumers ignore unknown fields. A breaking change
is a new major and follows the two-step rule of [docs/upgrade.md](../docs/upgrade.md): the new form is accepted or
emitted alongside the old one for at least one minor release and two weeks, then the old one goes. A contract change
is made in the same pull request as its schema, its conformance cases and the reference implementation.

**Known deviations.** Where today's reference implementation behaves in a way that is plainly a defect, the contract
says so in a "Known deviations" table, specifies the TARGET behaviour, and adds a conformance case for it. The
reference implementation is allowed to fail exactly those cases (`conformance/impl/python/expected-failures.txt`);
a new implementation must pass them.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY in the specs are used as in RFC 2119.
