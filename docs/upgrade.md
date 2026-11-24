# Versions and upgrades

## What is versioned

| what | where | tag |
|---|---|---|
| **the product** (a tested combination of everything below) | git tag | `vMAJOR.MINOR.PATCH`, e.g. `v0.2.0` |
| each component: `core`, `runner`, `sdk`, `generators`, `deploy`, `scorecard`, `cli`, each collector | `<dir>/VERSION` | `<component>/vX.Y.Z`, e.g. `runner/v0.5.0`, `collectors/host/v0.1.0` |
| each adapter module | `VERSION = "..."` in the module | (covered by the product tag) |
| the findings contract | `schema/findings-v1.schema.json`, documents carry `schema_version: "1.x"` | major in the file name |
| other contracts | `schema` fields: `security-platform/ledger/v1`, `tracker/v1`, `snapshot/v1`, `scorecard/v1`, ... | major in the name |
| metric names | `security_*` | part of the contract |

Components only talk through the contracts, so they can be upgraded one at a time (a new collector with an old core,
a new core with old site runners). The product tag is the combination we tested together and the one to install.

Semantic versioning, applied to what an operator sees:

- **patch** (`0.2.0 → 0.2.1`): fixes; no config change needed.
- **minor** (`0.2 → 0.3`): new checks, adapters, keys, metrics. Existing configs keep working; new findings may
  appear (new checks), which is the point.
- **major** (`1.x → 2.0`): something was removed after a deprecation period (below). Read the release notes first.

While the product is `0.x`, a minor release may also complete a two-step change announced in an earlier release.

## How to upgrade

Release notes: `CHANGELOG.md` and the GitHub release of the tag. Then:

```sh
cd ~/security-platform && git fetch --tags && git checkout v0.3.0      # the clone you use for `sp`
~/.venvs/security-platform/bin/pip install --require-hashes -r deploy/requirements.lock   # if the lock changed
sp doctor                                                               # new checks may need a tool
```

For the scheduled install (`bin/sp-install`):

```sh
~/security-platform/bin/sp-install ~/.local/opt/security-platform      # adds releases/v0.3.0, points current at it
~/.local/opt/security-platform/current/deploy/render.py env --install ~/.local/opt/security-platform   # if the lock changed
sh ~/.local/opt/security-platform/tick.sh && tail -5 $SP_DATA/state/runner/tick.log
```

**Rollback**: point `current` back (`ln -sfn releases/v0.2.0 ~/.local/opt/security-platform/current`). The private
data directory is forward and backward compatible within a major (unknown fields are ignored), so a rollback needs no
data migration. Commit the data directory before upgrading if it is a git repository (the `snapshot` job does that).

In Kubernetes: change the image tag in your overlay (`images: [{name: security-platform, newTag: <sha or tag>}]`)
and let your GitOps tool roll it out; roll back the same way.

Several hosts (hub and sites): upgrade the **hub first**, then the sites. A new hub accepts documents from old
sites (same contract major); a new site may emit new optional fields that an old hub ignores.

## Two-step changes (how breaking changes are made)

Nothing an operator relies on disappears in one release. A breaking change is split:

| step | release | what happens | what you do |
|---|---|---|---|
| 1. **add** | N | the new form is accepted/emitted **alongside** the old one: a consumer reads both contract majors, a metric is written under both names, a config key accepts the old and the new spelling. The old one is marked deprecated in CHANGELOG and logged. | Move dashboards, alerts and configs to the new form at your pace. |
| 2. **remove** | N+1 or later (at least one minor release and two weeks after step 1) | the old form goes. | Nothing, if you did step 1. |

Examples:

- **findings contract v2**: core accepts v1 and v2 (step 1); collectors switch to v2 one by one; after every
  collector emits v2, a later release stops reading v1 (step 2).
- **renaming a metric**: both names are exported (step 1); generated rules and dashboards switch to the new name;
  the old name is dropped later (step 2).
- **renaming a check**: the new check is emitted and the old name stays in the ledger until every old finding is
  closed; check names that were published are never reused for another meaning.

## Compatibility promises (0.x)

- Unknown fields in configs and documents are ignored, never fatal.
- Metric labels never carry asset details; adding a label to an existing metric is a minor change, removing one a
  two-step change.
- The data directory layout (`ledger.json`, `tracker/`, `reports/`, `state/`, `latest/`) is read by older and newer
  releases of the same major.
- Each tag passes the unit tests, the contract tests, `bin/check-residue --history`, and the kind end-to-end test
  (`e2e/kind/run.sh --ref <tag>`).

## Releasing (maintainers)

1. `CHANGELOG.md`: the section for the release lists every component version it contains.
2. Tag the components whose `VERSION` changed (`<component>/vX.Y.Z`) and the product (`vX.Y.Z`) on the merged commit.
3. `e2e/kind/run.sh --ref vX.Y.Z` passes; then the GitHub release with the notes (no environment data, ever).
