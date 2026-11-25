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
~/.local/opt/security-platform/current/bin/sp --version                 # sp <cli version> (security-platform v0.3.0)
```

The release directory is named after the **product tag** of the checked-out commit (`vX.Y.Z`), never after a
component tag, and holds a `RELEASE` file (`version=`, `commit=`) that `sp --version` and the runner's
`security_runner_info{release=...}` report. A commit without a product tag (a branch, `main`) is refused; install
it deliberately as a development build with `bin/sp-install --dev ...` (`releases/dev-v0.2.0-8-g73d9a9c`).
`bin/sp-install --ref <tag> <root>` installs another commit or tag with the installer you run, which is how an
older release is (re)installed with a current installer.

**A release directory named after a component tag** (`releases/collectors/codehost-gitea/v0.1.0`): the installer
shipped up to and including v0.2.0 named a release after whatever `git describe --tags` preferred, which on a
release commit is often a component tag created in the same second. Installing again with a current installer
fixes `current` and leaves the old directory alone (a tick may be running from it); it prints the command that
removes it:

```sh
cd ~/security-platform && git fetch --tags
git checkout v0.3.0 && bin/sp-install ~/.local/opt/security-platform              # or, to stay on v0.2.0:
# git checkout main && bin/sp-install --ref v0.2.0 ~/.local/opt/security-platform
#   installed v0.2.0 in ... (current -> releases/v0.2.0)
#   note: releases/collectors/codehost-gitea/v0.1.0 was named after a component tag by an older installer; ...
#         kept (it may still be in use); once nothing runs from it: rm -rf '.../releases/collectors/codehost-gitea/v0.1.0'
```

Remove it after the next tick ran from the new `current` (`tail $SP_DATA/state/runner/tick.log`). `tick.sh` enters
`current` by name, so it needs no change.

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

Release names are read from **product tags only** (`vMAJOR.MINOR.PATCH[-PRERELEASE]`, `cli/release.py`). Component
tags (`<component>/vX.Y.Z`) sit on the same commit and are never used as a release name, whatever their kind or
creation order, so the order in which the tags are created does not matter. Do not use `git describe --tags` to
name a release: it prefers annotated tags and then the newest one, which is usually a component tag.

For release `vX.Y.Z` (e.g. `v0.3.0`), on an up-to-date clone of `main`:

1. **Pull request "Release vX.Y.Z"**, merged after CI passed:
   - `CHANGELOG.md`: a section `## vX.Y.Z — <date>` listing every component version it contains (the table
     below prints them) and the upgrade actions collected from the sections since the previous release;
   - `docs/quickstart.md`: `git checkout vX.Y.Z`.
2. **Check** the merged commit (no tag yet):

   ```sh
   git switch main && git pull --ff-only && git fetch --tags
   python3 -m unittest discover -s tests && python3 generators/gen.py && git diff --exit-code dist/
   python3 cli/release.py; echo "exit $? (2 = no product tag yet: expected)"
   # component tags still to create: every <dir>/VERSION whose <dir>/v<VERSION> tag does not exist yet
   for f in $(git ls-files '*/VERSION'); do c=${f%/VERSION}; t="$c/v$(cat "$f")"
     git rev-parse -q --verify "refs/tags/$t" >/dev/null || echo "$t"; done
   ```

3. **Tag** (annotated) that commit: the product tag and the component tags listed above, then push the tags only:

   ```sh
   V=vX.Y.Z; C=$(git rev-parse HEAD)
   git tag -a "$V" -m "security-platform $V" "$C"
   for f in $(git ls-files '*/VERSION'); do c=${f%/VERSION}; t="$c/v$(cat "$f")"
     git rev-parse -q --verify "refs/tags/$t" >/dev/null || git tag -a "$t" -m "$t" "$C"; done
   test "$(python3 cli/release.py --ref "$V")" = "$V"                      # the name installers will use
   git push origin "$V" $(git tag --points-at "$C" | grep /)
   ```

4. **Verify** from the tag: `e2e/kind/run.sh --ref vX.Y.Z` passes (its `last-pass.json` records `installed: vX.Y.Z`),
   and a fresh `git clone` + `git checkout vX.Y.Z` + `bin/sp-install <scratch dir>` creates `releases/vX.Y.Z`.
5. **GitHub release** of the tag with the CHANGELOG section as notes (no environment data, ever).

A pre-release (`vX.Y.Z-rc.N`) goes the same way; installers pick the highest version when several product tags
point at one commit, and a release sorts above its pre-releases.
