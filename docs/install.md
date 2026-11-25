# Installing the sp binary and verifying it

From the first release that carries them, every product release `vX.Y.Z` on GitHub comes with a single `sp`
binary per platform. During the move to Go (docs/go.md) the binary runs the subcommands that have a Go
implementation and hands every other one to the Python tree of the same release, so you still install that tree
(docs/quickstart.md, step 1, or `bin/sp-install`, docs/upgrade.md). Until then, the `bin/sp` script of the tree
does the same job without a binary.

**Verify before you run it.** This is a security tool with read access to your systems: check that the binary
was built by this repository's release workflow from the tagged commit, not just that it downloaded completely.

## What a release contains

| asset | what it is |
|---|---|
| `sp-vX.Y.Z-linux-amd64`, `-linux-arm64` | Linux, statically linked |
| `sp-vX.Y.Z-darwin-arm64`, `-darwin-amd64` | macOS (Apple silicon, Intel) |
| `sp-vX.Y.Z-windows-amd64.exe` | Windows |
| `sp-vX.Y.Z-android-arm64` | Android / Termux (no cgo; linked against Android's system linker, as Android requires) |
| `SHA256SUMS` | SHA-256 of every binary |
| `SHA256SUMS.sigstore.json` | keyless [Sigstore](https://www.sigstore.dev/) signature of `SHA256SUMS` (cosign bundle) |
| `sp-vX.Y.Z.spdx.json` | SBOM (SPDX) of the binaries |

GitHub also keeps, for every binary, a signed [SLSA](https://slsa.dev/) build provenance attestation (which
workflow, which commit, which runner built it) and an SBOM attestation.

## Download and verify

```sh
V=vX.Y.Z; P=linux-amd64                        # darwin-arm64, windows-amd64.exe, android-arm64, ...
base=https://github.com/MIERAI/security-platform/releases/download/$V
curl -fsSLO "$base/sp-$V-$P" -O "$base/SHA256SUMS" -O "$base/SHA256SUMS.sigstore.json"
```

**1. The checksum list is signed by the release workflow of this repository, for this tag**
([cosign](https://docs.sigstore.dev/cosign/system_config/installation/) 2.4 or newer):

```sh
cosign verify-blob SHA256SUMS \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-identity "https://github.com/MIERAI/security-platform/.github/workflows/release.yml@refs/tags/$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

**2. The binary is the one in the signed list:**

```sh
sha256sum --ignore-missing -c SHA256SUMS        # macOS: shasum -a 256 --ignore-missing -c SHA256SUMS
```

**3. Build provenance** (independent of steps 1-2; needs the [GitHub CLI](https://cli.github.com/)):

```sh
gh attestation verify "sp-$V-$P" --repo MIERAI/security-platform \
  --signer-workflow MIERAI/security-platform/.github/workflows/release.yml \
  --source-ref "refs/tags/$V" --deny-self-hosted-runners
# the SBOM attestation of the same binary
gh attestation verify "sp-$V-$P" --repo MIERAI/security-platform \
  --signer-workflow MIERAI/security-platform/.github/workflows/release.yml \
  --predicate-type https://spdx.dev/Document/v2.3
```

Any failure: do not run the binary, and report it (SECURITY.md).

## Install

```sh
install -m 0755 "sp-$V-$P" ~/bin/sp            # or anywhere on PATH
sp --version                                    # sp <cli version> (security-platform vX.Y.Z), then the details
sp version --json                               # which components run in Go, which in Python
```

The binary finds the Python tree in this order: `$SP_PY_HOME`; the tree it sits in (`<tree>/bin/sp`); the
default install root `~/.local/opt/security-platform/current` that `bin/sp-install` creates. The interpreter is
`$SP_PYTHON`, else `python3` on `PATH` (put the platform's virtual environment first, as in the quick start).
`sp version` warns when the binary and the Python tree are different releases: install both from the same tag.

## Rebuild it yourself (reproducible builds)

The binaries are reproducible: the same tag and Go toolchain give byte-identical files on any machine (no cgo,
`-trimpath`, no build id; the release workflow checks this by building on Linux and macOS and comparing).
With the Go version named by the `toolchain` line of `go.mod`:

```sh
git clone https://github.com/MIERAI/security-platform.git && cd security-platform && git checkout "$V"
scripts/build-release.sh "$V" /tmp/sp-rebuild
diff /tmp/sp-rebuild/SHA256SUMS /path/to/downloaded/SHA256SUMS && echo identical
```

## Container image

The runner image (`Dockerfile`) carries the same `sp` binary at `/usr/local/bin/sp` next to the Python
implementation, and records the product release it was built from in `/opt/security-platform/RELEASE` (reported
as `security_runner_info{release=...}` and by `sp version`). Images are signed keylessly by the image workflow
(`.github/workflows/image.yml`).
