#!/usr/bin/env python3
"""release: the product version of a commit, from product tags only (component `cli`, see cli/VERSION). Stdlib only.

The repository carries two kinds of tags, often on the same commit:
  product    vMAJOR.MINOR.PATCH[-PRERELEASE]   e.g. v0.3.0, v0.3.0-rc.1   (what is installed and released)
  component  <component>/vX.Y.Z                 e.g. collectors/host/v0.2.0, core/v0.8.0
`git describe --tags` picks whichever tag it prefers (annotated before lightweight, then the newest), so it can name a
product release after a component. Everything that needs the product version asks this module instead:

  release_for(repo, ref)            -> "v0.3.0"  the highest product tag pointing at exactly that commit;
                                       raises NoProductTag when there is none (never another tag, never a hash)
  release_for(repo, ref, dev=True)  -> the product tag if there is one, else an explicit development name
                                       "dev-v0.2.0-8-g73d9a9c" (nearest product tag below, commits since, commit)
  installed_release(tree)           -> {"version", "commit"} from the RELEASE file bin/sp-install writes, or None

Command line (used by bin/sp-install and the e2e tests):
  python3 cli/release.py [--repo DIR] [--ref REF] [--dev]     prints the name; exit 2 with a reason when untagged
"""
import argparse
import os
import re
import subprocess
import sys

PRODUCT_TAG = re.compile(r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$")
RELEASE_FILE = "RELEASE"


class NoProductTag(Exception):
    pass


def is_product_tag(name):
    return bool(PRODUCT_TAG.match(name or ""))


def semver_key(tag):
    """Sort key of a product tag by semantic version precedence (a pre-release sorts before its release)."""
    m = PRODUCT_TAG.match(tag)
    core = tuple(int(m.group(i)) for i in (1, 2, 3))
    if m.group(4) is None:
        return core + (1, ())
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in m.group(4).split("."))
    return core + (0, ids)


def _git(repo, *args):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {r.stderr.strip() or 'failed'}")
    return r.stdout


def commit_of(repo, ref="HEAD"):
    return _git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}").strip()


def product_tags_at(repo, ref="HEAD"):
    """Product tags (annotated or lightweight) whose commit is exactly `ref`, highest version first."""
    tags = _git(repo, "tag", "--points-at", commit_of(repo, ref)).split()
    return sorted((t for t in tags if is_product_tag(t)), key=semver_key, reverse=True)


def dev_name(repo, ref="HEAD"):
    """dev-<nearest product tag below ref>-<commits since>-g<commit>; dev-untagged-g<commit> without one."""
    sha = commit_of(repo, ref)
    short = _git(repo, "rev-parse", "--short=7", sha).strip()
    below = [t for t in _git(repo, "tag", "--merged", sha).split() if is_product_tag(t)]
    if not below:
        return f"dev-untagged-g{short}"
    base = max(below, key=semver_key)
    n = _git(repo, "rev-list", "--count", f"{base}..{sha}").strip()
    return f"dev-{base}-{n}-g{short}"


def release_for(repo, ref="HEAD", dev=False):
    tags = product_tags_at(repo, ref)
    if tags:
        return tags[0]
    if dev:
        return dev_name(repo, ref)
    sha = commit_of(repo, ref)
    others = _git(repo, "tag", "--points-at", sha).split()
    hint = f" (it has only component tags: {', '.join(sorted(others))})" if others else ""
    raise NoProductTag(f"{ref} ({sha[:7]}) has no product tag vX.Y.Z{hint}. Check out a release "
                       f"(`git tag --list 'v*'`), or name it explicitly as a development build (--dev).")


def installed_release(tree):
    """The RELEASE file of an installed tree: {"version": ..., "commit": ...}, or None (a git checkout, an image)."""
    try:
        with open(os.path.join(tree, RELEASE_FILE)) as f:
            kv = dict(line.strip().split("=", 1) for line in f if "=" in line)
    except OSError:
        return None
    return kv if kv.get("version") else None


def describe_tree(tree):
    """Best-effort product version of a tree for display (`sp --version`): never raises."""
    rel = installed_release(tree)
    if rel:
        return rel["version"]
    try:
        if os.path.exists(os.path.join(tree, ".git")):
            return release_for(tree, "HEAD", dev=True)
    except (RuntimeError, OSError):
        pass
    return "unknown"


def main(argv=None):
    ap = argparse.ArgumentParser(prog="release.py", description="product version of a commit (product tags only)")
    ap.add_argument("--repo", default=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    ap.add_argument("--ref", default="HEAD")
    ap.add_argument("--dev", action="store_true", help="name an untagged commit dev-... instead of failing")
    a = ap.parse_args(argv)
    try:
        print(release_for(a.repo, a.ref, dev=a.dev))
    except NoProductTag as e:
        print(f"release.py: {e}", file=sys.stderr)
        return 2
    except RuntimeError as e:
        print(f"release.py: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
