"""Product release names come from product tags (vX.Y.Z) only: cli/release.py and bin/sp-install, on a temporary
repository whose release commit also carries component tags (annotated and lightweight, created before and after
the product tag) - the situation in which `git describe --tags` names a release after a component."""
import itertools
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path[:0] = [os.path.join(ROOT, "cli")]
import release  # noqa: E402

GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
COMPONENTS = ["collectors/codehost-gitea/v0.1.0", "core/v0.8.0", "runner/v0.9.0"]


def write(path, text=""):
    with open(path, "w") as f:
        f.write(text)


def git(repo, *args, date=None):
    env = dict(os.environ, **GIT_ENV)
    if date:
        env.update(GIT_COMMITTER_DATE=date, GIT_AUTHOR_DATE=date)
    return subprocess.run(["git", "-C", repo, *args], env=env, check=True, capture_output=True, text=True).stdout.strip()


def make_repo(tags, base=None):
    """A repository with the installer in it; `tags` = [(name, annotated)] in creation order, one second apart."""
    d = tempfile.mkdtemp()
    git(d, "init", "-q", "-b", "main")
    for rel in ("bin/sp-install", "cli/release.py"):
        os.makedirs(os.path.join(d, os.path.dirname(rel)), exist_ok=True)
        shutil.copy2(os.path.join(ROOT, rel), os.path.join(d, rel))
    if base:  # an older product release below the commit under test
        git(d, "add", "-A")
        git(d, "commit", "-q", "-m", "old", date="2026-01-01T00:00:00Z")
        git(d, "tag", "-a", base, "-m", base, date="2026-01-01T00:00:00Z")
        write(os.path.join(d, "NEW"), "x\n")
    git(d, "add", "-A")
    git(d, "commit", "-q", "-m", "release", date="2026-02-01T00:00:00Z")
    for i, (name, annotated) in enumerate(tags):
        when = f"2026-02-01T00:00:{i:02d}Z"
        git(d, "tag", *(["-a", "-m", name] if annotated else []), name, date=when)
    return d


class ReleaseName(unittest.TestCase):
    def test_product_tag_wins_whatever_order_and_kind(self):
        # product tag first/middle/last, annotated or lightweight; component tags annotated and lightweight
        for pos, prod_annotated, comp_annotated in itertools.product(range(len(COMPONENTS) + 1), (True, False),
                                                                    (True, False)):
            tags = [(c, comp_annotated if i % 2 == 0 else not comp_annotated) for i, c in enumerate(COMPONENTS)]
            tags.insert(pos, ("v0.3.0", prod_annotated))
            with self.subTest(tags=tags):
                d = make_repo(tags)
                try:
                    self.assertEqual(release.release_for(d), "v0.3.0")
                    self.assertEqual(release.release_for(d, dev=True), "v0.3.0")
                finally:
                    shutil.rmtree(d)

    def test_describe_alone_picks_a_component(self):
        """The bug being guarded against: the newest annotated tag on the commit is a component tag."""
        d = make_repo([("v0.3.0", True)] + [(c, True) for c in COMPONENTS])
        try:
            self.assertNotEqual(git(d, "describe", "--tags"), "v0.3.0")
            self.assertEqual(release.release_for(d), "v0.3.0")
        finally:
            shutil.rmtree(d)

    def test_highest_product_tag_and_prerelease_order(self):
        d = make_repo([("v0.3.0-rc.1", True), ("v0.3.0", False), ("v0.2.9", True), ("v0.10.0-rc.2", True),
                       ("v0.10.0-rc.10", True), ("vnext", False), ("x/v9.9.9", True)])
        try:
            self.assertEqual(release.release_for(d), "v0.10.0-rc.10")
            self.assertEqual(release.product_tags_at(d)[-1], "v0.2.9")
        finally:
            shutil.rmtree(d)

    def test_untagged_or_component_only_fails_clearly(self):
        for tags in ([], [(c, True) for c in COMPONENTS]):
            with self.subTest(tags=tags):
                d = make_repo(tags)
                try:
                    with self.assertRaisesRegex(release.NoProductTag, "no product tag"):
                        release.release_for(d)
                    self.assertRegex(release.release_for(d, dev=True), r"^dev-untagged-g[0-9a-f]{7}$")
                finally:
                    shutil.rmtree(d)

    def test_dev_name_counts_from_nearest_product_tag(self):
        d = make_repo([(c, True) for c in COMPONENTS], base="v0.2.0")
        try:
            name = release.release_for(d, dev=True)
            self.assertRegex(name, r"^dev-v0\.2\.0-1-g[0-9a-f]{7}$")
            self.assertFalse(release.is_product_tag(name))
        finally:
            shutil.rmtree(d)

    def test_installed_tree_reports_its_release_file(self):
        d = tempfile.mkdtemp()
        try:
            self.assertEqual(release.describe_tree(d), "unknown")
            write(os.path.join(d, "RELEASE"), "version=v0.3.0\ncommit=abc\n")
            self.assertEqual(release.describe_tree(d), "v0.3.0")
        finally:
            shutil.rmtree(d)


class Installer(unittest.TestCase):
    def setUp(self):
        self.dest = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.dest)

    def install(self, repo, *args):
        return subprocess.run([os.path.join(repo, "bin", "sp-install"), *args, self.dest],
                              capture_output=True, text=True)

    def test_installs_under_the_product_version_and_migrates_a_component_named_release(self):
        d = make_repo([("v0.3.0", True)] + [(c, i % 2 == 0) for i, c in enumerate(COMPONENTS)])
        try:
            # what an older installer left behind: current -> a release named after a component tag
            wrong = os.path.join(self.dest, "releases", "collectors", "codehost-gitea", "v0.1.0")
            os.makedirs(os.path.join(wrong, "bin"))
            write(os.path.join(wrong, "bin", "sp-install"))
            os.symlink("releases/collectors/codehost-gitea/v0.1.0", os.path.join(self.dest, "current"))
            r = self.install(d)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(os.readlink(os.path.join(self.dest, "current")), "releases/v0.3.0")
            with open(os.path.join(self.dest, "current", "RELEASE")) as f:
                rel = f.read()
            self.assertIn("version=v0.3.0\n", rel)
            self.assertIn(f"commit={git(d, 'rev-parse', 'HEAD')}\n", rel)
            self.assertTrue(os.path.isfile(os.path.join(self.dest, "current", "cli", "release.py")))
            self.assertTrue(os.path.isdir(wrong), "the old release must never be deleted automatically")
            self.assertIn("previous current -> releases/collectors/codehost-gitea/v0.1.0", r.stdout)
            self.assertIn(f"rm -rf '{self.dest}/releases/collectors/codehost-gitea/v0.1.0'", r.stdout)
            # a correct install reports nothing to clean up once the old directory is gone
            shutil.rmtree(os.path.join(self.dest, "releases", "collectors"))
            r = self.install(d)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("note:", r.stdout)
        finally:
            shutil.rmtree(d)

    def test_untagged_commit_is_refused_unless_dev(self):
        d = make_repo([(c, True) for c in COMPONENTS], base="v0.2.0")
        try:
            r = self.install(d)
            self.assertEqual(r.returncode, 2)
            self.assertIn("no product tag", r.stderr)
            self.assertFalse(os.path.lexists(os.path.join(self.dest, "current")))
            r = self.install(d, "--dev")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertRegex(os.readlink(os.path.join(self.dest, "current")), r"^releases/dev-v0\.2\.0-1-g[0-9a-f]{7}$")
            # --ref installs an older release with this installer
            r = self.install(d, "--ref", "v0.2.0")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(os.readlink(os.path.join(self.dest, "current")), "releases/v0.2.0")
            self.assertFalse(os.path.exists(os.path.join(self.dest, "current", "NEW")))
        finally:
            shutil.rmtree(d)


if __name__ == "__main__":
    unittest.main()
