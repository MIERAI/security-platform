"""Several installations in one cluster: the cluster-scoped objects of the hub (deploy/kubernetes/hub) and of an
in-cluster site (deploy/kubernetes/cronjob) get unique names through the `unique-names` component, references
(roleRef, policyName) follow, and a combined render of several environments has no colliding cluster-scoped name.
Rendering needs kustomize (`kustomize` or `kubectl kustomize`); CI has it, a workstation without it skips."""
import os
import shutil
import subprocess
import tempfile
import unittest

ROOT = os.path.realpath(os.path.join(os.path.dirname(__file__), ".."))   # realpath: relative paths across symlinks
K8S = os.path.join(ROOT, "deploy", "kubernetes")
CLUSTER_SCOPED = {"ClusterRole", "ClusterRoleBinding", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding",
                  "MutatingAdmissionPolicy", "MutatingAdmissionPolicyBinding", "ValidatingWebhookConfiguration",
                  "MutatingWebhookConfiguration", "Namespace", "CustomResourceDefinition", "PersistentVolume",
                  "StorageClass", "PriorityClass", "IngressClass", "RuntimeClass"}


def kustomize():
    if shutil.which("kustomize"):
        return ["kustomize", "build"]
    if shutil.which("kubectl"):
        return ["kubectl", "kustomize"]
    return None


class UniqueNames(unittest.TestCase):
    def setUp(self):
        self.d = os.path.realpath(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.d)

    def test_component_covers_every_cluster_scoped_object(self):
        """A cluster-scoped object added later must also get a unique name (static: no kustomize needed)."""
        import yaml
        comp = yaml.safe_load(open(os.path.join(K8S, "unique-names", "kustomization.yaml")))
        targets = {(t["select"]["kind"], t["select"]["name"]) for r in comp["replacements"] for t in r["targets"]}
        for base in ("hub", "cronjob"):
            kust = yaml.safe_load(open(os.path.join(K8S, base, "kustomization.yaml")))
            for f in kust["resources"]:
                for doc in yaml.safe_load_all(open(os.path.join(K8S, base, f))):
                    if doc and doc["kind"] in CLUSTER_SCOPED:
                        self.assertIn((doc["kind"], doc["metadata"]["name"]), targets, f"{base}/{f}")

    def render(self, name, base, namespace, installation=None):
        cmd = kustomize()
        if cmd is None:
            if os.environ.get("CI"):
                self.fail("kustomize (or kubectl) is required in CI")
            self.skipTest("kustomize/kubectl not installed")
        d = os.path.join(self.d, name)
        os.makedirs(d)
        rel = lambda p: os.path.relpath(p, d)  # noqa: E731  (kustomize refuses absolute paths)
        lines = [f"namespace: {namespace}", f"resources: [{rel(os.path.join(K8S, base))}]"]
        if installation:
            lines += [f"components: [{rel(os.path.join(K8S, 'unique-names'))}]", "configMapGenerator:",
                      f"  - {{ name: security-platform-installation, literals: [name={installation}],"
                      " options: { disableNameSuffixHash: true } }"]
        with open(os.path.join(d, "kustomization.yaml"), "w") as f:
            f.write("\n".join(lines) + "\n")
        p = subprocess.run(cmd + [d], capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr)
        import yaml
        return [x for x in yaml.safe_load_all(p.stdout) if x]

    def test_single_install_keeps_its_names(self):
        names = {(o["kind"], o["metadata"]["name"]) for o in self.render("one", "hub", "security") if o["kind"] in CLUSTER_SCOPED}
        self.assertEqual(names, {("ClusterRole", "security-platform-hub-read"), ("ClusterRoleBinding", "security-platform-hub-read"),
                                 ("ValidatingAdmissionPolicy", "security-platform-inbox-identity"),
                                 ("ValidatingAdmissionPolicyBinding", "security-platform-inbox-identity")})

    def test_two_environments_side_by_side(self):
        objs = []
        for env in ("staging", "prod"):
            for base in ("hub", "cronjob"):
                ns_ = f"security-{env}" + ("" if base == "hub" else "-site")
                rendered = self.render(f"{base}-{env}", base, ns_, env + ("" if base == "hub" else "-site"))
                objs += rendered
                cs = {(o["kind"], o["metadata"]["name"]): o for o in rendered if o["kind"] in CLUSTER_SCOPED}
                self.assertTrue(cs)
                for (kind, name), o in cs.items():
                    self.assertTrue(name.endswith("-" + ns_.removeprefix("security-")), name)
                    if kind == "ClusterRoleBinding":    # references follow, subjects are in this installation
                        self.assertIn(("ClusterRole", o["roleRef"]["name"]), cs)
                        self.assertEqual({s["namespace"] for s in o["subjects"]}, {ns_})
                    if kind == "ValidatingAdmissionPolicyBinding":
                        self.assertIn(("ValidatingAdmissionPolicy", o["spec"]["policyName"]), cs)
                # namespaced objects keep the names the code and the inbox policy rely on
                ns = {o["metadata"]["name"] for o in rendered if o["kind"] not in CLUSTER_SCOPED}
                self.assertIn("security-platform-" + ("hub" if base == "hub" else "site"), ns)
        cluster = [(o["kind"], o["metadata"]["name"]) for o in objs if o["kind"] in CLUSTER_SCOPED]
        self.assertEqual(len(cluster), len(set(cluster)), sorted(cluster))
        namespaced = [(o["kind"], o["metadata"].get("namespace"), o["metadata"]["name"]) for o in objs
                      if o["kind"] not in CLUSTER_SCOPED]
        self.assertEqual(len(namespaced), len(set(namespaced)))

    def test_component_without_installation_name_fails(self):
        cmd = kustomize()
        if cmd is None:
            self.skipTest("kustomize/kubectl not installed")
        d = os.path.join(self.d, "broken")
        os.makedirs(d)
        with open(os.path.join(d, "kustomization.yaml"), "w") as f:
            f.write(f"namespace: x\nresources: [{os.path.relpath(os.path.join(K8S, 'hub'), d)}]\n"
                    f"components: [{os.path.relpath(os.path.join(K8S, 'unique-names'), d)}]\n")
        p = subprocess.run(cmd + [d], capture_output=True, text=True, timeout=120)
        self.assertNotEqual(p.returncode, 0)          # never silently the shared names


if __name__ == "__main__":
    unittest.main()
