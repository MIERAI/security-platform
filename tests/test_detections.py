"""Contract tests for the detection content (component `detections`): the catalog is complete and routable, every rule
has a runbook, the generated rule files are current, the Falco rules keep the tag-based selection model, and the
audit policy never logs Secret bodies."""
import importlib.util
import os
import re
import tempfile
import unittest

import yaml

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
# loaded under its own name: deploy/render.py is another module called `render`
_spec = importlib.util.spec_from_file_location("detections_render", os.path.join(ROOT, "detections", "render.py"))
render = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(render)

CAT = render.load()


class Catalog(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(render.validate(CAT), [])

    def test_generated_files_current(self):
        self.assertEqual(render.main(["--check"]), 0, "run detections/render.py and commit the result")

    def test_required_coverage(self):
        """The minimum set a detection programme for a cluster + hosts + SaaS control planes must have."""
        ids = {r["id"] for r in CAT["rules"]}
        for need in ("falco-shell-in-container", "falco-unexpected-outbound", "falco-sensitive-file-read",
                     "falco-privilege-escalation", "falco-crypto-miner", "falco-write-below-etc",
                     "k8s-pod-exec", "k8s-secret-read-unexpected", "k8s-rbac-changed", "k8s-clusterrolebinding-created",
                     "k8s-anonymous-access", "auth-ssh-failed-burst", "auth-ssh-login-new-source",
                     "auth-authorized-keys-changed", "auth-sudo-unexpected-user", "codehost-credential-added",
                     "codehost-repo-made-public", "overlay-network-change"):
            self.assertIn(need, ids)

    def test_every_rule_has_attack_and_at_least_one_drill(self):
        for r in CAT["rules"]:
            self.assertTrue(r.get("attack"), r["id"])
            for t in r["attack"]:
                self.assertRegex(t, r"^T\d{4}(\.\d{3})?$", r["id"])
        self.assertTrue(any(r.get("drill") for r in CAT["rules"]))

    def test_rendered_rules_are_routable(self):
        doc = render.loki_rules(CAT)
        for g in doc["groups"]:
            for r in g["rules"]:
                self.assertIn(r["labels"]["severity"], render.SEVERITIES)
                self.assertEqual(r["labels"]["component"], "security-detection")
                self.assertTrue(r["annotations"]["runbook_url"].endswith(".md"))
                self.assertIsNone(re.search(r"\$[a-z_]", r["expr"]), f"{r['alert']}: unsubstituted parameter")

    def test_params_override(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump({"sudo_users": "admin|ops", "audit_clusters": ["c1", "c2"]}, f)
        cat = render.load(f.name)
        os.unlink(f.name)
        exprs = [r["expr"] for g in render.loki_rules(cat)["groups"] for r in g["rules"]]
        self.assertTrue(any('user!~"admin|ops"' in e for e in exprs))
        self.assertEqual(sum('absent_over_time({source="k8s-audit", cluster=' in e for e in exprs), 2)

    def test_unknown_param_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as f:
            yaml.safe_dump({"no_such_param": 1}, f)
        with self.assertRaises(SystemExit):
            render.load(f.name)
        os.unlink(f.name)

    def test_no_instance_values(self):
        """Product defaults stay generic: no tailnet or LAN host addresses, only network ranges."""
        with open(os.path.join(ROOT, "detections", "catalog.yaml")) as f:
            text = f.read()
        for ip in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d+)?", text):
            self.assertIn("/", ip, f"host address in the catalog: {ip}")


class FalcoRules(unittest.TestCase):
    RULES = yaml.safe_load(open(os.path.join(ROOT, "detections", "falco", "security-platform.rules.yaml")))

    def test_selection_by_tag(self):
        for item in self.RULES:
            if "rule" in item:
                self.assertIn("security-platform", item.get("tags", []), item["rule"])

    def test_catalog_names_exist(self):
        """Every Falco rule name a catalog query filters on is ours or a tagged upstream rule (no silent typo)."""
        names = {i["rule"] for i in self.RULES if "rule" in i}
        for r in CAT["rules"]:
            if r["source"] != "falco":
                continue
            m = re.search(r'\| rule=~?"([^"]+)"', r["query"])
            self.assertTrue(m, r["id"])
            for n in m.group(1).split("|"):
                self.assertIn(n, names, f"{r['id']}: {n}")

    def test_own_rules_do_not_use_upstream_macros(self):
        own = [i for i in self.RULES if "rule" in i and "condition" in i]
        self.assertTrue(own)
        for i in own:
            self.assertTrue(i["rule"].startswith("SP "), i["rule"])
            for word in ("spawned_process", "open_write", "open_read", "container_entrypoint"):
                self.assertNotRegex(i["condition"], rf"(?<![\w.]){word}(?![\w.])", i["rule"])


class AuditPolicy(unittest.TestCase):
    POLICY = yaml.safe_load(open(os.path.join(ROOT, "detections", "k8s-audit", "policy.yaml")))

    def first_match(self, group, resource, verb, user="alice", groups=("system:authenticated",)):
        for rule in self.POLICY["rules"]:
            if rule.get("nonResourceURLs"):
                continue
            if rule.get("users") and user not in rule["users"]:
                continue
            if rule.get("userGroups") and not set(rule["userGroups"]) & set(groups):
                continue
            if rule.get("verbs") and verb not in rule["verbs"]:
                continue
            if rule.get("resources"):
                hit = False
                for r in rule["resources"]:
                    if r.get("group", "") != group:
                        continue
                    if not r.get("resources") or resource in r["resources"]:
                        hit = True
                if not hit:
                    continue
            return rule["level"]
        return None

    def test_secret_bodies_never_logged(self):
        for verb in ("get", "list", "create", "update", "patch", "delete"):
            self.assertIn(self.first_match("", "secrets", verb), ("Metadata", "None"), verb)
            self.assertIn(self.first_match("", "configmaps", verb), ("Metadata", "None"), verb)

    def test_detection_inputs_logged(self):
        self.assertEqual(self.first_match("", "pods/exec", "create"), "Request")
        self.assertEqual(self.first_match("", "pods/exec", "get"), "Request")
        self.assertEqual(self.first_match("rbac.authorization.k8s.io", "clusterrolebindings", "create"), "Request")
        self.assertEqual(self.first_match("", "secrets", "get"), "Metadata")
        self.assertEqual(self.first_match("", "pods", "list", user="system:anonymous", groups=("system:unauthenticated",)), "Metadata")
        self.assertEqual(self.first_match("", "secrets", "get", user="system:serviceaccount:x:y", groups=("system:serviceaccounts",)), "Metadata")

    def test_access_reviews(self):
        sa = dict(user="system:serviceaccount:policy:cleanup-controller", groups=("system:serviceaccounts", "system:authenticated"))
        for r in ("selfsubjectaccessreviews", "subjectaccessreviews", "localsubjectaccessreviews", "selfsubjectrulesreviews"):
            self.assertEqual(self.first_match("authorization.k8s.io", r, "create", **sa), "None", r)   # controllers: noise
            self.assertEqual(self.first_match("authorization.k8s.io", r, "create"), "Metadata", r)     # a person: recon
        # the exemption is narrow: nothing else a service account creates is dropped
        self.assertEqual(self.first_match("authentication.k8s.io", "tokenreviews", "create", **sa), "Metadata")
        self.assertEqual(self.first_match("", "serviceaccounts/token", "create", **sa), "Request")
        self.assertEqual(self.first_match("", "pods/exec", "create", **sa), "Request")
        self.assertEqual(self.first_match("", "secrets", "create", **sa), "Metadata")
        self.assertEqual(self.first_match("", "pods", "create", **sa), "Metadata")
        self.assertEqual(self.first_match("rbac.authorization.k8s.io", "clusterrolebindings", "create", **sa), "Request")
        self.assertEqual(self.first_match("authorization.k8s.io", "selfsubjectaccessreviews", "create",
                                          user="system:anonymous", groups=("system:unauthenticated",)), "Metadata")


if __name__ == "__main__":
    unittest.main()
