"""Build a synthetic (environment-free) fixture for a collector with the SDK itself. Used to (re)generate
tests/fixtures/<collector>.findings.json; real findings never go into this repository."""
import json
import os
import sys
import tempfile

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.join(ROOT, "sdk"))
import spsdk  # noqa: E402

SAMPLES = {
    "exposure": ("network", "net-endpoint:host-a@192.0.2.10:9093", "alertmanager.unauth", "detection"),
    "host": ("identity", "host:host-a", "ssh.password_auth_enabled", "compliance"),
    "k8s": ("workload", "k8s-workload:cluster-a/ns/Deployment/app", "k8s.pod.privileged", "compliance"),
    "vuln-intel": ("supply-chain", "image:registry.example/app:1.0", "vuln.cve-2099-0001", "vulnerability"),
    "codehost-github": ("supply-chain", "repo:github/example/app", "repo.default_branch_unprotected", "compliance"),
    "secrets-files": ("data-secrets", "secret-file:host-a:~/.ssh/id_ed25519", "secret.ssh_key_no_passphrase", "compliance"),
    "agent-claude-code": ("ai-agents", "agent:claude-code:~/.claude/settings.json", "agent.reads_outside_workdir", "compliance"),
    "identity": ("identity", "identity:github/example-user", "identity.mfa_disabled", "compliance"),
}


def build(name):
    layer, asset, check, kind = SAMPLES[name]
    with tempfile.TemporaryDirectory() as d:
        os.environ["SP_RUN_DIR"] = d
        c = spsdk.Collector(name, open(os.path.join(ROOT, "collectors", name, "VERSION")).read().strip())
        c.ok(asset.split(":")[0] + ":example")
        c.gap("host:example-offline", "offline at scan time")
        extra = dict(cve="CVE-2099-0001", kev=True, epss=0.9, published_at="2099-01-01", alertable=True, exposed=False) if kind == "vulnerability" else {}
        c.finding(layer, asset, check, "synthetic example", "high", f"raw/{name}/example.json#x", "fix it", kind=kind, **extra)
        c.metric("security_example_metric", 1, "example", kind="x")
        c.write()
        return json.load(open(os.path.join(d, f"{name}.findings.json")))


if __name__ == "__main__":
    for n in sys.argv[1:] or SAMPLES:
        json.dump(build(n), open(os.path.join(ROOT, "tests", "fixtures", f"{n}.findings.json"), "w"), indent=1, sort_keys=True)
        print("wrote", n)
