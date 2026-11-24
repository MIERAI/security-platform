"""Minimal Kubernetes API access for the spool and sink adapters (stdlib only: a site such as a phone has python3
but no kubectl). Two transports, chosen by the config:

  {server: https://host:6443, token_file: F, ca_file: F}   HTTPS with a bearer token (mode 0600 file; e.g. a bound
                                                           ServiceAccount token from `kubectl create token`)
  {kubeconfig: "in-cluster"} or nothing, inside a pod       the pod's ServiceAccount (token re-read per request)
  {kubeconfig: F, context?: C}                              kubectl with that kubeconfig (operator workstations)

  client(cfg) -> Client: request(method, path, body=None, query=None) -> dict ; namespace -> str
Errors raise KubeError(status, reason); the token is never logged.
"""
import json
import os
import ssl
import subprocess
import urllib.error
import urllib.parse
import urllib.request

VERSION = "0.1.0"
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


class KubeError(RuntimeError):
    def __init__(self, status, reason):
        super().__init__(f"kubernetes API {status}: {reason}")
        self.status = status


def _secret(path, check_mode=True):
    from . import sinks
    return sinks.read_secret_file(path) if check_mode else open(path).read().strip()


class HTTP:
    def __init__(self, server, token_file, ca_file=None, namespace=None, check_mode=True):
        self.server, self.token_file, self.check_mode = server.rstrip("/"), os.path.expanduser(token_file), check_mode
        self.ctx = ssl.create_default_context(cafile=os.path.expanduser(ca_file)) if ca_file else ssl.create_default_context()
        self.namespace = namespace

    def request(self, method, path, body=None, query=None, timeout=60):
        url = self.server + path + ("?" + urllib.parse.urlencode(query) if query else "")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers={
            "Authorization": "Bearer " + _secret(self.token_file, self.check_mode), "Accept": "application/json",
            "Content-Type": "application/apply-patch+yaml" if method == "PATCH" else "application/json",
            "User-Agent": "security-platform-runner"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=self.ctx if url.startswith("https") else None) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:   # never echo the request (it carries the token)
            try:
                reason = json.loads(e.read()).get("message", e.reason)
            except ValueError:
                reason = e.reason
            raise KubeError(e.code, str(reason)[:200]) from None
        return json.loads(raw) if raw else {}


class Kubectl:
    """The same REST calls through `kubectl` (uses the kubeconfig's own auth: exec plugins, client certs...)."""
    def __init__(self, kubeconfig=None, context=None, namespace=None):
        self.kc = ["kubectl"] + (["--kubeconfig", os.path.expanduser(kubeconfig)] if kubeconfig else []) + \
            (["--context", context] if context else [])
        self.namespace = namespace

    def request(self, method, path, body=None, query=None, timeout=60):
        url = path + ("?" + urllib.parse.urlencode(query) if query else "")
        if method == "GET":
            args = ["get", "--raw", url]
        elif method == "DELETE":
            args = ["delete", "--raw", url]
        elif method == "POST":
            args = ["create", "--raw", url, "-f", "-"]
        elif method == "PATCH":   # server-side apply of a whole object
            args = ["apply", "--server-side", "--force-conflicts", "--field-manager=security-platform-runner", "-o", "json", "-f", "-"]
        else:
            raise ValueError(method)
        p = subprocess.run(self.kc + args, input=json.dumps(body) if body is not None else None,
                           capture_output=True, text=True, timeout=timeout)
        if p.returncode != 0:
            err = p.stderr.strip()
            status = 404 if "NotFound" in err or "not found" in err else 409 if "AlreadyExists" in err else 500
            raise KubeError(status, err[-200:])
        return json.loads(p.stdout) if p.stdout.strip() else {}


def in_cluster():
    return os.path.exists(os.path.join(SA_DIR, "token")) and os.environ.get("KUBERNETES_SERVICE_HOST")


def client(cfg):
    ns = cfg.get("namespace")
    if cfg.get("server"):
        if not cfg.get("token_file"):
            raise ValueError("kubernetes API: server needs token_file (and ca_file)")
        return HTTP(cfg["server"], cfg["token_file"], cfg.get("ca_file"), ns)
    if cfg.get("kubeconfig") in (None, "", "in-cluster") and in_cluster():
        host, port = os.environ["KUBERNETES_SERVICE_HOST"], os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if not ns:
            ns = open(os.path.join(SA_DIR, "namespace")).read().strip()
        return HTTP(f"https://{host}:{port}" if ":" not in host else f"https://[{host}]:{port}",
                    os.path.join(SA_DIR, "token"), os.path.join(SA_DIR, "ca.crt"), ns, check_mode=False)
    kc = cfg.get("kubeconfig")
    return Kubectl(None if kc == "in-cluster" else kc, cfg.get("context"), ns)
