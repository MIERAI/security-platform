"""exec adapter interface: run a READ-ONLY script on a target, non-interactively.

  executor(cfg).run(script, args=(), stdin=None, timeout=...) -> (rc, out, err)

cfg examples (instance config):  {type: local}   {type: ssh, host: <ssh alias>, options: [...]}
Rules: never prompt. A password prompt is a failure (BatchMode), recorded by the collector as a coverage gap.
Future adapters (interface only): ssm (AWS Systems Manager RunCommand), osquery (SQL), edr (vendor API).
"""
import shlex
import subprocess

VERSION = "0.1.0"


def _run(cmd, stdin=None, timeout=120):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, input=stdin,
                           errors="replace")
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


class Local:
    def __init__(self, cfg):
        self.cfg = cfg

    def run(self, argv, stdin=None, timeout=120):
        return _run(argv, stdin, timeout)


class SSH:
    BASE = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes"]

    def __init__(self, cfg):
        self.cfg = cfg

    def run(self, argv, stdin=None, timeout=120):
        cmd = ["ssh"] + self.BASE + list(self.cfg.get("options", [])) + [self.cfg["host"],
                                                                        " ".join(shlex.quote(a) for a in argv)]
        return _run(cmd, stdin, timeout)


class NotImplementedAdapter:
    def __init__(self, cfg):
        raise NotImplementedError(f"exec adapter {cfg.get('type')!r} is a documented future adapter")


ADAPTERS = {"local": Local, "ssh": SSH, "ssm": NotImplementedAdapter, "osquery": NotImplementedAdapter}


def executor(cfg):
    return ADAPTERS[cfg.get("type", "local")](cfg)
