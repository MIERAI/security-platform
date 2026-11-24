"""exec adapter interface: run a READ-ONLY script on a target, non-interactively.

  executor(cfg).run(script, args=(), stdin=None, timeout=...) -> (rc, out, err)

cfg examples (instance config):  {type: local}   {type: ssh, host: <ssh alias>, options: [...], shell: posix|windows}
`shell: windows` = the remote login shell is cmd.exe (Windows OpenSSH default): argv is quoted with the Windows
rules (subprocess.list2cmdline) instead of POSIX ones.
`powershell(executor, script)` runs a PowerShell script of ANY length: a short -EncodedCommand bootstrap reads the
script from stdin (cmd.exe caps a command line at 8191 characters and silently drops longer ones).
Rules: never prompt. A password prompt is a failure (BatchMode), recorded by the collector as a coverage gap.
Future adapters (interface only): ssm (AWS Systems Manager RunCommand), osquery (SQL), edr (vendor API).
"""
import shlex
import subprocess

VERSION = "0.2.0"


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
        remote = subprocess.list2cmdline(argv) if self.cfg.get("shell") == "windows" else \
            " ".join(shlex.quote(a) for a in argv)
        cmd = ["ssh"] + self.BASE + list(self.cfg.get("options", [])) + [self.cfg["host"], remote]
        return _run(cmd, stdin, timeout)


class NotImplementedAdapter:
    def __init__(self, cfg):
        raise NotImplementedError(f"exec adapter {cfg.get('type')!r} is a documented future adapter")


ADAPTERS = {"local": Local, "ssh": SSH, "ssm": NotImplementedAdapter, "osquery": NotImplementedAdapter}


# Reads the whole script from stdin and runs it; UTF-8 output so non-ASCII names (e.g. installed programs) survive.
PS_BOOTSTRAP = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ProgressPreference='SilentlyContinue';"
                "$s=@($input) -join [char]10;Invoke-Expression $s")


def powershell(e, script, timeout=180):
    """Run a PowerShell script (ASCII source) through any executor whose target has powershell.exe."""
    import base64
    b64 = base64.b64encode(PS_BOOTSTRAP.encode("utf-16-le")).decode()
    return e.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", b64], stdin=script, timeout=timeout)


def executor(cfg):
    return ADAPTERS[cfg.get("type", "local")](cfg)
