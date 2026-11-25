"""exec adapter interface: run a READ-ONLY script on a target, non-interactively.

  executor(cfg).run(argv, stdin=None, timeout=..., partial=False) -> (rc, out, err)

On timeout rc is 124 and err "timeout"; out is "" unless `partial=True`, then it is what the script printed before
it was stopped (for scripts whose lines are independent, e.g. host probes; never for a listing that must be complete).

cfg examples (instance config):  {type: local}   {type: ssh, host: <ssh alias>, options: [...], shell: posix|windows}
`shell: windows` = the remote login shell is cmd.exe (Windows OpenSSH default): argv is quoted with the Windows
rules (subprocess.list2cmdline) instead of POSIX ones.
`powershell(executor, script)` runs a PowerShell script of ANY length: a short -EncodedCommand bootstrap reads the
script from stdin (cmd.exe caps a command line at 8191 characters and silently drops longer ones).
Rules: never prompt. A password prompt is a failure (BatchMode), recorded by the collector as a coverage gap.
Future adapters (interface only): ssm (AWS Systems Manager RunCommand), osquery (SQL), edr (vendor API).
"""
import os
import shlex
import signal
import subprocess

VERSION = "0.3.0"


def _run(cmd, stdin=None, timeout=120, partial=False):
    # own session: on timeout the whole process group is stopped, not only the direct child (a local profile script's
    # children would otherwise keep running, and keep the output pipe open)
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin is not None else subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, errors="replace", start_new_session=True)
    try:
        out, err = p.communicate(stdin, timeout=timeout)
        return p.returncode, out, err
    except subprocess.TimeoutExpired as e:
        _stop(p)
        try:
            out, _ = p.communicate(timeout=5)   # everything read so far, plus what was still in the pipe
        except subprocess.TimeoutExpired:       # a detached grandchild holds the pipe: keep what was read before
            out = e.output.decode(errors="replace") if isinstance(e.output, bytes) else (e.output or "")
        return 124, out if partial else "", "timeout"


def _stop(p):
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except (OSError, AttributeError):
        p.kill()


class Local:
    def __init__(self, cfg):
        self.cfg = cfg

    def run(self, argv, stdin=None, timeout=120, partial=False):
        return _run(argv, stdin, timeout, partial)


class SSH:
    BASE = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "PasswordAuthentication=no",
            "-o", "KbdInteractiveAuthentication=no", "-o", "StrictHostKeyChecking=yes"]

    def __init__(self, cfg):
        self.cfg = cfg

    def run(self, argv, stdin=None, timeout=120, partial=False):
        remote = subprocess.list2cmdline(argv) if self.cfg.get("shell") == "windows" else \
            " ".join(shlex.quote(a) for a in argv)
        cmd = ["ssh"] + self.BASE + list(self.cfg.get("options", [])) + [self.cfg["host"], remote]
        return _run(cmd, stdin, timeout, partial)


class NotImplementedAdapter:
    def __init__(self, cfg):
        raise NotImplementedError(f"exec adapter {cfg.get('type')!r} is a documented future adapter")


ADAPTERS = {"local": Local, "ssh": SSH, "ssm": NotImplementedAdapter, "osquery": NotImplementedAdapter}


# Reads the whole script from stdin and runs it; UTF-8 output so non-ASCII names (e.g. installed programs) survive.
PS_BOOTSTRAP = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;$ProgressPreference='SilentlyContinue';"
                "$s=@($input) -join [char]10;Invoke-Expression $s")


def powershell(e, script, timeout=180, partial=False):
    """Run a PowerShell script (ASCII source) through any executor whose target has powershell.exe."""
    import base64
    b64 = base64.b64encode(PS_BOOTSTRAP.encode("utf-16-le")).decode()
    return e.run(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand", b64], stdin=script, timeout=timeout,
                 partial=partial)


def executor(cfg):
    return ADAPTERS[cfg.get("type", "local")](cfg)
