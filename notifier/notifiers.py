"""notifier adapters: deliver the short daily summary (`sp digest`) to people (component `notifier`, VERSION below).

  send(cfg, text) -> None   (raises on failure; the caller reports it and goes on with the next notifier)

The text is AGGREGATES ONLY (counts, plain-language check families, finding ids): notifications leave the private
boundary (chat services, push gateways, phones), so they never carry asset names, addresses or evidence. Secrets
(bot tokens, webhook URLs) are read from files that must be mode 0600; they are never logged, and errors are reduced
to a status code so a URL with a token in it cannot end up in a log.

Implemented (instance `notify: [ ... ]`, any number, each independent):
  stdout    {type: stdout}
  file      {type: file, path: <file>}                         overwrite with the latest summary (e.g. for a widget)
  webhook   {type: webhook, url_file: <0600 file>, format?: slack|json|text}
            Slack / Mattermost / Rocket.Chat incoming webhooks (slack: {"text": ...}), Microsoft Teams workflows and
            generic receivers (json: {"title", "text"}), ntfy or Gotify-like push (text: the body as text/plain)
  telegram  {type: telegram, token_file: <0600 file>, chat_id: <id> | chat_id_file: <file>, api?: <base url>}
            a bot you control (BotFather); the chat id is your user or group id
  exec      {type: exec, argv: [cmd, ...], exec?: <exec adapter cfg>}
            pipe the text into a command, locally or on a host through the exec adapter (e.g. a text-to-speech
            service, `mail -s`, `termux-notification`); a non-zero exit is a failure
Add one: a function `name(cfg, text)` and an entry in ADAPTERS; see docs/adapters.md.
"""
import json
import os
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from adapters import exec as ex  # noqa: E402

VERSION = "0.1.0"
TIMEOUT = 20


def secret(path):
    p = os.path.expanduser(path)
    if stat.S_IMODE(os.stat(p).st_mode) & 0o077:
        raise PermissionError(f"{path} must be mode 0600")
    return open(p).read().strip()


def _post(url, body, ctype):
    req = urllib.request.Request(url, data=body, headers={"Content-Type": ctype, "User-Agent": "security-platform"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status
    except urllib.error.HTTPError as e:      # the message names the status only, never the URL (it may hold a token)
        raise RuntimeError(f"HTTP {e.code}") from None
    except (urllib.error.URLError, OSError) as e:
        reason = getattr(e, "reason", e)
        raise RuntimeError(f"cannot connect ({type(reason).__name__})") from None


def stdout(cfg, text):
    print(text)


def file(cfg, text):
    p = os.path.expanduser(cfg["path"])
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    with open(p + ".tmp", "w") as f:
        f.write(text + "\n")
    os.replace(p + ".tmp", p)


def webhook(cfg, text):
    url = secret(cfg["url_file"]) if cfg.get("url_file") else cfg["url"]
    fmt = cfg.get("format", "slack")
    if fmt == "slack":
        _post(url, json.dumps({"text": text}).encode(), "application/json")
    elif fmt == "json":
        title, _, rest = text.partition("\n")
        _post(url, json.dumps({"title": title, "text": rest}).encode(), "application/json")
    elif fmt == "text":
        _post(url, text.encode(), "text/plain; charset=utf-8")
    else:
        raise ValueError(f"webhook format {fmt!r}: slack, json or text")


def telegram(cfg, text):
    token = secret(cfg["token_file"])
    chat = str(cfg.get("chat_id") or open(os.path.expanduser(cfg["chat_id_file"])).read().strip())
    api = cfg.get("api", "https://api.telegram.org").rstrip("/")
    body = urllib.parse.urlencode({"chat_id": chat, "text": text[:4000], "disable_web_page_preview": "true"}).encode()
    _post(f"{api}/bot{token}/sendMessage", body, "application/x-www-form-urlencoded")


def exec_(cfg, text):
    rc, _, err = ex.executor(cfg.get("exec") or {"type": "local"}).run(list(cfg["argv"]), stdin=text, timeout=60)
    if rc != 0:
        raise RuntimeError(f"rc={rc}: {err.strip()[-120:]}")


ADAPTERS = {"stdout": stdout, "file": file, "webhook": webhook, "telegram": telegram, "exec": exec_}


def send(cfg, text):
    t = cfg.get("type")
    if t not in ADAPTERS:
        raise ValueError(f"unknown notifier {t!r} (one of {', '.join(ADAPTERS)})")
    ADAPTERS[t](cfg, text)
