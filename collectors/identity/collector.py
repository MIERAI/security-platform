#!/usr/bin/env python3
"""Collector `identity`: the people pillar - accounts, MFA, access grants, token and key lifecycle. READ-ONLY.

Instance config:
  identity:
    providers:                       # adapters/identity.py; checks below are provider-independent
      - {type: github, accounts: [{gh_user: <login>}], orgs: [<org in scope>], repos_owner: <owner>,
         expected_collaborators: [<login>, ...]}
      - {type: tailscale, api_key_file: ~/.config/security-platform/tailscale-api.key}   # key optional (CLI fallback)
      - {type: google-workspace}     # interface only: reported as a coverage gap until implemented
    credentials:                     # local credential stores: METADATA only (names, kinds, scopes, ages, expiry)
      kubeconfigs: [~/.kube/*.yaml]
      ssh_dirs: [~/.ssh]
      docker_configs: [~/.docker/config.json]
      token_files: [~/.config/security-platform/*.token]
      exclude: [paths out of scope]
      exclude_registries: [hosts out of scope]
    max_token_age_days: 90           # rotatable tokens (PATs, OAuth tokens, API keys, static kube tokens, token files)
    max_ssh_key_age_days: 365
    expiring_days: 14
    dormant_device_days: 60
The raw evidence (raw/identity/inventory.json) holds names, kinds, scopes, dates. Never a token value.
"""
import os
import sys
import time

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..", "..")
sys.path[:0] = [os.path.join(ROOT, "sdk"), ROOT]
import spsdk  # noqa: E402
from adapters import identity as idp  # noqa: E402

VERSION = open(os.path.join(HERE, "VERSION")).read().strip()
ROTATABLE = {"oauth_token", "pat_classic", "pat_fine_grained", "api_key", "kube_token", "token_file", "registry"}


def ts(s):
    if not s:
        return None
    s = str(s)
    try:
        return time.mktime(time.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")) - time.timezone
    except ValueError:
        try:
            return time.mktime(time.strptime(s[:10], "%Y-%m-%d")) - time.timezone
        except ValueError:
            return None


def checks(c, snap, cfg, now, ev):
    F = c.finding
    max_age = float(cfg.get("max_token_age_days", 90)) * 86400
    ssh_age = float(cfg.get("max_ssh_key_age_days", 365)) * 86400
    soon = float(cfg.get("expiring_days", 14)) * 86400
    dormant = float(cfg.get("dormant_device_days", 60)) * 86400
    expected = {p["type"]: set(p.get("expected_collaborators") or []) for p in cfg.get("providers", [])}
    for a in snap["accounts"]:
        A = f"identity:{a['provider']}/{a['id']}"
        if a.get("mfa") is False:
            F("identity", A, "identity.mfa_disabled", f"{a['provider']} account {a['id']} has no two-factor authentication",
              "critical" if a.get("admin") else "high", ev, "enable 2FA (prefer a passkey or security key)", needs_human=True)
    for o in snap["orgs"]:
        A = f"org:{o['provider']}/{o['id']}"
        if o.get("mfa_required") is False:
            F("identity", A, "identity.org_mfa_not_required", f"organisation {o['id']} does not require 2FA of its members",
              "medium", ev, "require 2FA for everyone in the organisation settings (members without 2FA are removed: "
              "check first)", needs_human=True)
    for g in snap["grants"]:
        if g["kind"] == "collaborator":
            exp = expected.get(g["provider"], set())
            if g["principal"] not in exp:
                F("identity", f"{g['resource']}/collaborator/{g['principal']}", "identity.collaborator_unexpected",
                  f"{g['principal']} has {g['permission']} access to {g['resource'].split(':', 1)[1]} and is not in the expected list",
                  "high" if g["permission"] in ("admin", "maintain", "push") else "medium", ev,
                  "remove the collaborator, or add them to identity.providers[].expected_collaborators after review",
                  needs_human=True)
        elif g["kind"] == "deploy_key":
            lu = ts(g.get("last_used"))
            if lu is None or now - lu > 180 * 86400:
                F("identity", f"{g['resource']}/{g['principal']}", "identity.deploy_key_unused",
                  f"deploy key {g['principal'].split('/', 1)[1]} ({g['permission']}) not used for 180 days (or never)",
                  "low", ev, "delete it (re-create when a pipeline needs it)", needs_human=True)
    for p in snap["policies"]:
        if p["name"] == "fork_pr_approval" and p.get("public") and p.get("value") not in ("all_external_contributors",):
            F("identity", p["resource"], "identity.fork_pr_approval_weak",
              f"workflows from outside contributors run without approval for some contributors ({p.get('value')})", "low", ev,
              "require approval for all external contributors (repository Actions settings)")
        if p["name"] == "acl_allow_all" and p.get("value"):
            F("identity", p["resource"], "identity.overlay_acl_allow_all", "the overlay network ACL allows every device to reach every device",
              "high", ev, "replace the default allow-all policy with grants per tag/group", needs_human=True)
    for cr in snap["credentials"]:
        A = f"credential:{cr.get('store')}/{cr['id']}"
        created, exp, last = ts(cr.get("created_at")), ts(cr.get("expires_at")), ts(cr.get("last_used"))
        kind = cr["kind"]
        if kind in ROTATABLE and created and now - created > max_age:
            F("identity", A, "identity.token_age_over_90d",
              f"{kind} {cr['id']} is {int((now - created) / 86400)} days old (rotate every {int(max_age / 86400)} days)",
              "medium" if kind in ("pat_classic", "oauth_token", "api_key", "kube_token") else "low", ev,
              "rotate it (or replace it with a short-lived / fine-grained credential)", needs_human=True)
        if kind == "ssh_key" and created and now - created > ssh_age:
            F("identity", A, "identity.ssh_key_age_over_365d", f"SSH key {cr['id']} is {int((now - created) / 86400)} days old",
              "low", ev, "rotate yearly: new key, update authorized_keys / code host, delete the old one", needs_human=True)
        if kind in ("oauth_token", "pat_classic") and "repo" in (cr.get("scopes") or []):
            F("identity", A, "identity.token_classic_full_repo",
              f"{kind} {cr['id']} has the full `repo` scope (all private repositories, read and write)", "medium", ev,
              "use a fine-grained token limited to the repositories and permissions automation needs; keep the broad "
              "one for interactive use only", needs_human=True)
        if exp:
            if exp <= now:
                F("identity", A, "identity.credential_expired", f"{kind} {cr['id']} expired {cr['expires_at'][:10]} and is still configured",
                  "low", ev, "remove it or replace it", needs_human=True)
            elif exp - now < soon:
                F("identity", A, "identity.token_expiring_soon", f"{kind} {cr['id']} expires {cr['expires_at'][:10]}",
                  "medium", ev, "rotate it before it expires (outage) - and record where it is used", needs_human=True)
        if kind == "device_key" and last and now - last > dormant:
            F("identity", A, "identity.overlay_device_dormant", f"overlay device {cr['id']} not seen for {int((now - last) / 86400)} days",
              "low", ev, "remove the device from the overlay network", needs_human=True)
        if cr.get("mode") and int(cr["mode"], 8) & 0o077 and kind != "kube_exec":
            F("identity", A, "identity.credential_file_readable", f"{cr['id']} file is readable by others ({cr['mode']})", "high",
              ev, "chmod 600")


def main():
    inst = spsdk.load_instance()
    c = spsdk.Collector("identity", VERSION)
    cfg = inst.get("identity") or {}
    cache = os.path.join(os.environ.get("SP_DATA", c.out), "cache", "identity")
    total = idp.snapshot()
    for pc in cfg.get("providers", []):
        try:
            p = idp.provider(pc, cache_dir=cache)
            s = p.collect()
        except NotImplementedError as e:
            c.gap(f"identity-provider:{pc['type']}", str(e))
            continue
        except Exception as e:  # noqa: BLE001 - one provider down must not hide the others
            c.gap(f"identity-provider:{pc['type']}", f"{type(e).__name__}: {str(e)[:200]}")
            continue
        for k in ("accounts", "orgs", "grants", "credentials", "policies"):
            total[k] += s[k]
        for a, why in s["gaps"]:
            c.gap(a, why)
        for a in s["covered"]:
            c.ok(a)
    if cfg.get("credentials"):
        s = idp.local_credentials(cfg["credentials"])
        total["credentials"] += s["credentials"]
        for a, why in s["gaps"]:
            c.gap(a, why)
        for a in s["covered"]:
            c.ok(a)
    now = time.time()
    inv = {k: total[k] for k in ("accounts", "orgs", "grants", "policies")}
    inv["credentials"] = [{k: v for k, v in cr.items() if k != "value"} for cr in total["credentials"]]
    for cr in inv["credentials"]:
        t0 = ts(cr.get("created_at"))
        cr["age_days"] = round((now - t0) / 86400, 1) if t0 else None
    ev = c.raw("inventory.json", inv)
    checks(c, total, cfg, now, ev)
    kinds = {}
    for cr in total["credentials"]:
        kinds[cr["kind"]] = kinds.get(cr["kind"], 0) + 1
    for k, n in sorted(kinds.items()):
        c.metric("security_identity_credentials", n, "Credentials found (metadata only), by kind", kind=k)
    c.metric("security_identity_accounts", len(total["accounts"]), "Accounts seen through identity providers")
    c.metric("security_identity_mfa_unknown", sum(1 for a in total["accounts"] if a.get("mfa") is None),
             "Accounts whose MFA status no API could tell (attest them)")
    c.metric("security_identity_grants", len(total["grants"]), "Access grants seen (collaborators, deploy keys, members)")
    c.tools["identity-adapter"] = idp.VERSION
    c.write()


if __name__ == "__main__":
    main()
