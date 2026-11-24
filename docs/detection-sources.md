# Detection sources: what each event source can see, and what it needs

Events (docs/runner.md "Security events") are only as good as the access behind them. This page lists, per source,
what is observable through public interfaces, the least privilege that is enough, and the known blind spots. A blind
spot is recorded here and in the scorecard as a failing control; it is not hidden.

## Code host account (`github-account`)

| signal | endpoint | token scope (classic) / fine-grained permission |
|---|---|---|
| new SSH authentication key | `GET /user/keys` | `read:public_key` / account "Git SSH keys: read" |
| new GPG key | `GET /user/gpg_keys` | `read:gpg_key` / account "GPG keys: read" |
| new SSH signing key | `GET /user/ssh_signing_keys` | `read:ssh_signing_key` / account "SSH signing keys: read" |
| repository visibility change | `GET /user/repos`, `GET /users/{login}/events` (PublicEvent) | `repo` (private repositories) / "Metadata: read" |
| deploy keys, webhooks | `GET /repos/{owner}/{repo}/keys`, `/hooks` | `repo` (admin of the repository) / "Administration: read", "Webhooks: read" |
| GitHub App installations | `GET /user/installations` | a GitHub App user-to-server token only; classic tokens get 403 |

Without the key scopes the API answers 404 (not 403): the source records the endpoint under `unsupported` in its
state and run summary, and the corresponding rule (`codehost-credential-added`) is blind until a token with those
read scopes is configured. Use a dedicated read-only token for the events job, not an operator's everyday token.

**Not observable through the public API for personal accounts:** creation of personal access tokens, OAuth
application authorizations, sign-ins and 2FA changes. They are in the account's security log, which is only
available in the web UI and as a manual export (the audit-log REST/streaming APIs exist for organizations and
enterprises only). Options: move repositories into an organization (organization audit log API, `read:audit_log`),
or review the personal security log on a schedule (a human control, recorded in the private catalog review).

## Overlay network control plane (`tailscale-audit`)

`GET /api/v2/tailnet/-/logging/configuration?start=&end=` (configuration audit log: nodes added/removed, key expiry,
policy file, users and roles, routes / exit nodes, keys). Preferred credential: an OAuth client
(`oauth_client_id` + `oauth_client_secret_file`, 0600) whose scopes include `logs:configuration:read`; it is exchanged
for a short-lived token on every run. Fallback: an API access token (`token_file`), which carries its user's full
rights. Steps for the owner: admin console → Settings → OAuth clients → add the read scope `logs:configuration:read`
to the read-only client (or generate a new one with only that scope) → put the secret in a 0600 file on the host that
runs the job → add the source. Network flow logs
are a separate (paid) feature and out of scope.

## Hosts without a log agent (`command`, `file-integrity`)

| host type | how | notes |
|---|---|---|
| Linux with systemd | prefer the `node-logs` DaemonSet on cluster nodes; otherwise `journalctl SYSLOG_FACILITY=4 SYSLOG_FACILITY=10 -o short-iso --since @{since_epoch}` | parser `openssh` (also parses sudo) |
| Android (Termux sshd) | `logcat -d -v epoch -s sshd sshd-session` | an app can read its own log buffer only; the ring buffer is small, so run at least every 15 minutes |
| Embedded router (dropbear, BusyBox / syslog-ng) | `grep -h dropbear /tmp/messages` over ssh | timestamps have no year/zone: set `utc_offset`; the file lives in RAM and is lost on reboot |
| macOS | `log show --style ndjson --info --start {since_local} --predicate '…sudo… sshd…'` | runs locally; a sleeping workstation catches up on wake (latency) |
| authorized_keys | `file-integrity` over the exec adapter | hashes only; key material never leaves the host |
