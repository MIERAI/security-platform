"""Plain-language explanations of checks, for people who are not security specialists (component `cli`).

  explain(check) -> {"what", "why", "fix", "verify"}   (falls back to a generic text per check family)

Each entry answers four questions in everyday words:
  what    what was found, without jargon
  why     what could go wrong if it stays (the risk, concretely)
  fix     what to do, as steps a junior engineer can follow
  verify  how to see that it is fixed (the next scan closes it on its own)
Keep it generic: no environment, no product names of a particular company. A new check without an entry still gets
the family text plus the collector's own remediation line, so adding one here is encouraged but never required.
"""

NEXT_SCAN = "The next scheduled scan checks again and marks the finding fixed by itself; `sp run <job>` checks now."

CHECKS = {
    # --- identity / remote access -------------------------------------------------------------------------------
    "ssh.password_auth_enabled": dict(
        what="This server lets people log in over SSH with a password.",
        why="Passwords can be guessed or stolen. Bots try common passwords against every SSH server on the internet "
            "all day; one weak password is enough to get in.",
        fix="1. Make sure your own SSH key works first (log in with it in a second terminal).\n"
            "2. In /etc/ssh/sshd_config (or a file in sshd_config.d/) set: PasswordAuthentication no and "
            "KbdInteractiveAuthentication no.\n"
            "3. Reload sshd (systemctl reload ssh or sshd). Keep the working session open until a new key login works.",
        verify="`sudo sshd -T | grep -i passwordauthentication` prints `no`. " + NEXT_SCAN),
    "ssh.root_login_password": dict(
        what="The administrator account (root) can log in over SSH with a password.",
        why="root is the one account name every attacker knows; with a password it only takes a guess to own the "
            "whole machine.",
        fix="Set `PermitRootLogin prohibit-password` (or `no`) in the sshd configuration and reload sshd. Administrators "
            "log in as themselves and use sudo.",
        verify="`sudo sshd -T | grep -i permitrootlogin` is not `yes`. " + NEXT_SCAN),
    "ssh.x11_forwarding": dict(
        what="SSH allows forwarding graphical (X11) sessions.",
        why="Rarely needed on servers; it widens what a compromised client or server can do to the other side.",
        fix="Set `X11Forwarding no` in the sshd configuration and reload sshd.",
        verify=NEXT_SCAN),
    "overlay.node_key_expiry_disabled": dict(
        what="A machine's key for the private overlay network never expires.",
        why="If the machine is lost or copied, its access to the private network lasts forever.",
        fix="Turn key expiry back on in the overlay network's admin console; for unattended servers, record an "
            "exception with an owner and an end date instead.",
        verify=NEXT_SCAN),
    "github.token_broad_scopes": dict(
        what="A code-host token on this machine can do much more than read code (e.g. delete repositories).",
        why="Anyone or anything that can read this machine's token (a script, a compromised tool) gets all of that "
            "power, without an expiry date.",
        fix="Create a fine-grained token limited to the repositories and permissions a job needs, with an expiry; "
            "keep the broad one for interactive use only, or remove it.",
        verify=NEXT_SCAN),
    # --- network exposure ---------------------------------------------------------------------------------------
    "http.unauth_root": dict(
        what="A web service answers without asking who you are, and the platform cannot tell what it is.",
        why="Unknown services are how forgotten admin pages and test tools end up open to everyone on the network.",
        fix="Find out what runs on that address and port (who owns it?). If it should not be reachable, stop it or "
            "firewall it; if it should, put a login in front of it.",
        verify=NEXT_SCAN),
    "http.catch_all_unverified": dict(
        what="A web application answers every address with the same page, so the platform cannot check its login.",
        why="It may be fine (a single-page app) or it may be open; a person has to look once.",
        fix="Open it in a private browser window: if you can see data without logging in, require a login and turn "
            "off open sign-up. If it is fine, record an exception with the reason.",
        verify=NEXT_SCAN),
    "metrics.unauth": dict(
        what="A /metrics page is readable without a login.",
        why="It tells an attacker software versions and internal names, which helps them pick an exploit.",
        fix="Allow only your monitoring server to reach it (firewall or NetworkPolicy), or put it behind auth.",
        verify=NEXT_SCAN),
    "alertmanager.unauth": dict(
        what="The alert manager can be used by anyone who can reach it.",
        why="Someone could silence your alerts before doing something you would otherwise be paged for.",
        fix="Put it behind an authenticating proxy, or reach it only through a port-forward.",
        verify=NEXT_SCAN),
    "prometheus.unauth_read": dict(
        what="The Prometheus query page and API are open without a login.",
        why="It reveals your whole topology: host names, services, versions.",
        fix="Put an authenticating proxy in front, or restrict who can reach it.",
        verify=NEXT_SCAN),
    "prometheus.unauth_remote_write": dict(
        what="Anyone who can reach this Prometheus can write metrics into it.",
        why="Fake metrics can hide an incident or trigger false alerts, including the security platform's own.",
        fix="Require authentication (or mTLS) on the remote-write receiver, or allow only known senders.",
        verify=NEXT_SCAN),
    "prometheus.admin_api_unauth": dict(
        what="The Prometheus admin API is on and open.",
        why="Anyone who reaches it can delete monitoring data.",
        fix="Remove --web.enable-admin-api, or put it behind auth.",
        verify=NEXT_SCAN),
    "ollama.unauth": dict(
        what="An AI model server accepts requests from anyone.",
        why="Others can use your hardware, download or delete models.",
        fix="Bind it to localhost and put an authenticating proxy in front.",
        verify=NEXT_SCAN),
    "loki.unauth": dict(
        what="The log store can be read and written without a login.",
        why="Logs often contain personal data and tokens; anyone can read them or plant fake log lines.",
        fix="Put an authenticating proxy in front (per-tenant auth).",
        verify=NEXT_SCAN),
    "tempo.unauth_read": dict(
        what="The tracing store can be searched without a login.",
        why="Traces show internal requests and sometimes their data.",
        fix="Put an authenticating proxy in front.",
        verify=NEXT_SCAN),
    "otlp.unauth_ingest": dict(
        what="The telemetry intake accepts data from anyone.",
        why="Fake traces can confuse an investigation.",
        fix="Allow only known senders.",
        verify=NEXT_SCAN),
    "blackbox.open_probe": dict(
        what="A probe service can be told to fetch any address.",
        why="Attackers can use it to reach machines they cannot reach directly (a relay into your network).",
        fix="Allow only the monitoring server to call it.",
        verify=NEXT_SCAN),
    "db.reachable": dict(
        what="A database port can be reached from outside the machine.",
        why="Databases are a top target: one weak password or a new vulnerability exposes all the data.",
        fix="Make the database listen only on localhost or a private network; firewall the port.",
        verify=NEXT_SCAN),
    "smb.reachable": dict(
        what="Windows file sharing (SMB) can be reached.",
        why="SMB has a long history of worms and password attacks.",
        fix="Limit it to the local network, turn off guest access, or switch it off.",
        verify=NEXT_SCAN),
    "telnet.open": dict(
        what="Telnet (an old remote login without encryption) is reachable.",
        why="Passwords travel in clear text; anyone on the path can read them.",
        fix="Turn telnet off and use SSH.",
        verify=NEXT_SCAN),
    # --- host ---------------------------------------------------------------------------------------------------
    "patch.security_pending": dict(
        what="Security updates are waiting to be installed on this machine.",
        why="Published fixes tell attackers exactly what to attack; unpatched machines are the easiest way in.",
        fix="Install the updates (e.g. `sudo apt upgrade`), reboot if asked, and turn on automatic security updates.",
        verify=NEXT_SCAN),
    "patch.pending": dict(
        what="Software updates are waiting to be installed.",
        why="Old versions collect known bugs, some of them security bugs.",
        fix="Install the updates in your next maintenance window.",
        verify=NEXT_SCAN),
    "patch.auto_updates_off": dict(
        what="Automatic security updates are off.",
        why="Someone has to remember to patch; urgent fixes then wait for that person.",
        fix="Turn on unattended security upgrades (Debian/Ubuntu: unattended-upgrades) or your OS's equivalent.",
        verify=NEXT_SCAN),
    "patch.reboot_required": dict(
        what="Updates were installed but only take effect after a reboot.",
        why="Until the reboot, the old (vulnerable) code keeps running.",
        fix="Reboot in a quiet moment.",
        verify=NEXT_SCAN),
    "patch.metadata_stale": dict(
        what="The machine has not checked for updates for a long time.",
        why="It cannot know that security fixes exist.",
        fix="Refresh the package lists (e.g. `sudo apt update`) and make sure the regular update job runs.",
        verify=NEXT_SCAN),
    "patch.os_updates_pending": dict(
        what="Operating system updates are waiting.", why="See security updates: known bugs stay open.",
        fix="Install the OS updates and restart.", verify=NEXT_SCAN),
    "fw.host_firewall_off": dict(
        what="The machine's firewall is off.",
        why="Every service that listens is reachable by anyone on the network, including ones you forgot.",
        fix="Turn the firewall on with a default-deny rule for incoming connections, then allow what you need.",
        verify=NEXT_SCAN),
    "macos.disk_filevault_off": dict(
        what="The disk is not encrypted (FileVault is off).", why="A lost or stolen laptop gives away everything on it.",
        fix="System Settings > Privacy & Security > FileVault: turn it on and keep the recovery key somewhere safe.",
        verify=NEXT_SCAN),
    "macos.fw_app_firewall_off": dict(
        what="The Mac's firewall is off.", why="Every app that listens on the network can be reached by others nearby.",
        fix="System Settings > Network > Firewall: turn it on.", verify=NEXT_SCAN),
    "macos.fw_stealth_off": dict(
        what="The Mac answers network probes (stealth mode off).",
        why="It is easier for others on the same network to discover the machine and its services.",
        fix="System Settings > Network > Firewall > Options: enable stealth mode.", verify=NEXT_SCAN),
    "macos.sip_off": dict(
        what="System Integrity Protection is off.", why="Malware can change protected system files.",
        fix="Boot into recovery mode and run `csrutil enable`.", verify=NEXT_SCAN),
    "macos.gatekeeper_off": dict(
        what="Gatekeeper (the check that apps are signed) is off.", why="Unsigned, possibly malicious apps run without warning.",
        fix="Run `sudo spctl --master-enable`.", verify=NEXT_SCAN),
    "patch.brew_outdated": dict(
        what="Command-line packages installed with Homebrew are out of date.", why="Old tools collect known bugs.",
        fix="Run `brew upgrade` (and `brew autoremove`).", verify=NEXT_SCAN),
    "patch.android_security_patch_old": dict(
        what="The Android security patch level is old.", why="Phones are full of credentials; old patch levels have public exploits.",
        fix="Install the system update, or plan to replace a device that no longer gets updates.", verify=NEXT_SCAN),
    "patch.windows_stale": dict(
        what="Windows has not installed updates for a long time.", why="Known, exploited bugs stay open.",
        fix="Run Windows Update and restart.", verify=NEXT_SCAN),
    "win.av_realtime_off": dict(
        what="Real-time malware protection is off.", why="Malware runs without being stopped.",
        fix="Windows Security > Virus & threat protection: turn real-time protection on.", verify=NEXT_SCAN),
    "win.av_signatures_stale": dict(
        what="Malware definitions are out of date.", why="New malware is not recognised.",
        fix="Update the definitions (Windows Security > check for updates).", verify=NEXT_SCAN),
    "win.smb1_enabled": dict(
        what="The old SMB1 file-sharing protocol is on.", why="SMB1 is what the WannaCry worm used.",
        fix="Turn off 'SMB 1.0/CIFS File Sharing Support' in Windows features.", verify=NEXT_SCAN),
    "win.disk_unencrypted": dict(
        what="The disk is not encrypted (BitLocker off).", why="A lost or stolen device gives away everything on it.",
        fix="Turn on BitLocker and store the recovery key safely.", verify=NEXT_SCAN),
    "telnet.daemon_running": dict(
        what="A telnet server is running.", why="Passwords travel in clear text.",
        fix="Stop and remove the telnet server; use SSH.", verify=NEXT_SCAN),
    "secret.in_process_argv": dict(
        what="A password or token is visible in a running program's command line.",
        why="Every user on the machine can read command lines (e.g. with `ps`).",
        fix="Pass the secret through a file with restricted permissions or an environment variable, then rotate it.",
        verify=NEXT_SCAN),
    # --- code host / supply chain -------------------------------------------------------------------------------
    "repo.default_branch_unprotected": dict(
        what="Anyone with write access can push straight to the repository's main branch, without review.",
        why="One stolen account or one mistake changes production code with nobody looking; force-pushes can "
            "erase history.",
        fix="Add a branch protection rule (or ruleset) for the default branch: no direct pushes, changes through "
            "pull requests with at least one approval and passing checks, no force-push or deletion.",
        verify=NEXT_SCAN),
    "repo.protection_no_approvals": dict(
        what="The main branch is protected, but a change can be merged without anyone approving it.",
        why="Review is the control that catches mistakes and malicious changes; without it protection is thin.",
        fix="Require at least one approving review in the branch protection rule.",
        verify=NEXT_SCAN),
    "repo.deploy_key_write": dict(
        what="A deploy key can push to the repository.",
        why="Deploy keys often sit on build machines; whoever gets the key can change your code.",
        fix="Make it read-only unless a pipeline really needs to push; rotate it at least yearly.",
        verify=NEXT_SCAN),
    "repo.mirror_unverified_remote": dict(
        what="A mirror pulls code over plain http.",
        why="Anyone on the path can change the code on its way in.",
        fix="Mirror over https or ssh.", verify=NEXT_SCAN),
    "repo.actions_default_write": dict(
        what="CI jobs get a token that can write to the repository by default.",
        why="A compromised build step (e.g. a bad dependency) can change code or releases.",
        fix="Set the default CI token permission to read-only and grant write only to the jobs that need it.",
        verify=NEXT_SCAN),
    "repo.actions_can_approve_prs": dict(
        what="CI jobs may approve pull requests.", why="An automated job could approve its own change, skipping review.",
        fix="Turn off 'allow actions to create and approve pull requests' unless you rely on it.", verify=NEXT_SCAN),
    "repo.dependabot_alerts_off": dict(
        what="Alerts for vulnerable dependencies are off.", why="You will not hear about known holes in libraries you use.",
        fix="Turn on dependency alerts and security updates.", verify=NEXT_SCAN),
    "repo.dependabot_alerts_open": dict(
        what="Libraries used by this repository have known serious vulnerabilities.",
        why="Attackers scan for exactly these versions.",
        fix="Merge the proposed security updates (or update the libraries yourself) and release.", verify=NEXT_SCAN),
    "repo.secret_scanning_off": dict(
        what="Secret scanning is off for a public repository.", why="Leaked passwords and keys go unnoticed.",
        fix="Turn on secret scanning.", verify=NEXT_SCAN),
    "repo.push_protection_off": dict(
        what="Pushing a secret into the repository is not blocked.", why="A leaked key is public the moment it is pushed.",
        fix="Turn on push protection for secrets.", verify=NEXT_SCAN),
    "repo.secret_scanning_alerts_open": dict(
        what="Secrets (passwords, keys, tokens) were found in the repository.",
        why="Treat them as known to attackers: deleting the file does not help, history keeps them.",
        fix="1. Revoke or rotate each secret at its issuer. 2. Then close the alert. 3. Optionally clean history.",
        verify=NEXT_SCAN),
    "vuln.high_fixable_aggregate": dict(
        what="A running image contains several high-severity vulnerabilities that already have fixes.",
        why="Known, fixable vulnerabilities are the cheapest way in for an attacker.",
        fix="Rebuild the image on an updated base image / dependencies and redeploy.", verify=NEXT_SCAN),
    # --- secrets ------------------------------------------------------------------------------------------------
    "secret.permissions_too_open": dict(
        what="A file with a secret in it can be read by other users.",
        why="Any other account or process on the machine can copy it.",
        fix="`chmod 600 <file>` (only the owner can read it); rotate the secret if others may have read it.",
        verify=NEXT_SCAN),
    "secret.ssh_key_no_passphrase": dict(
        what="An SSH private key has no passphrase.",
        why="Whoever copies the file can use it immediately, everywhere the key is trusted.",
        fix="Add a passphrase (`ssh-keygen -p -f <key>`) and use an agent, or use a hardware key.", verify=NEXT_SCAN),
    "secret.kubeconfig_embedded_client_key": dict(
        what="A Kubernetes config file contains a long-lived client key.",
        why="The file alone grants cluster access until the certificate expires, often for a year or more.",
        fix="Use short-lived credentials (OIDC login or `kubectl create token`), or at least limit the identity's rights.",
        verify=NEXT_SCAN),
    "secret.tf_state_plaintext": dict(
        what="Infrastructure state files are stored unencrypted.",
        why="State files usually contain every password the infrastructure uses.",
        fix="Move the state to an encrypted backend (or encrypt it at rest) and restrict who can read it.",
        verify=NEXT_SCAN),
    "secret.rclone_config_plaintext": dict(
        what="A sync tool's configuration stores credentials unencrypted.", why="The file alone gives access to the storage.",
        fix="Encrypt the configuration (rclone config password) and restrict the file to its owner.", verify=NEXT_SCAN),
    "secret.docker_inline_auth": dict(
        what="Container registry passwords are stored inline in the Docker config.", why="The file alone gives registry access.",
        fix="Use a credential helper (OS keychain) instead and log in again.", verify=NEXT_SCAN),
    "secret.gh_token_in_file": dict(
        what="A code-host token is stored in a plain file.", why="Anything that can read the file can act as you.",
        fix="Store it in the OS keychain (e.g. `gh auth login` uses it) and rotate the token.", verify=NEXT_SCAN),
    "secret.credential_in_notes": dict(
        what="A password or token appears in notes or memory files.",
        why="Notes get shared, synced and read by tools (including AI assistants).",
        fix="Remove it from the notes, keep it in a password manager, and rotate it.", verify=NEXT_SCAN),
    "secret.age_over_90d": dict(
        what="A credential has not been changed for more than 90 days.",
        why="The longer a secret lives, the more places it has been copied to.",
        fix="Rotate it (issue a new one, switch users over, revoke the old one); automate rotation where possible.",
        verify=NEXT_SCAN),
    # --- Kubernetes ---------------------------------------------------------------------------------------------
    "k8s.netpol.missing": dict(
        what="Pods in this namespace can talk to anything, and anything can talk to them.",
        why="One compromised pod can reach every other service in the cluster.",
        fix="Add a default-deny NetworkPolicy to the namespace, then allow only the traffic each app needs.",
        verify=NEXT_SCAN),
    "k8s.operator_cred_system_masters": dict(
        what="The credential used to inspect this cluster is a full administrator.",
        why="If the file leaks, the whole cluster is lost; a read-only check needs no admin rights.",
        fix="Create a read-only identity for the platform (deploy/kubernetes RBAC) and use that kubeconfig.",
        verify=NEXT_SCAN),
    "k8s.policy.engine_missing": dict(
        what="The cluster has no admission policy engine.",
        why="Nothing stops a risky workload (privileged, host access) from being deployed.",
        fix="Install a policy engine (e.g. Kyverno or Gatekeeper) with the baseline Pod Security rules, in audit "
            "mode first.", verify=NEXT_SCAN),
    "agent.bypass_permissions_default": dict(
        what="An AI coding assistant runs commands without asking first, by default.",
        why="A prompt injected through a file or web page can make it run anything on this machine.",
        fix="Set the default mode to ask for permission; allow-list only safe commands.", verify=NEXT_SCAN),
    "agent.reads_outside_workdir": dict(
        what="An AI coding assistant may read files outside the project it works on.",
        why="It can read keys, tokens and other projects' data, and might send them somewhere.",
        fix="Restrict reads to the working directory (and explicitly listed extra directories).", verify=NEXT_SCAN),
    "agent.settings_writable_by_others": dict(
        what="An AI assistant's settings file can be changed by other users.", why="Others could grant it more power.",
        fix="`chmod 600` the settings file.", verify=NEXT_SCAN),
}

FAMILIES = [
    ("k8s.pod.privileged", dict(
        what="A container runs in privileged mode: it has almost the same power as the machine (node) itself.",
        why="If that container is broken into, the attacker owns the node and usually the cluster.",
        fix="Remove `privileged: true` from the pod spec. If the workload needs one specific power, grant only that "
            "capability; run it as non-root.")),
    ("k8s.pod.hostpath", dict(
        what="A pod mounts a directory of the node.", why="It can read or change node files (often credentials).",
        fix="Use a normal volume; if a node path is needed, mount it read-only and as narrow as possible.")),
    ("k8s.pod.host", dict(
        what="A pod shares the node's own processes, network or IPC.",
        why="It can see or reach things on the node that ordinary pods cannot.",
        fix="Remove hostPID / hostNetwork / hostIPC unless the workload is a node agent that truly needs it.")),
    ("k8s.pod.cap", dict(
        what="A container is given extra Linux powers (capabilities).", why="They make escaping the container easier.",
        fix="Drop all capabilities and add back only the one the app needs.")),
    ("k8s.pod.", dict(
        what="A pod is configured with more power than ordinary workloads need.",
        why="Extra power turns a small break-in into a big one.",
        fix="Follow the remediation line below; compare with the Kubernetes Pod Security 'restricted' profile.")),
    ("k8s.rbac.", dict(
        what="An account in the cluster has broad rights (admin, wildcard or secret-reading).",
        why="Whoever controls that account (or its token) controls much of the cluster.",
        fix="Give the account a role with just the verbs and resources it needs; remove cluster-admin bindings that "
            "are not for people doing break-glass work.")),
    ("k8s.policy.fail.", dict(
        what="A workload breaks one of the cluster's own admission policies.",
        why="The policy describes something your team decided is unsafe.",
        fix="Change the workload to satisfy the policy, or record an exception with an owner and an end date.")),
    ("cis.", dict(
        what="The cluster fails an item of the CIS Kubernetes benchmark (a public hardening checklist).",
        why="Each item closes a known way to attack or misuse a cluster.",
        fix="Read the benchmark item's remediation text (in the finding) and apply it on the node or control plane.")),
    ("vuln.", dict(
        what="A known vulnerability (CVE) affects software you run.",
        why="Public vulnerabilities, especially ones listed as exploited in the wild (KEV), are attacked at scale.",
        fix="Update the affected package or image to a fixed version and redeploy. If none exists, reduce exposure "
            "(no public access) and record an exception with an end date.")),
    ("agent.broad_allow.", dict(
        what="An AI coding assistant is allowed to run a broad class of commands without asking.",
        why="Broad rules (any shell, any network tool) let an injected prompt do real damage.",
        fix="Replace the broad rule with specific, read-only commands.")),
    ("listen.db_wildcard.", dict(
        what="A database listens on every network interface of this machine.",
        why="It can be reached from the network, not only from the apps on this machine.",
        fix="Make it listen on localhost (or a private interface) only; firewall the port.")),
    ("win.fw_profile_", dict(
        what="A Windows firewall profile is off.", why="Services on the machine are reachable from that network type.",
        fix="Windows Security > Firewall & network protection: turn the profile back on.")),
    ("macos.", dict(
        what="A built-in macOS protection is off.", why="The Mac is easier to attack or to read when lost.",
        fix="Turn the protection back on in System Settings > Privacy & Security.")),
    ("fw.", dict(
        what="The machine's firewall is not configured to block unexpected incoming connections.",
        why="Forgotten services become reachable.", fix="Turn on the firewall with default-deny for incoming traffic.")),
    ("patch.", dict(
        what="The machine is missing updates.", why="Known bugs stay open.", fix="Install the updates and reboot if needed.")),
    ("secret.", dict(
        what="A secret (password, key, token) is stored in a risky way.", why="It can be copied and misused.",
        fix="Restrict the file, move the secret to a secrets manager or keychain, and rotate it.")),
    ("win.", dict(
        what="A Windows protection is off or out of date.", why="Windows machines are the most attacked endpoints.",
        fix="Turn the protection back on (Windows Security) and update it.")),
]

LAYER_WORDS = {
    "identity": "who can log in or act, and with which keys",
    "network": "what can be reached from the network",
    "host": "the machine itself (updates, firewall, disk)",
    "workload": "what runs in the cluster",
    "supply-chain": "where your code and software come from",
    "data-secrets": "passwords, keys and data",
    "ai-agents": "AI assistants and what they may do",
    "detection": "whether an attack would be noticed",
}
SEVERITY_WORDS = {
    "critical": "fix today: attackers are likely to use this soon",
    "high": "fix this week",
    "medium": "plan it this month",
    "low": "fix when convenient",
    "info": "for awareness",
}


def explain(check):
    e = CHECKS.get(check)
    if e:
        return dict(e)
    for prefix, fam in FAMILIES:
        if check.startswith(prefix):
            return dict(fam, verify=NEXT_SCAN)
    return dict(what="", why="", fix="", verify=NEXT_SCAN)


def headline(check, fallback=""):
    """One short plain-language line for a check (for digests and dashboards): never contains asset details."""
    w = explain(check).get("what")
    return w or fallback
