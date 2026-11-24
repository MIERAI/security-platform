# Incident response playbook

How to handle a security detection (an alert from `detections/catalog.yaml`, `component=security-detection`) from the
first minute to the postmortem. Generic: the instance's Alertmanager routing decides who gets paged; this page decides
what they do. Every alert has its own runbook in [runbooks/](runbooks/) (`runbook_url` annotation); this playbook is
the frame around them.

**Blameless.** We look for the conditions that allowed the incident (missing control, unclear runbook, over-broad
permission), never for a person to blame. People who report their own mistakes early are the best detection we have.

## Roles

| Role | Who | Does |
|---|---|---|
| Incident commander (IC) | whoever acknowledges the alert first (in a one-person team: you) | decides, keeps the timeline moving, declares phases and the end |
| Scribe | the timeline file `<data>/incidents/<date>-<slug>/timeline.md` (the IC writes to it as they go) | UTC timestamp + action + who + evidence pointer, one line each |
| Responders | anyone the IC pulls in (owner of the affected system, a second pair of eyes) | execute one task at a time, report back to the IC |

The IC hands over explicitly ("you are IC now") and writes the handover in the timeline. Incident records,
timelines and evidence are private (same boundary as findings), never in a public repository or chat.

## Severity

| Alert severity | Meaning | Response target | Becomes an incident when |
|---|---|---|---|
| `page` | likely active compromise or loss of a critical control | acknowledge within 15 minutes, any hour | always, until triage proves it benign |
| `ticket` | suspicious, or a weakened control | triage the same day | triage finds unexplained activity |
| `info` | recorded for context and metrics | weekly review | correlated with a page/ticket |

Pipeline-health alerts (sensor down, audit log quiet, shipper broken, backstop) are `ticket` but are handled as
possible defence evasion: blindness is an incident until the cause is proven benign.

## Phases

### 1. Triage (timebox: 30 minutes for `page`, same day for `ticket`)

- [ ] Acknowledge the alert (silence only the duplicate notifications, with the incident id in the silence comment).
- [ ] Open the alert's runbook; run its triage queries; copy the result into the evidence directory (see below).
- [ ] Answer: what happened, where, since when, by which identity, from where. Known benign (drill, operator session,
      reviewed change)? Record the verdict (below) and stop.
- [ ] Otherwise declare an incident: create `<data>/incidents/<date>-<slug>/`, start the timeline, set IC.
- [ ] Scope: what else did the same identity / pod / host / source address do (one hour before the first signal at
      least)? Which other detections fired?

### 2. Contain (timebox: 1 hour after declaration)

Goal: stop the spread without destroying evidence. Least destructive first:

- [ ] Capture volatile evidence first (process, memory, network: [evidence preservation](#evidence-preservation)).
- [ ] Network isolation: deny-all NetworkPolicy on the affected pods; firewall the source address; remove the node
      from the overlay network if the host itself is compromised.
- [ ] Credentials: revoke/rotate what the attacker had or could read (ServiceAccount tokens, kubeconfigs, SSH keys,
      code host tokens, cloud keys, Secrets the workload mounted).
- [ ] Workloads: scale the owner to 0 only after capture; keep the pod object (relabel it out of its Service) and the
      cordoned node.
- [ ] Record every action in the timeline (time, command, result).

### 3. Eradicate (timebox: 1 day)

- [ ] Find the entry point (vulnerable image, exposed service, stolen credential, malicious change) and remove it.
- [ ] Remove persistence: keys, bindings, CronJobs, webhooks, modified images, setuid files.
- [ ] Rebuild instead of cleaning: workloads from Git (GitOps sync), hosts from configuration management.
- [ ] Re-run the platform's collectors for the affected assets; the ledger must show the related findings fixed.

### 4. Recover (timebox: 1 day)

- [ ] Restore service from known-good state (Git, signed images, backups taken before the first signal).
- [ ] Watch the same detections with extra attention for 7 days (a reminder in the tracker).
- [ ] Lift isolation step by step, recording each step.
- [ ] Close the incident in the timeline (end time, IC).

### 5. Postmortem (within 5 working days)

Use the [postmortem template](runbooks.md#postmortem-template) and add the detection view:

```
Detection:  which alert fired first (detection id), time-to-detect (first malicious action -> alert),
            time-to-acknowledge, time-to-contain; which detections SHOULD have fired and did not (gaps)
Response:   which runbook steps worked / were missing / were wrong (fix the runbook in the same PR)
Controls:   new or changed detection rules, allowlists, preventive controls (admission policy, RBAC, firewall)
```

Every action item has an owner and a due date and goes into the private tracker. Gaps found here are the main
input for new detection rules.

## Communication

- One channel per incident (the timeline is the source of truth; status updates point to it).
- Update cadence: every 30 minutes during containment for `page` incidents, at every phase change otherwise.
- Never paste secrets, evidence content or attacker indicators into public places (public repositories, issues,
  chat with outside parties). Public changes made during the incident use neutral wording ("routine hardening").
- Third parties (code host, overlay network vendor, upstream projects) are contacted by the IC with only the
  minimum facts needed.

## Evidence preservation

Capture before changing anything, in order of volatility (most volatile first). Do not reboot, delete pods,
restart services or "clean up" before the capture is done. Keep the cordoned node and the scaled-down/relabelled
pod until the postmortem is reviewed.

Evidence directory: `<data>/incidents/<date>-<slug>/evidence/` (private, then copied to write-once storage).

1. **Running state (memory, processes, network)**
   - Pod: `kubectl get pod <pod> -n <ns> -o yaml > pod.yaml`; `kubectl describe pod …`; `kubectl logs <pod> -n <ns>
     --all-containers --timestamps > logs.txt` and `--previous` for restarted containers.
   - Container runtime on the node: `crictl inspect <container-id> > inspect.json`; `crictl ps -a`.
   - Checkpoint the container if the kubelet checkpoint API is enabled (`POST /checkpoint/<ns>/<pod>/<container>` on
     the kubelet): a restorable memory and filesystem image.
   - Node: `ss -tpn > ss.txt`, `ps auxwwf > ps.txt`, `sha256sum /proc/<pid>/exe` and a copy of it
     (`cp /proc/<pid>/exe exe.<pid>`), `ls -l /proc/<pid>/fd`, `cat /proc/<pid>/environ | tr '\0' '\n'` (may contain
     secrets: store, do not paste), `lsmod`, `who`, `last -F`.
2. **Filesystems**
   - Container writable layer: `kubectl cp <ns>/<pod>:<path> ./fs/<path>` for the relevant paths, or export the
     container's filesystem from the runtime on the node (snapshot mount / `ctr` export) for a full copy.
   - Host files touched (authorized_keys, sudoers, cron, systemd units): copy with metadata (`cp -a`), plus `stat`.
3. **Logs**
   - Node journal: `journalctl --since "<start>" --until "<end>" -o export > journal.export` (keeps all fields).
   - API audit log files on the control-plane node (copy the files, including rotated ones).
   - The log store: export the incident window for every relevant selector with logcli
     (`logcli query --from=… --to=… --limit=0 --output=jsonl '<query>' > loki-<name>.jsonl`) or the query API
     (`/loki/api/v1/query_range`, paginate by time). The log store is the copy the attacker could not reach:
     export it early, retention may expire.
   - Alertmanager: the alert payloads (`/api/v2/alerts`) as JSON.
4. **Manifest and custody**
   - `sha256sum * > MANIFEST.sha256` over every artifact; record in `custody.md`: who collected what, when (UTC),
     from where, with which command, the hash, and every later transfer (who, when, to where).
   - Copy the directory to write-once / versioned storage (object store with object lock or a bucket with
     versioning and no delete permission for the responder); never edit artifacts, work on copies.

## Recording a verdict

Every security-detection alert that fired gets exactly one verdict, recorded in the private data directory:
`<data>/detections/verdicts.yaml` (human-written; reviewed like `exceptions.yaml`). The platform derives the
false-positive rate and alert volume metrics from it (alerts without a verdict count as `unreviewed`).

```yaml
- alert: SecurityDetectionK8sPodExec          # alert name
  detection: k8s-pod-exec                      # detection id (label `detection`)
  fired_at: "2026-01-01T10:00:00Z"             # the alert's startsAt
  verdict: benign                              # true_positive | false_positive | benign | drill
  by: <who decided>
  note: operator debugging session, matched change record
  ticket: <tracker id, incident id or change reference>
```

- `true_positive`: malicious or unauthorised activity; links to the incident.
- `false_positive`: the rule matched something it was not meant to match; links to the tuning change (allowlist,
  params, rule fix) made through a reviewed PR.
- `benign`: the rule worked as intended and the activity was authorised (an operator's session, a reviewed change).
  Many `benign` verdicts for one rule = the rule needs context (an allowlist) or a lower severity.
- `drill`: a planned simulation (see below).

## Drills

Detection that was never exercised is assumed broken. Drills run **in the lab environment only**, with benign
simulations (no real malware, no production systems, no data leaving the environment). Typical drills: exec into a
lab test pod (k8s-pod-exec, falco-shell-in-container), read a sensitive file in a lab container
(falco-sensitive-file-read), create and delete a ClusterRoleBinding with a test name (k8s-clusterrolebinding-created).

1. Announce the drill in the timeline file and record `action_at` (UTC, from the command's own clock).
2. Perform the action; do not touch the detection pipeline.
3. Wait for the alert at the Alertmanager (`/api/v2/alerts?filter=detection="<id>"`); record `alert_at` = the time
   the alert was first received (its `startsAt`, or the receiving side's timestamp if earlier is unknown).
4. Follow the runbook as if it were real (triage queries must find the evidence); note what was missing.
5. Clean up the drill artefacts, record the verdict `drill`.

Record: `<data>/detections/drills/<date>-<id>.yaml`

```yaml
id: 2026-01-01-k8s-pod-exec
detection: [k8s-pod-exec, falco-shell-in-container]
cluster: <lab cluster>
action: exec into a lab test pod with an interactive shell
action_at: "2026-01-01T10:00:00Z"
alert_at: "2026-01-01T10:01:30Z"
ttd_seconds: 90                     # alert_at - action_at; the platform reports the latest and the worst
runbook_followed: true              # triage queries found the evidence; gaps listed in result
result: pass                        # pass | fail (no alert, or alert without usable evidence)
```

A failed drill is handled like an incident of the detection pipeline: postmortem, fix, drill again.
