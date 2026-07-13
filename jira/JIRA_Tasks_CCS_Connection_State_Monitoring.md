# Jira Tasks — Epic: CCS Remote Connection-State Degradation Monitoring

> **Note:** No Jira connector is currently linked to this workspace, so these
> tasks could not be created directly in Jira from this session. This file (and
> the companion `jira_import.csv`) is the deliverable: it is structured so you
> can either (a) import `jira_import.csv` via **Jira → your project → Import
> issues from CSV**, mapping the `Epic Name`/`Epic Link` column to your Epic, or
> (b) copy each task below into Jira by hand. Once a Jira connector is added to
> the workspace I can create these programmatically instead.

**Epic:** CCS Remote Connection-State Degradation Monitoring
**Epic goal:** Detect and alert on degradation of the connection pool between
local and remote Elasticsearch clusters before it surfaces as missing/partial
data in federal dashboards.

---

## Phase 0 — Definition & baseline

### CCS-1 · Inventory all remotes across the four clusters
**Type:** Task · **Phase:** 0 · **Milestone:** M0
Enumerate every remote configured on each local cluster (dev, qa, prod, ccs) by
reading `GET /_remote/info`. Record cluster → remote → current
`num_nodes_connected`, `mode`, `initial_connect_timeout`, `skip_unavailable`.
**Acceptance:** A reviewed inventory table exists covering all four clusters and
all their remotes.

### CCS-2 · Define per-remote expected baseline (nodes + mode)
**Type:** Task · **Phase:** 0 · **Milestone:** M0
For each remote, agree the expected `num_nodes_connected` and expected `mode`
(`sniff`/`proxy`). Do **not** assume uniformity across environments.
**Acceptance:** `es_clusters.json` populated with `expected_nodes` and
`expected_mode` per remote; signed off by owner.

### CCS-3 · Define per-environment severity thresholds
**Type:** Task · **Phase:** 0 · **Milestone:** M0
Decide what counts as Warning vs Critical per environment (e.g. is one-of-three
nodes down a warning or critical in prod?). Define handling of missing remotes
and unreachable local clusters as Critical.
**Acceptance:** Documented severity matrix per environment, referenced by the
collector logic.

### CCS-4 · Confirm skip_unavailable posture per remote
**Type:** Task · **Phase:** 0 · **Milestone:** M0
Record `skip_unavailable` for every remote and note where `true` could mask
silent downstream degradation; weight severity accordingly.
**Acceptance:** `skip_unavailable` captured per remote with risk annotation.

### CCS-5 · Design `.ccs-health-monitor` verdict schema
**Type:** Task · **Phase:** 0 · **Milestone:** M0
Define the verdict document schema (timestamp, local cluster, remote name,
connected, nodes expected/actual, mode, skip_unavailable, severity, reason).
**Acceptance:** Schema documented and reviewed; ready for Phase 2 mapping.

---

## Phase 1 — Collector

### CCS-6 · Build connection-state probe in `ccs_health_check.py`
**Type:** Story · **Phase:** 1 · **Milestone:** M1
Implement the probe: load cluster inventory + credentials from file, call
`GET /_remote/info` per local cluster, evaluate each remote vs baseline, classify
severity (Healthy/Warning/Critical), and **print verdicts to screen** (no
indexing yet).
**Acceptance:** Script runs against all four clusters and prints correct
per-remote verdicts; edge cases handled (missing remote, unreachable cluster,
mode drift, unmonitored remote).

### CCS-7 · Credential loading from file (interim)
**Type:** Task · **Phase:** 1 · **Milestone:** M1
Read API keys from a local credentials file (git-ignored), with an example
template committed. Keep the auth layer isolated behind one function.
**Acceptance:** Credentials read from file; real secrets not committed;
`credentials.example.json` present.

### CCS-8 · Refactor credential loading to AWS Secrets Manager
**Type:** Task · **Phase:** 1 · **Milestone:** M1
Replace file-based credential loading with runtime retrieval via boto3 from AWS
Secrets Manager, keeping the same auth interface.
**Acceptance:** Collector authenticates using Secrets Manager at runtime; no
static key files in the deploy path.

### CCS-9 · Provision least-privilege service account / API key
**Type:** Task · **Phase:** 1 · **Milestone:** M1
Create a least-privilege credential: cluster `monitor` privilege plus write to
the single `.ccs-health-monitor` index only.
**Acceptance:** Key provisioned, scoped, and validated against a non-prod
cluster.

### CCS-10 · Error handling, timeouts, and TLS verification
**Type:** Task · **Phase:** 1 · **Milestone:** M1
Add request timeouts, per-cluster isolation (one failure never aborts the loop),
FedRAMP-compliant TLS cert verification (CA bundle support), and structured
logging.
**Acceptance:** Induced network/auth/TLS failures produce a Critical verdict for
the affected cluster only; other clusters still evaluated.

---

## Phase 2 — State store

### CCS-11 · Create `.ccs-health-monitor` index with explicit mapping
**Type:** Task · **Phase:** 2 · **Milestone:** M2
Create the hidden state index with the Phase 0 schema mapping.
**Acceptance:** Index created; verdict docs index cleanly against the mapping.

### CCS-12 · Add ILM/DSL retention policy
**Type:** Task · **Phase:** 2 · **Milestone:** M2
Apply retention (ILM or data-stream lifecycle) per the agreed retention period.
**Acceptance:** Old verdicts age out automatically per policy.

### CCS-13 · Wire collector to write verdicts to state store
**Type:** Task · **Phase:** 2 · **Milestone:** M2
Enable indexing path in the collector (one verdict doc per remote per cycle).
**Acceptance:** Verdicts land in `.ccs-health-monitor`, queryable, one doc per
remote per cycle.

### CCS-14 · Confirm hidden-index read access for alerting role
**Type:** Task · **Phase:** 2 · **Milestone:** M2
Ensure the Kibana alerting role can read the hidden index.
**Acceptance:** Alerting role queries the index successfully.

---

## Phase 3 — Alerting

### CCS-15 · Kibana ES Query rule — Critical tier (per remote)
**Type:** Story · **Phase:** 3 · **Milestone:** M3
Create per-remote-grouped critical rule (`connected: false` / missing remote /
unreachable cluster).
**Acceptance:** Induced non-prod critical fires and targets the failing remote.

### CCS-16 · Kibana ES Query rule — Warning tier (per remote)
**Type:** Task · **Phase:** 3 · **Milestone:** M3
Create per-remote warning rule (partial pool / mode drift), distinct from
critical.
**Acceptance:** Partial-pool condition fires warning, not critical.

### CCS-17 · SMTP connector + templated messages naming failing remote
**Type:** Task · **Phase:** 3 · **Milestone:** M3
Reuse existing Kibana SMTP connector; template messages to name the failing
remote and cluster.
**Acceptance:** Alert email identifies the exact remote and severity.

### CCS-18 · Recovery action group (auto-resolve)
**Type:** Task · **Phase:** 3 · **Milestone:** M3
Configure recovery notifications so alerts auto-resolve when state clears.
**Acceptance:** State clearing triggers a recovery notification.

### CCS-19 · Staleness rule — detect dead collector
**Type:** Task · **Phase:** 3 · **Milestone:** M3
Alert when no verdict docs land in a defined window (collector dead).
**Acceptance:** Stopping the collector fires the staleness alert within the
window.

---

## Phase 4 — Scheduling & hardening

### CCS-20 · Schedule collector via cron
**Type:** Task · **Phase:** 4 · **Milestone:** M4
Schedule at the chosen interval; ensure alert window is wider than the interval
to absorb jitter.
**Acceptance:** Collector runs unattended on schedule with no false flaps.

### CCS-21 · Log rotation + per-tier runbook
**Type:** Task · **Phase:** 4 · **Milestone:** M4
Add logrotate config and write per-severity runbooks (what each alert means,
first response).
**Acceptance:** Logs rotate; runbook linked from alert messages.

### CCS-22 · Sustained-operation validation
**Type:** Task · **Phase:** 4 · **Milestone:** M4
Run in non-prod for a sustained period; confirm no false flaps and correct
recovery behavior under normal jitter.
**Acceptance:** Clean sustained run recorded; sign-off for prod rollout.
