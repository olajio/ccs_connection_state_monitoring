# CCS Remote Connection-State Degradation Monitoring

Detects degradation of the connection pool between local and remote
Elasticsearch clusters **before** it surfaces as missing or partial data in
federal dashboards.

Connection state is the earliest and cheapest degradation signal available: a
local cluster's connection pool to a remote can shrink or collapse long before a
user notices anything. And because `skip_unavailable: true` lets Elasticsearch
quietly drop a degraded remote from cross-cluster results, **a dashboard can look
perfectly healthy while being silently incomplete**. This project reads
lightweight cluster metadata on a schedule and turns that silent failure into an
explicit, alertable signal.

Full plan: [`Project_CCS_Connection_State_Monitoring.md`](./Project_CCS_Connection_State_Monitoring.md)
· Step-by-step setup: **[HOWTO.md](./HOWTO.md)**

---

## How it works

```
  ┌─────────────────────────────────────────────────────────────────────┐
  │  Collector — ccs_health_check.py  (cron or systemd timer, every N m) │
  │                                                                     │
  │   es_clusters.json ──► GET /_remote/info per LOCAL cluster           │
  │   credentials      ──► (file | AWS Secrets Manager | env)            │
  │                          │                                          │
  │                          ▼                                          │
  │              compare each remote vs its Phase-0 baseline             │
  │                          │                                          │
  │                          ▼                                          │
  │      one verdict document per remote, per cycle                      │
  └──────────────────────────┬──────────────────────────────────────────┘
                             ▼
              ┌──────────────────────────────┐
              │  ccs-health-monitor          │  state store: decouples
              │  (data stream + retention)   │  measuring from reacting,
              └──────────────┬───────────────┘  and retains history
                             ▼
              ┌──────────────────────────────────────────────┐
              │  Kibana Elasticsearch Query rules            │
              │   • CRITICAL   grouped per remote            │
              │   • WARNING    grouped per remote            │
              │   • staleness  no heartbeat = dead collector │
              │   • recovery action group → auto-resolve     │
              └──────────────────────────────────────────────┘
```

The collector never runs a search against a remote — it reads
`GET /_remote/info` metadata only, so probing production costs nothing
measurable.

---

## Verdicts

| Severity | Condition |
|---|---|
| **HEALTHY** | Connected, pool at or above the baseline, no configuration drift. |
| **WARNING** | Connected but the pool is partial, or `mode` / `initial_connect_timeout` / `skip_unavailable` has drifted from the baseline. |
| **CRITICAL** | `connected: false`, pool below the environment's critical floor, a baselined remote **missing** from `_remote/info`, or the local cluster could not be probed at all. |
| **INFO** | A remote present in `_remote/info` but absent from the baseline — an undocumented configuration change. |

Three behaviours are worth calling out, because each one closes a way this kind
of monitoring usually fails silently:

- **A missing remote is CRITICAL, not "healthy by omission."** A baselined remote
  that has vanished from `_remote/info` is real config drift, and treating its
  absence as nothing to report is how a removed remote goes unnoticed for weeks.
- **An unreachable local cluster produces one CRITICAL verdict, not zero.** A
  dead probe that emits nothing is indistinguishable from health.
- **Each remote and each cluster is evaluated in isolation.** One failing remote
  or one unreachable cluster never aborts evaluation of the others.

Severity thresholds are per environment, not global. Prod can call one-of-three
nodes CRITICAL while dev calls the same state a WARNING — see
[severity policy](docs/SCHEMA.md#severity_policy).

---

## Quick start

```bash
pip install -r requirements.txt
./run_tests.sh                      # 113 tests, no cluster or credentials needed
```

Try it against the bundled mock Elasticsearch before touching a real cluster:

```bash
# terminal 1
python3 tools/mock_es_server.py --port 9250 --scenario partial_pool
# terminal 2 — see HOWTO.md step 0 for the throwaway inventory
python3 ccs_health_check.py -c /tmp/mock_clusters.json --no-index --quiet
```

Against real clusters:

```bash
cp credentials.example.json credentials.json && chmod 600 credentials.json
$EDITOR credentials.json es_clusters.json

python3 ccs_health_check.py --show-config          # resolved config, no secrets
python3 ccs_health_check.py --no-index --no-color  # probe and print, write nothing
python3 ccs_health_check.py                        # probe, print, and index
```

```
========================================================================================
 CCS Remote Connection-State Health Check
 run_id=6ff47946915a4e9fbcb47359324e8cd1  ·  2026-06-02T14:35:00.512Z
========================================================================================

local cluster: prod  [prod]
  https://prod-es.example.com:9200
  status: WARNING   (probe 41 ms)
  !  [WARNING ] remote_prod_a
          partial pool: 2/3 nodes connected; skip_unavailable=true: this
          degradation can be silently dropped from CCS results
          codes: partial_pool, skip_unavailable_risk
  OK [HEALTHY ] remote_prod_b
          connected, 3/3 nodes, mode 'sniff'
          codes: healthy

----------------------------------------------------------------------------------------
 verdicts: HEALTHY=1  INFO=0  WARNING=1  CRITICAL=0
 OVERALL:  WARNING
----------------------------------------------------------------------------------------
```

**Exit codes:** `0` healthy · `1` degraded · `2` configuration error ·
`3` probing worked but the state store could not be written. Exit 3 outranks
exit 1 on purpose: if verdicts cannot land, the alerting layer is blind, and
that is the more urgent problem.

---

## Repository layout

```
ccs_health_check.py            The collector. This is the entry point.
run_tests.sh                   Full test suite — no cluster required.

es_clusters.json               Inventory + Phase-0 baselines + severity policy.
credentials.example.json       Template for the (git-ignored) credentials file.

ccs_monitor/                   Shared library
  config.py                      load and strictly validate es_clusters.json
  credentials.py                 file / Secrets Manager / env providers
  severity.py                    severity vocabulary and policy merging
  http.py                        sessions, TLS, timeouts, bounded retries
  probe.py                       GET /_remote/info
  evaluate.py                    baseline comparison → verdicts
  documents.py                   verdicts → ccs-health-monitor documents
  sink.py                        bulk writer for the state store
  report.py                      table / JSON / NDJSON output
  logging_setup.py               text and JSON logging

setup/                         Phase 2 — state store and security
  setup_state_store.py           creates the index template, lifecycle, stream
  setup_security.py              least-privilege roles and API keys
  index_template.json            the strict verdict mapping
  ilm_policy.json                rollover + retention skeleton
  roles/                         collector and alerting role definitions

alerting/                      Phase 3 — Kibana
  setup_alerting.py              creates the data view and the rules
  rules/                         critical, warning, staleness, unmonitored

tools/                         Phase 0 and testing
  baseline_inventory.py          inventory remotes; emit a starting baseline
  mock_es_server.py              a fake Elasticsearch for testing
  scenarios.json                 ten degradation scenarios to drive it

deploy/                        Phase 4 — scheduling and hardening
  install.sh                     one-shot host install (systemd or cron)
  crontab.example                cron schedule with jitter guidance
  systemd/                       hardened service + timer units
  logrotate/                     copytruncate rotation config

docs/
  SCHEMA.md                      every config key and document field
  RUNBOOK.md                     what to do when each alert fires

tests/                         113 tests: unit, mapping conformance, end-to-end
jira/                          the CCS-1 … CCS-22 task breakdown
```

---

## Project phases

| Phase | Delivered by | Status |
|---|---|---|
| **0** — Baseline and schema | `tools/baseline_inventory.py`, `es_clusters.json`, `docs/SCHEMA.md` | Tooling complete; the baseline itself is yours to review and sign off |
| **1** — Collector | `ccs_health_check.py`, `ccs_monitor/`, `setup/setup_security.py` | Complete |
| **2** — State store | `setup/setup_state_store.py`, `setup/index_template.json` | Complete |
| **3** — Alerting | `alerting/setup_alerting.py`, `alerting/rules/` | Complete |
| **4** — Scheduling and hardening | `deploy/`, `docs/RUNBOOK.md` | Complete |

Each phase is a step in [HOWTO.md](./HOWTO.md), with its exit criterion and how
to prove it.

---

## Design notes

**The state store is visible, not hidden.** The index is `ccs-health-monitor`,
not `.ccs-health-monitor`. A dot-prefixed index requires restricted-index grants
for the alerting role, is awkward to put behind a data view, and is hard to
inspect during an incident. The config parser rejects a dot-prefixed name so this
does not drift back.

**Every document in one cycle shares one timestamp.** A cycle therefore never
straddles two alerting windows, which is one less way for the rules to flap.

**The alert window must be wider than the probe interval.**
`alerting/setup_alerting.py` derives every window from
`--probe-interval-minutes` (3× by default) so the two cannot drift apart.
Recovery is delayed by up to one window as a result — that is the intended trade
against false flaps.

**A per-run heartbeat backs the staleness rule.** Every cycle writes one
`ccs.doc_type: run` document, so "the collector is dead" is distinguishable from
"the collector ran and had nothing to say". Without it, a dead collector and a
healthy estate look identical.

**Alerts group on `ccs.alert_key` (`local_cluster:remote`), not the remote name.**
Each remote alerts and recovers independently, and the same remote name on two
local clusters stays two separate alerts.

**The mapping is `dynamic: strict`.** A field the collector emits that the
mapping does not declare would be rejected at index time and the verdict silently
lost — so a test compares every emitted field against the mapping on every run.

**Credentials go through one interface.** File, AWS Secrets Manager, and
environment providers are interchangeable, which is what made the Phase-1
hardening step (CCS-8) a configuration change rather than a rewrite.

**Both connection modes are read correctly.** Sniff-mode remotes report
`num_nodes_connected` / `max_connections_per_cluster`; proxy-mode remotes report
`num_proxy_sockets_connected` / `max_proxy_socket_connections`. Both are read, so
a proxy-mode remote is never mis-scored as "no data available".

---

## Testing

```bash
./run_tests.sh          # everything
./run_tests.sh -v       # with test names
python3 -m unittest tests.test_evaluate -v
```

The suite needs no cluster, no credentials, and no network. `tests/test_integration.py`
runs the real collector CLI — argument parsing, HTTP, evaluation, document
building, bulk writes — against `tools/mock_es_server.py` on a loopback port, and
also renders every Kibana rule template to check its shape.

---

## Jira

`jira/JIRA_Tasks_CCS_Connection_State_Monitoring.md` and `jira/jira_import.csv`
hold the CCS-1 … CCS-22 breakdown for the epic, ready to import.
