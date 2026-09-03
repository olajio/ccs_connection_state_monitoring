# Project Plan: CCS Remote Connection-State Degradation Monitoring

**Project ID:** 13.1 (sub-project of Cross-Cluster Search Health Check)
**Owner:** Olamide Olajide — Observability Engineer, ITSMA Monitoring & Analytics / ELK Platform
**Environments:** HedgeServ federal dashboards — dev, qa, prod, ccs · **Compliance:** FedRAMP / FISMA · **Target:** Q2–Q4 2026

---

## 1. Objective & rationale

Detect and alert on degradation of the connection pool between local and remote Elasticsearch clusters, before it surfaces as missing or partial data in federal dashboards.

Connection state is the earliest, cheapest degradation signal: the local pool can silently shrink or collapse long before a user notices. Because `skip_unavailable` can quietly drop a degraded remote from results, a healthy-looking dashboard can be silently incomplete. This layer reads lightweight cluster metadata (not probe queries) to turn that silent failure into an explicit signal.

**Scope:** connection-state layer only. Excludes remote internal health (Layer 2), query-path latency (Layer 3), and index/dependency resolution (Layer 4), all tracked separately. No auto-remediation in this phase.

---

## 2. Monitored signals

From `GET /_remote/info` per remote, each probe cycle:

| Signal | Source | Degradation meaning |
|---|---|---|
| Connection presence | `connected` | `false` = pool collapsed / remote unreachable |
| Pool saturation | `num_nodes_connected` vs `max_connections_per_cluster` | Fewer than expected = partial degradation |
| Connection mode | `mode` (`sniff`/`proxy`) | Unexpected mode change |
| Connect timeout | `initial_connect_timeout` | Drift from baseline |
| Skip-unavailable | `skip_unavailable` | If `true`, degradation may be silent downstream |
| Remote presence in inventory | baseline vs `_remote/info` keys | Baseline remote **absent** from response = config drift / removed remote |
| Local cluster reachability | HTTP call to local `_remote/info` | Local cluster unreachable = collector cannot measure at all |

**Severity:** Healthy = connected + node count matches expected · Warning = connected but node count below expected (partial pool), or connection `mode` drifted from baseline · Critical = `connected: false`, **a baseline remote missing from `_remote/info` entirely**, or the **local cluster is unreachable** (probe failed). Remotes present in `_remote/info` but *not* in the baseline are surfaced as an informational "unmonitored remote" signal (possible undocumented config change). "Expected" is per-remote, defined in Phase 0 — not assumed uniform across environments.

**Isolation:** each remote is evaluated independently, and each local cluster is probed independently — one failing remote or one unreachable cluster must never abort evaluation of the others. A per-cluster probe failure yields a single Critical verdict for that cluster rather than a silent gap.

---

## 3. Architecture

```
Collector (cron, every N min)
  └─ ccs_health_check.py (connection-state mode)
       ├─ remote list from es_clusters.json
       ├─ API key from AWS Secrets Manager (boto3, runtime)
       ├─ GET /_remote/info per cluster, compare vs baseline
       └─ one verdict doc per remote → ccs-health-monitor

State store: ccs-health-monitor  (decouples measuring from reacting; retains history)

Alerting: Kibana Elasticsearch Query rules
       ├─ critical / warning tiers, grouped per remote (independent recovery)
       ├─ auto-recovery when state clears
       └─ staleness rule: no docs in window = dead collector
```

---

## 4. Phases

**Phase 0 — Definition & baseline.** Inventory every remote across the four clusters with expected `num_nodes_connected` and `mode`; finalize per-environment severity thresholds; confirm `skip_unavailable` posture; define the `ccs-health-monitor` schema. *Exit: baseline table + schema + severity rules reviewed.*

**Phase 1 — Collector.** Build the connection-state probe in `ccs_health_check.py` (reusing `es_clusters.json`), with runtime Secrets Manager auth and a least-privilege key (`monitor` on clusters + write on the one index). *Exit: runs against all four clusters, writes correct verdicts.*

**Phase 2 — State store.** Create `ccs-health-monitor` with explicit mapping and ILM/DSL retention; confirm read access for the alerting role. The index name is deliberately **not** dot-prefixed: a visible index needs no restricted-index grants, appears in Discover and data views without extra configuration, and is far easier to inspect during an incident. *Exit: verdicts land, queryable, retention enforced.*

**Phase 3 — Alerting.** Kibana ES Query rules for critical/warning, grouped per remote; existing SMTP connector with templated messages naming the failing remote; recovery action group; staleness rule. *Exit: induced non-prod failure fires the right tier and auto-resolves.*

**Phase 4 — Scheduling & hardening.** Cron at chosen interval with alert window wider than the interval to absorb jitter; logrotate; per-tier runbook. *Exit: sustained unattended operation, no false flaps.*

---

## 5. Milestones

| Milestone | Target |
|---|---|
| M0 — Baseline + schema signed off | Early Q2 2026 |
| M1 — Collector probing all clusters | Mid Q2 2026 |
| M2 — State store live with retention | Late Q2 2026 |
| M3 — Alerting + staleness validated | Q3 2026 |
| M4 — Scheduled, hardened, runbooked | Q3–Q4 2026 |

---

## 6. Success criteria

Every remote probed on schedule · collapsed pool → critical within one probe+rule cycle · partial pool → warning, distinct from critical · alerts auto-resolve on recovery · dead collector detected via staleness · no false flaps under normal jitter.

---

## 7. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Cron jitter causes false recovery flaps | Alert window wider than probe interval |
| Collector dies silently → false health | Staleness rule on document recency |
| Uniform thresholds misfire per environment | Per-remote baseline defined in Phase 0 |
| `skip_unavailable: true` masks degradation | Capture the flag; weight severity accordingly |
| Over-privileged credential | Least-privilege: `monitor` + write to one index |
| Probe load on prod remotes | Metadata reads (`_remote/info`), not query probes |

---

## 8. Dependencies

`es_clusters.json` inventory · AWS Secrets Manager (boto3) · existing Kibana SMTP connector · Kibana space placement for rules + data view (space-scoped) · least-privilege service account provisioning.

---

## 9. Open decisions (resolve in Phase 0)

1. Probe interval — detection speed vs cluster load
2. Per-remote expected `num_nodes_connected` baselines
3. Per-environment severity thresholds (is one-of-three down warning or critical in prod?)
4. `ccs-health-monitor` retention period
5. Which Kibana space hosts the rules, given the multi-space layout
6. Notification routing — single inbox vs per-environment recipients

---

## 10. Plan review notes (corrections applied)

The following gaps were identified during review and folded into the plan above; they are the behaviors the Phase 1 collector implements:

- **Missing-remote detection.** A remote that exists in the Phase 0 baseline but does not appear in `_remote/info` at all is a real degradation/config-drift signal, not "healthy by omission." It is now classified **Critical**, distinct from `connected: false`.
- **Local-cluster-unreachable handling.** If the collector cannot reach a local cluster's `_remote/info` endpoint (network, auth, TLS), that cluster must emit a single **Critical** verdict rather than produce no verdict — otherwise a dead probe looks like health. (The Phase 3 staleness rule remains the backstop for a fully dead collector.)
- **Per-remote / per-cluster isolation.** One failing remote or one unreachable cluster must never abort the evaluation loop for the others. Each remote and each cluster is evaluated in isolation.
- **Unexpected/unmonitored remotes.** Remotes seen in `_remote/info` but absent from the baseline are surfaced as an informational signal so undocumented config changes are visible.
- **Testing/first-run (this phase).** The initial collector prints verdicts to screen only — no writes to `ccs-health-monitor` — for validation. Indexing, alerting, scheduling, and hardening (Phases 2–4) follow. Credentials are read from a local file in this phase and refactored to AWS Secrets Manager in Phase 1 hardening.
