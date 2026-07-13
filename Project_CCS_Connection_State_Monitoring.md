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

**Severity:** Healthy = connected + node count matches expected · Warning = connected but node count below expected (partial pool) · Critical = `connected: false`. "Expected" is per-remote, defined in Phase 0 — not assumed uniform across environments.

---

## 3. Architecture

```
Collector (cron, every N min)
  └─ ccs_health_check.py (connection-state mode)
       ├─ remote list from es_clusters.json
       ├─ API key from AWS Secrets Manager (boto3, runtime)
       ├─ GET /_remote/info per cluster, compare vs baseline
       └─ one verdict doc per remote → .ccs-health-monitor

State store: .ccs-health-monitor  (decouples measuring from reacting; retains history)

Alerting: Kibana Elasticsearch Query rules
       ├─ critical / warning tiers, grouped per remote (independent recovery)
       ├─ auto-recovery when state clears
       └─ staleness rule: no docs in window = dead collector
```

---

## 4. Phases

**Phase 0 — Definition & baseline.** Inventory every remote across the four clusters with expected `num_nodes_connected` and `mode`; finalize per-environment severity thresholds; confirm `skip_unavailable` posture; define the `.ccs-health-monitor` schema. *Exit: baseline table + schema + severity rules reviewed.*

**Phase 1 — Collector.** Build the connection-state probe in `ccs_health_check.py` (reusing `es_clusters.json`), with runtime Secrets Manager auth and a least-privilege key (`monitor` on clusters + write on the one index). *Exit: runs against all four clusters, writes correct verdicts.*

**Phase 2 — State store.** Create `.ccs-health-monitor` with explicit mapping and ILM/DSL retention; confirm hidden-index read access for the alerting role. *Exit: verdicts land, queryable, retention enforced.*

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
4. `.ccs-health-monitor` retention period
5. Which Kibana space hosts the rules, given the multi-space layout
6. Notification routing — single inbox vs per-environment recipients
