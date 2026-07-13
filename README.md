# CCS Remote Connection-State Degradation Monitoring

Monitors the connection state of remote Elasticsearch clusters as seen from each
local cluster, and flags any remote that is not in a healthy Connected state.
See [`Project_CCS_Connection_State_Monitoring.md`](./Project_CCS_Connection_State_Monitoring.md)
for the full plan.

## What the collector does (Phase 1)

`ccs_health_check.py` calls `GET /_remote/info` on each local cluster and, for
every remote, produces a verdict against its Phase-0 baseline:

| Severity | Condition |
|---|---|
| **HEALTHY** | `connected` **and** `num_nodes_connected >= expected_nodes` **and** mode matches |
| **WARNING** | connected but fewer nodes than expected (partial pool), or `mode` drift |
| **CRITICAL** | `connected: false`, or a baseline remote missing from `_remote/info`, or the local cluster is unreachable/auth/TLS failure |
| **INFO** | a remote present in `_remote/info` but not in the baseline (unmonitored remote) |

Each remote and each cluster is evaluated in isolation — one failure never aborts
the rest.

> **Phase-1 scope:** credentials are read from a **file**, and verdicts are
> **printed to screen only** (nothing is indexed into Elasticsearch). Secrets
> Manager, indexing to `.ccs-health-monitor`, alerting, scheduling, and hardening
> come in later phases.

## Setup

```bash
pip install -r requirements.txt

# 1. Fill in the local-cluster inventory + per-remote baselines
$EDITOR es_clusters.json

# 2. Create the (git-ignored) credentials file from the template
cp credentials.example.json credentials.json
$EDITOR credentials.json     # add each cluster's Elasticsearch API key
```

`api_key` is the base64 `id:api_key` string used in the
`Authorization: ApiKey <...>` header.

## Run

```bash
python3 ccs_health_check.py
# or with explicit paths / no color:
python3 ccs_health_check.py --clusters es_clusters.json --credentials credentials.json --no-color
```

Exit code is `0` when everything is HEALTHY/INFO and `1` when any WARNING/CRITICAL
verdict is present (useful once this is scheduled).

## Jira

`jira/JIRA_Tasks_CCS_Connection_State_Monitoring.md` and `jira/jira_import.csv`
contain the task breakdown for the Epic **CCS Remote Connection-State Degradation
Monitoring**, ready to import into Jira.
