# Schema reference

Two contracts are documented here:

1. **`es_clusters.json`** — the inventory and Phase-0 baseline the collector reads.
2. **`ccs-health-monitor`** — the verdict document the collector writes and the
   Kibana rules query (CCS-5).

Both are contracts. The document field names in particular are shared with
`setup/index_template.json` and `alerting/rules/*.json`; renaming one means
changing all three together, plus `docs/RUNBOOK.md`.

---

## 1. `es_clusters.json`

```
{
  "defaults":    { ... }   run-wide HTTP settings and the base severity policy
  "credentials": { ... }   which credential provider to use
  "state_store": { ... }   where verdicts are written
  "clusters":    [ ... ]   the local clusters to probe, with per-remote baselines
}
```

A `_comment` key is accepted anywhere and is ignored by the parser.

### `defaults`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `timeout_seconds` | number | `10` | Per-request timeout. |
| `retries` | integer | `2` | Retries for transient transport faults only. Auth and TLS failures are never retried. |
| `retry_backoff_seconds` | number | `0.5` | Backoff factor between retries. |
| `severity_policy` | object | see below | Base policy for every cluster. |

### `credentials`

| Key | Type | Meaning |
|---|---|---|
| `provider` | `file` \| `aws_secrets_manager` \| `env` | Where credentials come from. |
| `path` | string | `file` provider: path to the credentials file. Relative paths resolve against the inventory file, so cron's working directory does not matter. |
| `secret_id` | string | Secrets Manager: one secret holding a JSON object keyed by cluster name. |
| `secret_id_template` | string | Secrets Manager: one secret per cluster, e.g. `ccs/es/{cluster}`. Must contain `{cluster}`. |
| `region`, `profile` | string | AWS region and profile. |
| `env_prefix` | string | `env` provider prefix. Default `CCS_API_KEY_`, so cluster `prod` reads `CCS_API_KEY_PROD`. |

### `state_store`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `enabled` | boolean | `true` | When false, the collector reports but never indexes. |
| `index` | string | `ccs-health-monitor` | Write target. A dot-prefixed name is rejected — this project uses a visible index. |
| `mode` | `data_stream` \| `index` | `data_stream` | Data stream, or a write alias over rolling indices. |
| `lifecycle` | `dsl` \| `ilm` \| `none` | `dsl` | `dsl` requires `mode: data_stream`. `ilm` works with both. |
| `retention` | string | `90d` | How long verdicts are kept (Phase-0 decision #4). |
| `cluster` | string | — | Inventory cluster hosting the store; its URL, TLS settings, and credential are inherited. |
| `base_url` | string | — | Explicit URL, for a dedicated monitoring cluster. Overrides `cluster`'s URL. |
| `credentials_key` | string | — | Credential key for the store, if it differs from the cluster's. |
| `index_template`, `ilm_policy` | string | derived from `index` | Object names created by `setup/setup_state_store.py`. |
| `number_of_shards`, `number_of_replicas` | integer | `1`, `1` | Index settings. |
| `rollover_max_age`, `rollover_max_primary_shard_size` | string | `30d`, `10gb` | ILM rollover thresholds. |
| `write_run_document` | boolean | `true` | Emit the per-run heartbeat the staleness rule watches. Leave this on. |

### `clusters[]`

| Key | Type | Required | Meaning |
|---|---|---|---|
| `name` | string | yes | Local cluster name. Also the credential key unless `credentials_key` is set. |
| `base_url` | string | yes | `http(s)://host:port`. |
| `environment` | string | no | Environment label indexed as `ccs.environment`. Defaults to `name`. |
| `verify_certs` | boolean | no | TLS verification. Default `true`. |
| `ca_cert` | string | no | CA bundle path. Wins over `verify_certs`; combining it with `verify_certs: false` is a configuration error rather than a silent downgrade. |
| `timeout_seconds`, `retries`, `retry_backoff_seconds` | | no | Per-cluster overrides of `defaults`. |
| `credentials_key` | string | no | Credential key, when it differs from `name`. |
| `enabled` | boolean | no | Set false to park a cluster without deleting its baseline. |
| `severity_policy` | object | no | Cluster-level policy overrides. |
| `expected_remotes` | object | yes-ish | The Phase-0 baseline, keyed by remote name. An empty object means every remote reports as an unmonitored `INFO`. |

### `expected_remotes.<remote>`

| Key | Type | Meaning |
|---|---|---|
| `expected_nodes` | integer | Baseline connected nodes (sniff) or proxy sockets (proxy). |
| `expected_mode` | `sniff` \| `proxy` | Baseline connection mode. |
| `expected_skip_unavailable` | boolean | Documented `skip_unavailable` posture (CCS-4). Drift from it is a WARNING. |
| `expected_initial_connect_timeout` | string | Baseline `initial_connect_timeout`, e.g. `"30s"`. Only checked when set. |
| `description` | string | Free-text note. |
| `severity_policy` | object | Remote-level policy overrides — the most specific layer. |

### `severity_policy`

Merged **defaults → cluster → remote**, most specific winning.

| Key | Type | Default | Applies when |
|---|---|---|---|
| `disconnected` | severity | `CRITICAL` | `connected: false`. |
| `partial_pool` | severity | `WARNING` | Connected, but fewer nodes than `expected_nodes`. |
| `critical_below_nodes` | integer \| null | `1` | Connected with fewer than this many nodes. The default of `1` makes "connected with zero nodes" a collapsed pool. Set `2` in prod to make one-of-three critical (Phase-0 decision #3). `null` disables the escalation. |
| `mode_drift` | severity | `WARNING` | Observed `mode` differs from the baseline. |
| `timeout_drift` | severity | `WARNING` | Observed `initial_connect_timeout` differs from the baseline. |
| `skip_unavailable_drift` | severity | `WARNING` | Observed `skip_unavailable` differs from the documented posture. |
| `missing_remote` | severity | `CRITICAL` | A baselined remote is absent from `_remote/info`. |
| `unreachable_cluster` | severity | `CRITICAL` | The local cluster could not be probed. |
| `unmonitored_remote` | severity | `INFO` | A remote is present but not baselined. |
| `escalate_warning_when_skip_unavailable` | boolean | `false` | Promotes a WARNING to CRITICAL on a `skip_unavailable: true` remote, because that degradation is dropped from results silently. |

Severity values are `HEALTHY`, `INFO`, `WARNING`, `CRITICAL`. Unknown keys and
invalid values are rejected at load time with the path that caused it — a typo
must never become a silently wrong baseline.

---

## 2. The verdict document

One document per remote per cycle, plus one per unreachable cluster, plus one
run heartbeat. Documents are append-only, so history is retained and every cycle
is queryable after the fact. Null fields are omitted.

### Common fields

| Field | Type | Meaning |
|---|---|---|
| `@timestamp` | date | Cycle time. **Every document from one cycle shares this value**, so a cycle never straddles two alerting windows. |
| `event.kind` | keyword | `state` for verdicts, `metric` for the run heartbeat. |
| `event.dataset` | keyword | `ccs.connection_state`. |
| `event.module` | keyword | `ccs_health_check`. |
| `event.severity` | byte | Numeric severity, same as `ccs.severity_rank`. |
| `event.duration_ms` | float | Run heartbeat only: whole-cycle duration. |
| `run.id` | keyword | Hex id shared by every document in the cycle. |
| `run.version` | keyword | Collector version. |
| `run.host`, `run.user`, `run.pid`, `run.platform` | keyword/integer | Which collector produced it. |

### `ccs.*`

| Field | Type | Meaning |
|---|---|---|
| `ccs.doc_type` | keyword | `remote`, `cluster` (probe failure), or `run` (heartbeat). |
| `ccs.local_cluster` | keyword | The local cluster that was probed. |
| `ccs.environment` | keyword | Environment label. |
| `ccs.remote` | keyword | Remote name. Absent on `cluster` and `run` documents. |
| `ccs.alert_key` | keyword | `<local_cluster>:<remote>`, or `<local_cluster>:_cluster`, or `_run`. **The grouping field for every rule** — grouping on the bare remote name would merge a remote that exists on several local clusters into one alert. |
| `ccs.severity` | keyword | `HEALTHY` / `INFO` / `WARNING` / `CRITICAL`. |
| `ccs.severity_rank` | byte | `0` / `1` / `2` / `3`, for sorting and range queries. |
| `ccs.monitored` | boolean | False for an unmonitored remote. The informational rule keys off this. |
| `ccs.connected` | boolean | As reported by `_remote/info`. |
| `ccs.nodes.expected` | integer | Baseline node count. |
| `ccs.nodes.actual` | integer | `num_nodes_connected`, or `num_proxy_sockets_connected` in proxy mode. |
| `ccs.nodes.max_configured` | integer | `max_connections_per_cluster` / `max_proxy_socket_connections`. |
| `ccs.nodes.deficit` | integer | `expected - actual`, floored at 0. |
| `ccs.mode.expected` / `.actual` / `.drift` | keyword/boolean | Baseline mode, observed mode, and whether they differ. |
| `ccs.initial_connect_timeout.expected` / `.actual` / `.drift` | keyword/boolean | Same, for the connect timeout. |
| `ccs.skip_unavailable` | boolean | Observed flag. `true` means degradation here can be dropped from results silently. |
| `ccs.skip_unavailable_expected` | boolean | Documented posture. |
| `ccs.skip_unavailable_drift` | boolean | Whether the posture changed. |
| `ccs.seeds` | keyword[] | Seed addresses (sniff mode). |
| `ccs.proxy_address` | keyword | Proxy address (proxy mode). |
| `ccs.reason` | text + `.keyword` | Human-readable explanation. This is what the alert email prints. |
| `ccs.reason_codes` | keyword[] | Stable machine-readable codes; see below. |
| `ccs.probe.ok` | boolean | Whether the probe itself succeeded. |
| `ccs.probe.duration_ms` | float | Probe round-trip time. |
| `ccs.probe.error` | text + `.keyword` | Probe error message, when it failed. |
| `ccs.probe.error_kind` | keyword | `tls_error`, `auth_error`, `connect_timeout`, `read_timeout`, `connection_error`, `credential_error`, `server_error`, `client_error`, `not_found`, `invalid_json`, `too_many_redirects`, `invalid_url`, `request_error`. |

### Run heartbeat extras (`ccs.doc_type: run`)

| Field | Type | Meaning |
|---|---|---|
| `ccs.clusters_total` | integer | Clusters attempted this cycle. |
| `ccs.clusters_probed_ok` | integer | Clusters probed successfully. |
| `ccs.clusters_unreachable` | integer | Clusters that failed. |
| `ccs.verdicts_total` | integer | Verdicts produced. |
| `ccs.counts.healthy` / `.info` / `.warning` / `.critical` | integer | Verdict counts by severity. |

### Reason codes

| Code | Severity (default) | Meaning |
|---|---|---|
| `healthy` | HEALTHY | At baseline, no drift. |
| `disconnected` | CRITICAL | `connected: false`. |
| `pool_collapsed` | CRITICAL | Connected but below `critical_below_nodes`. |
| `partial_pool` | WARNING | Connected but below `expected_nodes`. |
| `mode_drift` | WARNING | Connection mode changed. |
| `timeout_drift` | WARNING | `initial_connect_timeout` changed. |
| `skip_unavailable_drift` | WARNING | `skip_unavailable` posture changed. |
| `skip_unavailable_risk` | — | Added to any non-healthy verdict on a skippable remote. |
| `missing_remote` | CRITICAL | Baselined remote absent from `_remote/info`. |
| `unmonitored_remote` | INFO | Present but not baselined. |
| `no_baseline_configured` | INFO | Accompanies `unmonitored_remote`. |
| `unreachable_cluster` | CRITICAL | The local cluster could not be probed. The probe's `error_kind` is appended as a second code. |
| `malformed_remote_info` | CRITICAL | The entry had no boolean `connected` field. A body we cannot trust is a fault, not health. |

### Example — a partial pool on a skippable remote

```json
{
  "@timestamp": "2026-06-02T14:35:00.512Z",
  "event": { "kind": "state", "category": "network",
             "dataset": "ccs.connection_state", "module": "ccs_health_check", "severity": 2 },
  "run": { "id": "9f2c...", "version": "1.0.0", "host": "elk-collector-01" },
  "ccs": {
    "doc_type": "remote",
    "local_cluster": "prod", "environment": "prod",
    "remote": "remote_prod_a", "alert_key": "prod:remote_prod_a",
    "severity": "WARNING", "severity_rank": 2,
    "monitored": true, "connected": true,
    "nodes": { "expected": 3, "actual": 2, "max_configured": 3, "deficit": 1 },
    "mode": { "expected": "sniff", "actual": "sniff", "drift": false },
    "skip_unavailable": true, "skip_unavailable_expected": true,
    "reason": "partial pool: 2/3 nodes connected; skip_unavailable=true: this degradation can be silently dropped from CCS results",
    "reason_codes": ["partial_pool", "skip_unavailable_risk"],
    "probe": { "ok": true, "duration_ms": 41.2 }
  }
}
```

### Mapping notes

`setup/index_template.json` sets `dynamic: strict`, so a field the collector
emits but the mapping does not declare is **rejected at index time** — the
verdict is silently lost. `tests/test_documents.py::MappingConformanceTests`
compares every emitted field against the mapping on every test run, which is
what keeps that from shipping.

### Useful queries

```
# Current state of every remote (latest verdict each)
GET ccs-health-monitor/_search
{ "size": 0, "query": { "term": { "ccs.doc_type": "remote" } },
  "aggs": { "by_remote": { "terms": { "field": "ccs.alert_key", "size": 200 },
    "aggs": { "latest": { "top_hits": { "size": 1, "sort": [{ "@timestamp": "desc" }],
      "_source": ["ccs.severity", "ccs.reason", "@timestamp"] } } } } } }

# Everything that is not healthy right now
GET ccs-health-monitor/_search
{ "query": { "bool": { "filter": [
    { "range": { "@timestamp": { "gte": "now-15m" } } },
    { "range": { "ccs.severity_rank": { "gte": 2 } } } ] } },
  "sort": [{ "@timestamp": "desc" }] }

# Is the collector alive?
GET ccs-health-monitor/_search
{ "size": 1, "query": { "term": { "ccs.doc_type": "run" } },
  "sort": [{ "@timestamp": "desc" }] }
```
