# Runbook — CCS remote connection-state alerts

**Scope:** connection state between local and remote Elasticsearch clusters
(dev, qa, prod, ccs). This layer answers one question: *can the local cluster
still reach this remote, and is the pool the size we agreed it should be?*

It does **not** cover remote internal health, query latency, or index resolution
— those are separate layers with their own runbooks.

**Alert sources:** the Kibana rules created by `alerting/setup_alerting.py`.
**Underlying data:** `ccs-health-monitor` (see [SCHEMA.md](./SCHEMA.md)).

---

## First 60 seconds, for any alert

The alert email names the failing remote as `local_cluster:remote` — that is
`ccs.alert_key`. Get the current state directly:

```bash
cd /opt/ccs-health-monitor
venv/bin/python ccs_health_check.py --clusters es_clusters.json \
    --no-index --no-color --problems-only
```

That runs the exact same probe the collector runs, prints the current verdict
for every remote, and writes nothing. It is always safe to run, including in
prod: it is one metadata read per cluster.

For history rather than the present moment, in Discover on the
**CCS Health Monitor** data view:

```
ccs.alert_key : "prod:remote_prod_a"
```

sorted by `@timestamp` descending. That shows exactly when the state changed and
what the collector saw at each cycle.

---

## CRITICAL

**Meaning:** the connection to a remote is gone, the remote has disappeared from
the local cluster's configuration, or the local cluster could not be probed at
all. **Cross-cluster searches touching that remote may be returning incomplete
results right now** — and where `skip_unavailable: true`, they are doing so
without any error the user can see.

Read `ccs.reason_codes` in the alert to tell the four cases apart.

### `disconnected` — `connected: false`

The local cluster has no live connection to the remote.

1. Confirm from the local cluster:
   `GET /_remote/info` — check the entry's `connected` and `num_nodes_connected`.
2. Is the remote cluster itself up? Check its own health and its nodes.
3. Network path: can the local nodes reach the remote's transport port (9300 by
   default for sniff, the proxy port for proxy mode)? Firewall changes and
   security-group edits are the usual cause.
4. Certificates: for a TLS-secured transport, an expired or rotated remote cert
   drops the pool. Check the local cluster's logs for handshake failures.
5. If the remote is intentionally down (planned maintenance), silence the rule
   for that `alert_key` for the maintenance window rather than disabling the
   whole rule.

### `missing_remote` — a baselined remote is absent from `_remote/info`

The remote is not merely disconnected; the local cluster no longer has it
configured. This is configuration drift, and it is almost always a human action.

1. Check recent cluster-settings changes:
   `GET /_cluster/settings?include_defaults=false` and look under
   `persistent.cluster.remote`.
2. If the removal was intentional, remove the remote from `es_clusters.json` and
   let the change go through review — otherwise this alert fires forever.
3. If it was not intentional, restore the remote's configuration and confirm the
   next collector cycle returns HEALTHY.

### `pool_collapsed` — connected, but below the critical node floor

Connected with fewer nodes than `critical_below_nodes` allows (in prod, fewer
than 2). The connection exists but has almost no capacity behind it.

1. `GET /_remote/info` for the current count.
2. Check how many remote nodes are actually up, and whether the seed nodes are
   among the ones still running — in sniff mode, losing every seed node stops the
   pool refilling even while the cluster is healthy.
3. Treat as a partial outage of that remote.

### `unreachable_cluster` — the probe itself failed

The collector could not read `_remote/info` from a **local** cluster, so the
state of every remote on it is unknown. Note the `error_kind` in the alert:

| `error_kind` | What to check |
|---|---|
| `auth_error` | The API key expired or was revoked. Re-mint it: `setup/setup_security.py --create-api-key`. |
| `tls_error` | CA bundle or server certificate. Check `ca_cert` in `es_clusters.json` and the cert's expiry. |
| `connect_timeout`, `connection_error` | The cluster or its load balancer is down, or a firewall rule changed. |
| `read_timeout` | The cluster is up but overloaded — check its own health. |
| `credential_error` | The credential is missing for this cluster: absent from `credentials.json`, or the Secrets Manager secret/IAM permission is wrong. |
| `server_error` | The cluster returned 5xx. Check its logs. |

Until this clears, treat that cluster's remotes as **unknown, not healthy**.

---

## WARNING

**Meaning:** the remote is still connected and serving, but it is not in the
state you agreed it should be in. Searches still work. Investigate in hours,
not at 03:00.

### `partial_pool`

Fewer connected nodes than the baseline. Common and often self-healing: a remote
node restarted, or a rolling upgrade is in progress.

1. If a maintenance window is running, expect it to clear on its own — the alert
   auto-recovers once verdicts stop matching.
2. If it persists past one cycle with no maintenance, check remote node health
   and whether a node left the remote cluster permanently.
3. If the remote has **permanently** shrunk, the fix is to update
   `expected_nodes` in `es_clusters.json` — not to silence the rule.

### `mode_drift`

The connection mode changed between `sniff` and `proxy` since the baseline.
Nobody changes this by accident: someone reconfigured the remote. Confirm the
change was intended, then either revert it or update `expected_mode`.

### `timeout_drift`

`initial_connect_timeout` no longer matches the baseline. Low urgency on its own,
but it means someone edited remote-cluster settings — check what else changed in
the same edit.

### `skip_unavailable_drift`

The `skip_unavailable` posture changed. This one deserves more attention than its
tier suggests: flipping it to `true` means future degradation on that remote will
be **dropped from search results silently**. Confirm it was a deliberate decision
and that the affected dashboards can tolerate partial results.

### `skip_unavailable_risk`

Not a tier of its own — this code rides along on any non-healthy verdict for a
remote with `skip_unavailable: true`. It is the reminder that this degradation
produces no user-visible error. Where the environment sets
`escalate_warning_when_skip_unavailable: true` (prod does), the verdict has
already been promoted to CRITICAL.

---

## STALE — no verdicts at all

**Meaning:** no run heartbeat has been written for the staleness window. The
collector is dead, its host is down, or it cannot write to the state store.

**This is the most dangerous alert in the set**, because while it is firing every
other rule is quiet — and quiet looks exactly like healthy.

1. Is the schedule running?
   ```bash
   systemctl list-timers ccs-health-monitor.timer
   systemctl status ccs-health-monitor.service
   journalctl -u ccs-health-monitor.service -n 50
   # or, under cron:
   sudo -u ccs-monitor crontab -l
   tail -n 50 /var/log/ccs-health-monitor/collector.log
   ```
2. Run it by hand and read the exit code:
   ```bash
   cd /opt/ccs-health-monitor
   venv/bin/python ccs_health_check.py --clusters es_clusters.json --no-color; echo "exit=$?"
   ```
   | Exit | Meaning |
   |---|---|
   | 0 | Healthy. The schedule is the problem, not the collector. |
   | 1 | Degraded remotes — but the collector works, so the staleness cause is elsewhere. |
   | 2 | Configuration or credential error. The message names the file and key. |
   | 3 | Probing works but the state store is unwritable. See step 3. |
3. Check the state store:
   ```bash
   venv/bin/python ccs_health_check.py --clusters es_clusters.json --check-state-store
   ```
   If it reports MISSING, re-run `setup/setup_state_store.py`. If it reports an
   auth error, the collector's key lost its write privilege on the index.
4. Disk and log space on the collector host — a full disk stops the log write and
   can take the run with it.

Until verdicts resume, CCS connection state is **unknown**.

---

## INFO — unmonitored remote

A remote exists on a local cluster but is absent from the Phase-0 baseline, so
nothing is judging its connection state. Not a fault; it is config drift you
should close out.

Either add it to `expected_remotes` in `es_clusters.json` (with a real reviewed
baseline — see `tools/baseline_inventory.py`), or remove it from the cluster.

---

## Maintenance tasks

### A remote's baseline has genuinely changed

Edit `es_clusters.json`, then verify before it goes live:

```bash
venv/bin/python ccs_health_check.py --clusters es_clusters.json --show-config
venv/bin/python ccs_health_check.py --clusters es_clusters.json --no-index --no-color
```

### Change the probe interval

The alert window must stay wider than the interval, or cron jitter produces
windows with no verdict in them and the rules flap. Change both together:

```bash
# 1. the schedule (systemd timer OnUnitActiveSec, or the cron expression)
# 2. the rules, which re-derive every window from the interval:
python3 alerting/setup_alerting.py --kibana-url https://kibana.example.com \
    --space <space> --kibana-user <user> \
    --connector-name "<SMTP connector>" --to <recipient> \
    --probe-interval-minutes <new interval>
```

### Rotate the collector's API key

```bash
python3 setup/setup_security.py --clusters es_clusters.json --cluster ccs \
    --admin-user elastic --create-api-key --key-name ccs-collector-$(date +%Y%m)
# Paste into credentials.json (or update the Secrets Manager secret), then:
venv/bin/python ccs_health_check.py --clusters es_clusters.json --no-index
# Only after that succeeds, invalidate the old key in Kibana → Stack Management → API keys.
```

### Silence an alert during planned maintenance

Snooze the specific alert instance for its `alert_key` in
**Kibana → Stack Management → Rules**. Do not disable the rule: that silences
every other remote it covers as well.

---

## Escalation

| Situation | Action |
|---|---|
| CRITICAL on a prod remote, cause not found in 15 minutes | Escalate to the ELK Platform on-call, and notify the dashboard owners that federal dashboards may be showing partial data. |
| STALE for more than one staleness window | Escalate — connection state is unmonitored while it lasts. |
| Repeated flapping between alert and recovery | Do not silence it. Check that the alert window is genuinely wider than the probe interval (see above); flapping usually means those two drifted apart. |
