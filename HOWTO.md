# HOWTO — set up CCS connection-state monitoring, step by step

This walks the whole project from an empty checkout to a scheduled, alerting,
runbooked collector. It follows the project phases, and each step says what it
produces and how to prove it worked before moving on.

**You can do steps 0–4 with no Elasticsearch at all.** Step 0 runs everything
against a bundled mock cluster, so you can see every alert condition before
touching a real one.

| Step | Phase | Jira | Produces |
|---|---|---|---|
| [0. Rehearse against the mock](#step-0) | — | — | Confidence, and a working local demo |
| [1. Install](#step-1) | — | — | Dependencies and a passing test suite |
| [2. Provision credentials](#step-2) | 1 | CCS-7, CCS-9 | A least-privilege API key |
| [3. Baseline the remotes](#step-3) | 0 | CCS-1, CCS-2, CCS-4 | A reviewed `es_clusters.json` |
| [4. Set severity policy](#step-4) | 0 | CCS-3 | Per-environment thresholds |
| [5. Run the collector](#step-5) | 1 | CCS-6, CCS-10 | Correct verdicts on screen |
| [6. Create the state store](#step-6) | 2 | CCS-11, CCS-12 | `ccs-health-monitor` with retention |
| [7. Index verdicts](#step-7) | 2 | CCS-13, CCS-14 | Verdicts landing and queryable |
| [8. Create the alerting rules](#step-8) | 3 | CCS-15…19 | Alerts that fire and auto-resolve |
| [9. Validate with an induced failure](#step-9) | 3 | CCS-15 | Proof the whole chain works |
| [10. Schedule and harden](#step-10) | 4 | CCS-20, CCS-21 | Unattended operation |
| [11. Move to Secrets Manager](#step-11) | 1 | CCS-8 | No key files in the deploy path |
| [12. Sustained validation](#step-12) | 4 | CCS-22 | Sign-off for prod |

---

<a name="step-0"></a>
## Step 0 — Rehearse the whole thing against the mock cluster

Before touching a real cluster, drive every alert condition locally. This costs
five minutes and is the fastest way to understand what the collector classifies
and why.

```bash
pip install -r requirements.txt

# Terminal 1 — a fake Elasticsearch serving a healthy topology
python3 tools/mock_es_server.py --port 9250 --scenario healthy
```

```bash
# Terminal 2 — point a throwaway inventory at it
cat > /tmp/mock_clusters.json <<'JSON'
{
  "credentials": { "provider": "env", "env_prefix": "CCS_API_KEY_" },
  "state_store": { "enabled": true, "cluster": "dev", "index": "ccs-health-monitor" },
  "clusters": [{
    "name": "dev", "environment": "dev",
    "base_url": "http://127.0.0.1:9250", "verify_certs": false,
    "expected_remotes": {
      "remote_dev_a": { "expected_nodes": 3, "expected_mode": "sniff",
                        "expected_skip_unavailable": false,
                        "expected_initial_connect_timeout": "30s" },
      "remote_dev_b": { "expected_nodes": 2, "expected_mode": "proxy",
                        "expected_skip_unavailable": false,
                        "expected_initial_connect_timeout": "30s" }
    }
  }]
}
JSON

export CCS_API_KEY_DEV=dGVzdDp0ZXN0     # the mock accepts any non-empty key

python3 ccs_health_check.py -c /tmp/mock_clusters.json --no-index --quiet
```

You should see two HEALTHY verdicts and exit code 0. Now restart the mock with
each scenario in turn (Ctrl-C, change `--scenario`, re-run the collector):

| `--scenario` | Expected verdict |
|---|---|
| `healthy` | HEALTHY · exit 0 |
| `partial_pool` | WARNING — `1/3 nodes connected` |
| `disconnected` | CRITICAL — `connected=false` |
| `missing_remote` | CRITICAL — baselined remote absent from `_remote/info` |
| `mode_drift` | WARNING — `sniff` became `proxy` |
| `timeout_drift` | WARNING — `initial_connect_timeout` changed |
| `silent_degradation` | WARNING — partial pool on a `skip_unavailable: true` remote |
| `unmonitored_remote` | INFO — a remote nobody baselined |
| `no_remotes` | CRITICAL ×2 — every baselined remote gone |
| `unreachable` | CRITICAL ×1 — one verdict for the whole cluster |

Two things worth doing here, because they are the parts people get wrong later:

```bash
# See exactly what would be indexed, byte for byte, without indexing it:
python3 ccs_health_check.py -c /tmp/mock_clusters.json --no-index --format ndjson --quiet

# Create the state store on the mock, then write to it for real:
python3 setup/setup_state_store.py -c /tmp/mock_clusters.json
python3 ccs_health_check.py -c /tmp/mock_clusters.json --quiet
curl -s http://127.0.0.1:9250/_mock/docs | python3 -m json.tool | head -40
```

---

<a name="step-1"></a>
## Step 1 — Install

**Requirements:** Python 3.9+ and network access to each local cluster's HTTPS
port. The collector reads metadata only; it never runs a search.

```bash
git clone <this repo> ccs-health-monitor
cd ccs-health-monitor

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

./run_tests.sh
```

**Prove it:** `run_tests.sh` ends with `All checks passed.` The suite needs no
cluster, no credentials, and no network — it runs against the bundled mock.

---

<a name="step-2"></a>
## Step 2 — Provision a least-privilege credential (CCS-7, CCS-9)

The collector needs exactly two privileges: cluster `monitor` (which is what
`GET /_remote/info` requires) and the right to append documents to one index.
Nothing else. `setup/setup_security.py` creates both roles and mints a key that
cannot exceed them.

```bash
# Review what it will create:
python3 setup/setup_security.py --url https://ccs-es.example.com:9200 --dry-run

# Create the roles and a collector key (needs an administrative credential):
python3 setup/setup_security.py \
    --url https://ccs-es.example.com:9200 \
    --ca-cert /etc/pki/agency-ca.pem \
    --admin-user elastic \
    --create-api-key --key-name ccs-collector-prod
```

It prints the key once, base64-encoded as `id:api_key`. Put it in the
git-ignored credentials file:

```bash
cp credentials.example.json credentials.json
chmod 600 credentials.json
$EDITOR credentials.json          # one entry per local cluster
```

Repeat per cluster. The collector warns if `credentials.json` is group- or
world-readable.

> **Why a file first?** Phase 1 uses a file deliberately, so the collector can be
> validated before the AWS dependency is added. [Step 11](#step-11) switches to
> Secrets Manager, and it is a one-line configuration change because every
> credential path goes through one provider interface.

**Prove it:** a `curl` with the new key returns the remote list, and nothing else:

```bash
curl -s -H "Authorization: ApiKey <KEY>" --cacert /etc/pki/agency-ca.pem \
     https://ccs-es.example.com:9200/_remote/info | python3 -m json.tool
```

---

<a name="step-3"></a>
## Step 3 — Baseline every remote (CCS-1, CCS-2, CCS-4)

You cannot detect drift from a baseline you have not written down. Start by
recording what is actually configured today.

First put the four local clusters into `es_clusters.json` — just `name`,
`environment`, `base_url`, and TLS settings; leave `expected_remotes` empty.
Then:

```bash
# The CCS-1 inventory table, ready to paste into the review doc:
python3 tools/baseline_inventory.py --clusters es_clusters.json --format markdown \
    > phase0_inventory.md
```

That table lists every remote on every cluster with its current node count, mode,
connect timeout, and `skip_unavailable` — and flags the remotes where
`skip_unavailable: true` means degradation would be dropped from results silently
(CCS-4).

To pre-fill the baseline from observed state:

```bash
python3 tools/baseline_inventory.py --clusters es_clusters.json \
    --emit-baseline es_clusters.generated.json
```

> **Review every generated line before using it.** These are *observed* values,
> not *agreed* ones. If a remote was already degraded when you ran this, its
> degraded state has just been recorded as the expected baseline — and the
> collector will call that degradation healthy forever. This is the single
> easiest way to get this project wrong.

Merge the reviewed values into `es_clusters.json`:

```json
"remote_prod_a": {
  "expected_nodes": 3,
  "expected_mode": "sniff",
  "expected_skip_unavailable": false,
  "expected_initial_connect_timeout": "30s",
  "description": "Primary prod remote — owner: ELK Platform"
}
```

**Prove it (CCS-2 exit criterion):** the inventory table is reviewed and signed
off, and every remote in it appears in `es_clusters.json` with an agreed
expectation.

---

<a name="step-4"></a>
## Step 4 — Decide the severity thresholds (CCS-3)

Phase-0 open decision #3 — *is one-of-three nodes down a warning or a critical in
prod?* — is configuration, not code. Set it per environment:

```json
{
  "name": "prod",
  "environment": "prod",
  "severity_policy": {
    "critical_below_nodes": 2,
    "escalate_warning_when_skip_unavailable": true
  },
  "expected_remotes": { ... }
}
```

That says: in prod, dropping below two connected nodes is CRITICAL rather than a
partial-pool WARNING, and any WARNING on a remote whose failures are silently
skipped is promoted to CRITICAL. Dev and qa inherit the softer defaults.

Policies merge **defaults → cluster → remote**, most specific winning, so a
single unusual remote can be tuned without loosening its whole environment. Every
key is listed in [docs/SCHEMA.md](docs/SCHEMA.md#severity_policy).

**Prove it:**

```bash
python3 ccs_health_check.py --show-config
```

Each remote prints its effective policy. Check that prod shows
`critical_below_nodes=2` and dev shows `1`.

---

<a name="step-5"></a>
## Step 5 — Run the collector (CCS-6, CCS-10)

```bash
python3 ccs_health_check.py --no-index --no-color
```

`--no-index` is the Phase-1 behaviour: probe, evaluate, print, write nothing.

Useful variants:

```bash
python3 ccs_health_check.py --no-index --problems-only    # hide healthy remotes
python3 ccs_health_check.py --no-index --cluster prod     # one cluster
python3 ccs_health_check.py --no-index --format json      # machine-readable
python3 ccs_health_check.py --no-index --format ndjson    # the documents themselves
python3 ccs_health_check.py --no-index --log-level DEBUG  # every request
```

Exit codes: `0` healthy · `1` degraded · `2` config error · `3` state-store write
failure.

**Prove the isolation guarantee (CCS-10).** This is the property the whole design
rests on, so test it rather than trusting it. Point one cluster at a dead port:

```bash
python3 - <<'PY'
import json
c = json.load(open("es_clusters.json"))
c["clusters"][0]["base_url"] = "https://127.0.0.1:9"   # nothing listens here
json.dump(c, open("/tmp/broken.json", "w"), indent=2)
PY
python3 ccs_health_check.py -c /tmp/broken.json --no-index --no-color
```

The broken cluster must produce exactly **one** CRITICAL verdict labelled
`(whole cluster)`, and every other cluster must still be evaluated and reported.
A dead probe that produced *no* verdict would look identical to health.

---

<a name="step-6"></a>
## Step 6 — Create the state store (CCS-11, CCS-12)

The state store is what decouples measuring from reacting: the collector only
writes verdicts, Kibana rules only read them. That is what gives history,
auto-recovery, and a staleness signal.

Configure it in `es_clusters.json`:

```json
"state_store": {
  "enabled": true,
  "cluster": "ccs",
  "index": "ccs-health-monitor",
  "mode": "data_stream",
  "lifecycle": "dsl",
  "retention": "90d"
}
```

> **On the index name.** `ccs-health-monitor` is deliberately *not* dot-prefixed.
> A visible index needs no restricted-index grants for the alerting role, shows
> up in Discover and data views without special handling, and can be inspected
> during an incident without fighting Kibana. The parser rejects a dot-prefixed
> name outright.

Choose `mode`:

- **`data_stream`** (recommended) — append-only by design, retention via the
  data-stream lifecycle. Set `"lifecycle": "dsl"`.
- **`index`** — a write alias over rolling indices, retention via ILM. Use this
  where DSL is unavailable. Set `"lifecycle": "ilm"`.

Then:

```bash
python3 setup/setup_state_store.py --clusters es_clusters.json --dry-run   # review
python3 setup/setup_state_store.py --clusters es_clusters.json             # apply
python3 setup/setup_state_store.py --clusters es_clusters.json --verify    # confirm
```

It is idempotent — re-run it after editing the mapping or the retention period.

**Prove it:**

```bash
python3 ccs_health_check.py --check-state-store
# OK: data_stream 'ccs-health-monitor' exists and is reachable.
```

---

<a name="step-7"></a>
## Step 7 — Write verdicts to the state store (CCS-13, CCS-14)

Drop `--no-index`:

```bash
python3 ccs_health_check.py --no-color
```

Each cycle writes one document per remote, one per unreachable cluster, and one
run heartbeat. Confirm they landed:

```bash
curl -s -H "Authorization: ApiKey <KEY>" --cacert /etc/pki/agency-ca.pem \
  "https://ccs-es.example.com:9200/ccs-health-monitor/_search?size=3&sort=@timestamp:desc" \
  | python3 -m json.tool
```

Then grant the Kibana alerting user read access (CCS-14). `setup_security.py`
already created the `ccs_health_alerting` role; assign it to that user in
**Kibana → Stack Management → Users**. Because the index is visible, a plain
`read` grant is enough — no `allow_restricted_indices`.

**Prove it:** one document per remote per cycle, `ccs.severity` matching what the
console printed, and the alerting user able to query the index.

---

<a name="step-8"></a>
## Step 8 — Create the alerting rules (CCS-15 … CCS-19)

Pick the Kibana space that will host the rules and the data view (Phase-0
decision #5) — rules and data views are space-scoped, and rules cannot read a
data view from another space.

Find the existing SMTP connector (CCS-17):

```bash
python3 alerting/setup_alerting.py --kibana-url https://kibana.example.com \
    --space observability --kibana-user olajide --list-connectors
```

Review, then create:

```bash
python3 alerting/setup_alerting.py \
    --kibana-url https://kibana.example.com \
    --space observability \
    --kibana-user olajide \
    --connector-name "ITSMA SMTP" \
    --to elk-oncall@example.gov \
    --probe-interval-minutes 5 \
    --dry-run          # drop this to apply
```

That creates the data view plus three rules:

| Rule | Fires on | Grouping |
|---|---|---|
| **CRITICAL** | `ccs.severity: CRITICAL` | per `ccs.alert_key` |
| **WARNING** | `ccs.severity: WARNING` | per `ccs.alert_key` |
| **Staleness** | *no* run heartbeat in the window | not grouped |

Add `--include-info` for a fourth, low-urgency rule on unmonitored remotes.

Three design points worth understanding before you tune anything:

- **Grouping is per `alert_key`** (`local_cluster:remote`), not per remote name.
  Each remote alerts and recovers independently (CCS-18), and the same remote on
  two local clusters stays two separate alerts.
- **The window is 3× the probe interval by default.** It must be wider than the
  interval, or ordinary cron jitter produces a window with no verdict in it and
  the rules flap between alert and recovery. This is plan risk #1. Recovery is
  therefore delayed by up to one window — that is the intended trade.
- **The staleness rule watches the run heartbeat**, not verdicts in general, so
  "the collector is dead" is distinguishable from "the collector ran and had
  nothing to say".

Recipients are Phase-0 decision #6: pass `--to` more than once for several
addresses, or run the script once per environment with different recipients.

---

<a name="step-9"></a>
## Step 9 — Validate with an induced failure (CCS-15 exit criterion)

A rule that has never fired is not a rule you can rely on. Induce a real failure
in **non-prod** and watch the whole chain.

The cleanest inducement that changes nothing on the cluster: point the dev
cluster's baseline at a remote that does not exist.

```bash
python3 - <<'PY'
import json
c = json.load(open("es_clusters.json"))
for cluster in c["clusters"]:
    if cluster["name"] == "dev":
        cluster["expected_remotes"]["remote_that_does_not_exist"] = {
            "expected_nodes": 3, "expected_mode": "sniff"
        }
json.dump(c, open("/tmp/induced.json", "w"), indent=2)
PY

python3 ccs_health_check.py -c /tmp/induced.json --no-color
```

Now confirm, in order:

1. The console shows CRITICAL / `missing_remote` for that remote.
2. A document with `ccs.severity: CRITICAL` lands in `ccs-health-monitor`
   (check Discover, filtering on `ccs.alert_key: "dev:remote_that_does_not_exist"`).
3. Within one rule interval, an email arrives naming that exact remote.
4. Re-run with the real `es_clusters.json`; within one alert window, a **recovery**
   email arrives. That proves CCS-18.

To exercise a real disconnect instead — heavier, non-prod only — block the
transport port to a remote with a temporary firewall rule and watch the same
chain produce `disconnected`.

Also validate staleness (CCS-19): stop the collector for longer than the
staleness window and confirm the STALE alert fires, then restart it and confirm
it recovers.

---

<a name="step-10"></a>
## Step 10 — Schedule and harden (CCS-20, CCS-21)

```bash
sudo ./deploy/install.sh                       # systemd timer (default)
sudo ./deploy/install.sh --schedule cron       # cron instead
```

That creates the `ccs-monitor` service account, installs to
`/opt/ccs-health-monitor` with its own virtualenv, prepares
`/var/log/ccs-health-monitor`, installs logrotate, and enables the schedule.
It is safe to re-run to upgrade — an edited `es_clusters.json` is never
clobbered.

Then edit the installed inventory and confirm the first runs:

```bash
sudo -u ccs-monitor /opt/ccs-health-monitor/venv/bin/python \
    /opt/ccs-health-monitor/ccs_health_check.py \
    --clusters /opt/ccs-health-monitor/es_clusters.json --no-index --no-color

systemctl list-timers ccs-health-monitor.timer
journalctl -u ccs-health-monitor.service -f
tail -f /var/log/ccs-health-monitor/collector.log
```

Notes on the unit: `SuccessExitStatus=0 1` is deliberate — exit 1 means
"remotes are degraded", which is a *successful* collector run reporting bad news.
Exit 2 and 3 stay failures so they surface in `systemctl` and node-level
monitoring.

The logrotate config uses `copytruncate` because the collector holds the log
open; rotating by rename would leave it writing to an unlinked inode and the log
would silently stop growing.

**If you change the interval, change the rules too** — re-run
`alerting/setup_alerting.py` with the new `--probe-interval-minutes` so the
windows stay wider than the interval.

---

<a name="step-11"></a>
## Step 11 — Move credentials to Secrets Manager (CCS-8)

Store the same JSON as the credentials file, as one secret:

```bash
aws secretsmanager create-secret \
    --name ccs/es/api-keys \
    --region us-gov-east-1 \
    --secret-string '{
      "dev":  {"api_key": "..."},
      "qa":   {"api_key": "..."},
      "prod": {"api_key": "..."},
      "ccs":  {"api_key": "..."}
    }'
```

Point the inventory at it:

```json
"credentials": {
  "provider": "aws_secrets_manager",
  "secret_id": "ccs/es/api-keys",
  "region": "us-gov-east-1"
}
```

One secret per cluster works too — use `"secret_id_template": "ccs/es/{cluster}"`
instead of `secret_id`.

The collector host's IAM role needs `secretsmanager:GetSecretValue` on those
secrets (and `kms:Decrypt` on the key if the secret uses a customer-managed CMK).

```bash
pip install 'boto3>=1.34.0'
python3 ccs_health_check.py --no-index --no-color     # confirm it still authenticates
sudo rm -f /opt/ccs-health-monitor/credentials.json   # only after that succeeds
```

**Prove it:** the collector runs with no credentials file anywhere in the deploy
path.

---

<a name="step-12"></a>
## Step 12 — Sustained validation (CCS-22)

Run in non-prod for a sustained period and confirm:

- Every remote is probed on schedule, with no gaps.
- No false flaps — no alert/recovery pair without a real state change. If you see
  flapping, the alert window is too close to the probe interval.
- Recovery notifications arrive when conditions genuinely clear.
- The staleness rule stays quiet while the collector is alive.

A quick way to see the whole period at once:

```
# Kibana → Discover → CCS Health Monitor
ccs.doc_type : "remote" and ccs.severity_rank >= 2
```

Then repeat step 9's induced failure in the target environment before prod
sign-off.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Configuration error: ... unknown key` | A typo in `es_clusters.json`. The message names the exact path. Strictness here is deliberate — a silently ignored key becomes a silently wrong baseline. |
| `Credential error: ... still the placeholder` | `credentials.json` still has `REPLACE_WITH_...`. |
| `credential_error` for one cluster | That cluster's name is missing from the credentials file or secret. Key names must match `name` (or `credentials_key`) exactly. |
| `tls_error` | Set `ca_cert` to the agency CA bundle. Do not set `verify_certs: false` — the parser rejects combining the two, and disabling verification is not acceptable under FedRAMP. |
| `auth_error` (401/403) | The key expired, or lacks cluster `monitor`. Re-run `setup/setup_security.py`. |
| Exit 3, `State-store write failed` | Probing worked but indexing failed. Run `--check-state-store`; usually the store does not exist yet or the key lacks `create_doc`. |
| Documents rejected with `strict_dynamic_mapping_exception` | The collector emits a field the mapping does not declare. Re-run `setup/setup_state_store.py` to update the template; note that mapping changes apply to *new* backing indices, so roll over the data stream to pick them up. |
| Rules fire but no email | The connector, not the rule. Test the connector directly in **Kibana → Stack Management → Connectors**. |
| Alerts flap between firing and recovered | The alert window is not wider than the probe interval. Re-run `setup_alerting.py` with the correct `--probe-interval-minutes`. |
| Alerts never recover | Verdicts are still being written for that remote. Check Discover for the latest `ccs.alert_key` documents — the condition probably has not actually cleared. |
| Staleness alert firing while the collector runs fine | The collector runs but cannot *write*. Check its exit code and `--check-state-store`. |

Deeper reference: [docs/SCHEMA.md](docs/SCHEMA.md) for every field and config key,
[docs/RUNBOOK.md](docs/RUNBOOK.md) for what to do when an alert fires.
