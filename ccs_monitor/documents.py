"""Verdict -> `ccs-health-monitor` document.

The document shape is the Phase-0 schema (docs/SCHEMA.md) and is what the
Phase-3 Kibana rules query. Field names are stable contract: changing one means
changing the index template, the rules, and the runbook together.

Null-valued fields are dropped before indexing — Elasticsearch stores nothing
for them anyway, and a sparse document is far easier to read in Discover.
"""

from __future__ import annotations

import getpass
import os
import platform
import socket
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from . import __version__
from .evaluate import DOC_TYPE_RUN, ClusterVerdict, Verdict
from .severity import SEVERITY_RANK

EVENT_DATASET = "ccs.connection_state"
EVENT_MODULE = "ccs_health_check"


def utc_now_iso() -> str:
    """RFC3339 / ISO-8601 timestamp in UTC, the format ES `date` accepts."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_run_id() -> str:
    return uuid.uuid4().hex


def _runner_identity() -> Dict[str, Any]:
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - no pwd entry in some containers
        user = None
    return {
        "host": socket.gethostname(),
        "user": user,
        "pid": os.getpid(),
        "platform": platform.platform(terse=True),
    }


def prune(value: Any) -> Any:
    """Recursively drop None values and now-empty containers."""
    if isinstance(value, dict):
        cleaned = {k: prune(v) for k, v in value.items() if v is not None}
        return {k: v for k, v in cleaned.items() if v is not None and v != {}}
    if isinstance(value, list):
        return [prune(v) for v in value if v is not None]
    return value


def verdict_document(
    verdict: Verdict,
    run_id: str,
    timestamp: Optional[str] = None,
    runner: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build one verdict document."""
    doc: Dict[str, Any] = {
        "@timestamp": timestamp or utc_now_iso(),
        "event": {
            "kind": "state",
            "category": "network",
            "dataset": EVENT_DATASET,
            "module": EVENT_MODULE,
            "severity": SEVERITY_RANK[verdict.severity],
        },
        "run": {"id": run_id, "version": __version__, **(runner or _runner_identity())},
        "ccs": {
            "doc_type": verdict.doc_type,
            "local_cluster": verdict.cluster,
            "environment": verdict.environment,
            "remote": verdict.remote,
            "alert_key": verdict.alert_key,
            "severity": verdict.severity,
            "severity_rank": SEVERITY_RANK[verdict.severity],
            "monitored": verdict.monitored,
            "connected": verdict.connected,
            "nodes": {
                "expected": verdict.nodes_expected,
                "actual": verdict.nodes_actual,
                "max_configured": verdict.nodes_max,
                "deficit": verdict.nodes_deficit,
            },
            "mode": {
                "expected": verdict.mode_expected,
                "actual": verdict.mode_actual,
                "drift": verdict.mode_drift,
            },
            "initial_connect_timeout": {
                "expected": verdict.timeout_expected,
                "actual": verdict.timeout_actual,
                "drift": verdict.timeout_drift,
            },
            "skip_unavailable": verdict.skip_unavailable,
            "skip_unavailable_expected": verdict.skip_unavailable_expected,
            "skip_unavailable_drift": verdict.skip_unavailable_drift,
            "seeds": verdict.seeds or None,
            "proxy_address": verdict.proxy_address,
            "reason": verdict.reason,
            "reason_codes": verdict.reason_codes or None,
            "probe": {
                "ok": verdict.probe_ok,
                "duration_ms": verdict.probe_duration_ms,
                "error": verdict.probe_error,
                "error_kind": verdict.probe_error_kind,
            },
        },
    }
    return prune(doc)


def run_document(
    run_id: str,
    cluster_verdicts: List[ClusterVerdict],
    overall: str,
    counts: Dict[str, int],
    duration_ms: float,
    timestamp: Optional[str] = None,
    runner: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """A per-run heartbeat document.

    The Phase-3 staleness rule watches for the absence of these: it distinguishes
    "the collector is dead" from "the collector ran and had nothing to say".
    """
    doc = {
        "@timestamp": timestamp or utc_now_iso(),
        "event": {
            "kind": "metric",
            "category": "network",
            "dataset": EVENT_DATASET,
            "module": EVENT_MODULE,
            "duration_ms": round(duration_ms, 2),
        },
        "run": {"id": run_id, "version": __version__, **(runner or _runner_identity())},
        "ccs": {
            "doc_type": DOC_TYPE_RUN,
            "alert_key": "_run",
            "severity": overall,
            "severity_rank": SEVERITY_RANK[overall],
            "clusters_total": len(cluster_verdicts),
            "clusters_probed_ok": sum(1 for cv in cluster_verdicts if cv.probe_ok),
            "clusters_unreachable": sum(1 for cv in cluster_verdicts if not cv.probe_ok),
            "verdicts_total": sum(len(cv.verdicts) for cv in cluster_verdicts),
            "counts": {
                "healthy": counts.get("HEALTHY", 0),
                "info": counts.get("INFO", 0),
                "warning": counts.get("WARNING", 0),
                "critical": counts.get("CRITICAL", 0),
            },
            "reason": (
                f"Collector run completed in {duration_ms:.0f} ms across "
                f"{len(cluster_verdicts)} local cluster(s); overall {overall}"
            ),
        },
    }
    return prune(doc)


def build_documents(
    cluster_verdicts: List[ClusterVerdict],
    run_id: str,
    include_run_document: bool = True,
    overall: str = "HEALTHY",
    counts: Optional[Dict[str, int]] = None,
    duration_ms: float = 0.0,
) -> List[Dict[str, Any]]:
    """All documents for one collector cycle, sharing a single run timestamp.

    One timestamp for the whole cycle means every verdict from a cycle lands in
    the same alerting window — no split-window flapping from a slow probe.
    """
    timestamp = utc_now_iso()
    runner = _runner_identity()
    docs = [
        verdict_document(v, run_id, timestamp, runner)
        for cv in cluster_verdicts
        for v in cv.verdicts
    ]
    if include_run_document:
        docs.append(
            run_document(
                run_id,
                cluster_verdicts,
                overall,
                counts or {},
                duration_ms,
                timestamp,
                runner,
            )
        )
    return docs


def iter_verdicts(cluster_verdicts: Iterable[ClusterVerdict]) -> Iterable[Verdict]:
    for cluster_verdict in cluster_verdicts:
        for verdict in cluster_verdict.verdicts:
            yield verdict
