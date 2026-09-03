"""Output: human-readable table, JSON, and NDJSON.

Phase 1 validated the collector from this console output alone. It stays a
first-class output afterwards — it is what an on-call engineer runs by hand when
an alert fires (see docs/RUNBOOK.md).
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional, TextIO

from .documents import build_documents
from .evaluate import DOC_TYPE_CLUSTER, ClusterVerdict, severity_counts
from .severity import SEVERITY_ORDER

_COLORS = {
    "HEALTHY": "\033[92m",
    "INFO": "\033[96m",
    "WARNING": "\033[93m",
    "CRITICAL": "\033[91m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
    "DIM": "\033[2m",
}

_SYMBOLS = {"HEALTHY": "OK ", "INFO": "i  ", "WARNING": "!  ", "CRITICAL": "XX "}

WIDTH = 88


def should_use_color(no_color_flag: bool, stream: Optional[TextIO] = None) -> bool:
    """Honour --no-color, NO_COLOR (no-color.org), and non-TTY output."""
    if no_color_flag or os.environ.get("NO_COLOR"):
        return False
    stream = stream if stream is not None else sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def colorize(text: str, key: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_COLORS.get(key, '')}{text}{_COLORS['RESET']}"


def print_table(
    cluster_verdicts: List[ClusterVerdict],
    overall: str,
    run_id: str,
    timestamp: str,
    use_color: bool,
    stream: Optional[TextIO] = None,
    show_healthy: bool = True,
) -> None:
    """The operator-facing report."""
    out = (stream if stream is not None else sys.stdout).write
    rule = "=" * WIDTH

    out(colorize(rule, "BOLD", use_color) + "\n")
    out(colorize(" CCS Remote Connection-State Health Check", "BOLD", use_color) + "\n")
    out(f" run_id={run_id}  ·  {timestamp}\n")
    out(colorize(rule, "BOLD", use_color) + "\n")

    for cluster_verdict in cluster_verdicts:
        out("\n")
        header = f"local cluster: {cluster_verdict.cluster}  [{cluster_verdict.environment}]"
        out(colorize(header, "BOLD", use_color) + "\n")
        out(colorize(f"  {cluster_verdict.base_url}", "DIM", use_color) + "\n")

        status_line = colorize(cluster_verdict.severity, cluster_verdict.severity, use_color)
        probe_note = (
            f"probe {cluster_verdict.probe_duration_ms:.0f} ms"
            if cluster_verdict.probe_ok and cluster_verdict.probe_duration_ms is not None
            else "probe FAILED"
        )
        out(f"  status: {status_line}   ({probe_note})\n")

        if not cluster_verdict.verdicts:
            out(colorize("    (no remotes in the baseline and none reported)\n", "DIM", use_color))
            continue

        # Worst first, so the thing that needs attention is at the top.
        ordered = sorted(
            cluster_verdict.verdicts,
            key=lambda v: (-SEVERITY_ORDER.index(v.severity), v.remote or ""),
        )
        for verdict in ordered:
            if not show_healthy and verdict.severity == "HEALTHY":
                continue
            symbol = _SYMBOLS.get(verdict.severity, "?  ")
            label = verdict.remote if verdict.doc_type != DOC_TYPE_CLUSTER else "(whole cluster)"
            tag = colorize(f"  {symbol}[{verdict.severity:<8}]", verdict.severity, use_color)
            out(f"{tag} {label}\n")
            out(f"          {verdict.reason}\n")
            if verdict.reason_codes:
                out(colorize(f"          codes: {', '.join(verdict.reason_codes)}\n", "DIM", use_color))

    counts = severity_counts(cluster_verdicts)
    out("\n" + colorize("-" * WIDTH, "BOLD", use_color) + "\n")
    summary = "  ".join(f"{name}={counts.get(name, 0)}" for name in SEVERITY_ORDER)
    out(f" verdicts: {summary}\n")
    out(f" OVERALL:  {colorize(overall, overall, use_color)}\n")
    out(colorize("-" * WIDTH, "BOLD", use_color) + "\n")


def build_json_report(
    cluster_verdicts: List[ClusterVerdict],
    overall: str,
    run_id: str,
    timestamp: str,
    duration_ms: float,
) -> Dict[str, Any]:
    """Machine-readable report — the same facts as the table, for pipelines."""
    return {
        "run_id": run_id,
        "timestamp": timestamp,
        "overall_severity": overall,
        "duration_ms": round(duration_ms, 2),
        "counts": severity_counts(cluster_verdicts),
        "clusters": [
            {
                "cluster": cv.cluster,
                "environment": cv.environment,
                "base_url": cv.base_url,
                "severity": cv.severity,
                "probe_ok": cv.probe_ok,
                "probe_duration_ms": cv.probe_duration_ms,
                "error": cv.error,
                "error_kind": cv.error_kind,
                "verdicts": [
                    {
                        "remote": v.remote,
                        "alert_key": v.alert_key,
                        "doc_type": v.doc_type,
                        "severity": v.severity,
                        "monitored": v.monitored,
                        "connected": v.connected,
                        "nodes_expected": v.nodes_expected,
                        "nodes_actual": v.nodes_actual,
                        "nodes_max_configured": v.nodes_max,
                        "mode_expected": v.mode_expected,
                        "mode_actual": v.mode_actual,
                        "initial_connect_timeout": v.timeout_actual,
                        "skip_unavailable": v.skip_unavailable,
                        "reason": v.reason,
                        "reason_codes": v.reason_codes,
                    }
                    for v in cv.verdicts
                ],
            }
            for cv in cluster_verdicts
        ],
    }


def print_json(report: Dict[str, Any], stream: Optional[TextIO] = None) -> None:
    stream = stream if stream is not None else sys.stdout
    stream.write(json.dumps(report, indent=2, default=str) + "\n")


def print_ndjson(
    cluster_verdicts: List[ClusterVerdict],
    run_id: str,
    overall: str,
    duration_ms: float,
    stream: Optional[TextIO] = None,
    include_run_document: bool = True,
) -> None:
    """Emit exactly the documents that would be indexed — one JSON object per line.

    This is what makes `--no-index --format ndjson` a safe dress rehearsal for
    Phase 2: what you see is byte-for-byte what gets written.
    """
    stream = stream if stream is not None else sys.stdout
    docs = build_documents(
        cluster_verdicts,
        run_id,
        include_run_document=include_run_document,
        overall=overall,
        counts=severity_counts(cluster_verdicts),
        duration_ms=duration_ms,
    )
    for doc in docs:
        stream.write(json.dumps(doc, default=str) + "\n")
