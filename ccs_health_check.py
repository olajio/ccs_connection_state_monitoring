#!/usr/bin/env python3
"""
ccs_health_check.py — CCS Remote Connection-State Degradation Monitoring (Phase 1 collector).

Reads a local-cluster inventory (es_clusters.json) and credentials (credentials.json),
calls `GET /_remote/info` on each LOCAL Elasticsearch cluster, and evaluates the
connection state of every configured remote against its Phase-0 baseline.

Verdict per remote:
    HEALTHY   connected AND num_nodes_connected >= expected_nodes AND mode matches
    WARNING   connected but fewer nodes than expected (partial pool), OR mode drift
    CRITICAL  connected: false, OR a baseline remote is missing from _remote/info,
              OR the local cluster is unreachable / auth / TLS failure

Also surfaces remotes present in _remote/info but absent from the baseline as an
informational "unmonitored remote" signal.

Phase-1 behavior (intentional, per the project plan):
  * Credentials are read from a FILE. This is refactored to AWS Secrets Manager later.
  * Verdicts are PRINTED TO SCREEN ONLY — nothing is indexed into Elasticsearch yet.

Each remote and each cluster is evaluated in isolation: one failing remote or one
unreachable cluster never aborts evaluation of the others.

Usage:
    python3 ccs_health_check.py
    python3 ccs_health_check.py --clusters es_clusters.json --credentials credentials.json
    python3 ccs_health_check.py --no-color
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

try:
    import requests
except ImportError:  # pragma: no cover
    sys.stderr.write(
        "Missing dependency 'requests'. Install with: pip install -r requirements.txt\n"
    )
    sys.exit(2)


# --------------------------------------------------------------------------- #
# Severity model
# --------------------------------------------------------------------------- #

# Ordered from best to worst so we can track the worst verdict seen.
SEVERITY_ORDER = ["HEALTHY", "INFO", "WARNING", "CRITICAL"]
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITY_ORDER)}

_COLORS = {
    "HEALTHY": "\033[92m",   # green
    "INFO": "\033[96m",      # cyan
    "WARNING": "\033[93m",   # yellow
    "CRITICAL": "\033[91m",  # red
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}


def _c(text: str, key: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_COLORS.get(key, '')}{text}{_COLORS['RESET']}"


def worst(a: str, b: str) -> str:
    return a if SEVERITY_RANK[a] >= SEVERITY_RANK[b] else b


# --------------------------------------------------------------------------- #
# Config loading
# --------------------------------------------------------------------------- #

def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def get_api_key(credentials: dict, cluster_name: str) -> str | None:
    """Return the API key for a cluster, or None if not present.

    Isolated here so swapping file-based creds for AWS Secrets Manager later
    touches exactly one function.
    """
    entry = credentials.get(cluster_name)
    if not entry:
        return None
    return entry.get("api_key")


# --------------------------------------------------------------------------- #
# Probing
# --------------------------------------------------------------------------- #

def fetch_remote_info(cluster: dict, api_key: str, timeout: float = 10.0) -> dict:
    """Call GET /_remote/info on a local cluster. Returns the parsed JSON body.

    Raises on any failure (network, TLS, auth, non-2xx) so the caller can turn it
    into a single CRITICAL verdict for the cluster.
    """
    base_url = cluster["base_url"].rstrip("/")
    url = f"{base_url}/_remote/info"

    verify = cluster.get("ca_cert") or cluster.get("verify_certs", True)
    headers = {"Authorization": f"ApiKey {api_key}", "Accept": "application/json"}

    resp = requests.get(url, headers=headers, timeout=timeout, verify=verify)
    resp.raise_for_status()
    return resp.json()


# --------------------------------------------------------------------------- #
# Evaluation
# --------------------------------------------------------------------------- #

def evaluate_remote(name: str, baseline: dict, observed: dict | None) -> dict:
    """Compare one remote's observed state against its baseline; return a verdict."""
    expected_nodes = baseline.get("expected_nodes")
    expected_mode = baseline.get("expected_mode")

    # Baseline remote entirely absent from _remote/info -> config drift / removed.
    if observed is None:
        return {
            "remote": name,
            "severity": "CRITICAL",
            "connected": None,
            "expected_nodes": expected_nodes,
            "actual_nodes": None,
            "expected_mode": expected_mode,
            "actual_mode": None,
            "skip_unavailable": None,
            "reason": "Baseline remote missing from _remote/info (config drift or removed)",
        }

    connected = observed.get("connected", False)
    actual_nodes = observed.get("num_nodes_connected")
    actual_mode = observed.get("mode")
    skip_unavailable = observed.get("skip_unavailable")

    reasons = []
    severity = "HEALTHY"

    if not connected:
        severity = "CRITICAL"
        reasons.append("connected: false (pool collapsed / remote unreachable)")
    else:
        if expected_nodes is not None and actual_nodes is not None and actual_nodes < expected_nodes:
            severity = worst(severity, "WARNING")
            reasons.append(
                f"partial pool: {actual_nodes}/{expected_nodes} nodes connected"
            )
        if expected_mode is not None and actual_mode is not None and actual_mode != expected_mode:
            severity = worst(severity, "WARNING")
            reasons.append(f"mode drift: expected '{expected_mode}', got '{actual_mode}'")

    if skip_unavailable:
        reasons.append("skip_unavailable=true (degradation may be silent downstream)")

    if not reasons:
        reasons.append(f"connected, {actual_nodes}/{expected_nodes} nodes, mode '{actual_mode}'")

    return {
        "remote": name,
        "severity": severity,
        "connected": connected,
        "expected_nodes": expected_nodes,
        "actual_nodes": actual_nodes,
        "expected_mode": expected_mode,
        "actual_mode": actual_mode,
        "skip_unavailable": skip_unavailable,
        "reason": "; ".join(reasons),
    }


def evaluate_cluster(cluster: dict, credentials: dict) -> dict:
    """Probe and evaluate every remote for one local cluster, in isolation."""
    name = cluster["name"]
    expected_remotes = cluster.get("expected_remotes", {})
    result = {"cluster": name, "base_url": cluster.get("base_url"), "verdicts": []}

    api_key = get_api_key(credentials, name)
    if not api_key:
        result["cluster_severity"] = "CRITICAL"
        result["error"] = f"No API key found for cluster '{name}' in credentials file"
        return result

    try:
        remote_info = fetch_remote_info(cluster, api_key)
    except requests.exceptions.SSLError as exc:
        result["cluster_severity"] = "CRITICAL"
        result["error"] = f"TLS verification failed: {exc}"
        return result
    except requests.exceptions.RequestException as exc:
        result["cluster_severity"] = "CRITICAL"
        result["error"] = f"Local cluster unreachable / probe failed: {exc}"
        return result
    except ValueError as exc:  # bad JSON
        result["cluster_severity"] = "CRITICAL"
        result["error"] = f"Invalid response from _remote/info: {exc}"
        return result

    cluster_severity = "HEALTHY"

    # Evaluate every baselined remote (present or missing).
    for remote_name, baseline in expected_remotes.items():
        verdict = evaluate_remote(remote_name, baseline, remote_info.get(remote_name))
        cluster_severity = worst(cluster_severity, verdict["severity"])
        result["verdicts"].append(verdict)

    # Surface remotes seen but not baselined (informational).
    for observed_name in remote_info:
        if observed_name not in expected_remotes:
            obs = remote_info[observed_name] or {}
            cluster_severity = worst(cluster_severity, "INFO")
            result["verdicts"].append({
                "remote": observed_name,
                "severity": "INFO",
                "connected": obs.get("connected"),
                "expected_nodes": None,
                "actual_nodes": obs.get("num_nodes_connected"),
                "expected_mode": None,
                "actual_mode": obs.get("mode"),
                "skip_unavailable": obs.get("skip_unavailable"),
                "reason": "Unmonitored remote: present in _remote/info but not in baseline",
            })

    result["cluster_severity"] = cluster_severity
    return result


# --------------------------------------------------------------------------- #
# Reporting (screen only — no indexing in this phase)
# --------------------------------------------------------------------------- #

def print_report(results: list[dict], use_color: bool) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    overall = "HEALTHY"

    print(_c("=" * 78, "BOLD", use_color))
    print(_c(f" CCS Remote Connection-State Health Check  ·  {ts}", "BOLD", use_color))
    print(_c("=" * 78, "BOLD", use_color))

    for res in results:
        cluster_sev = res.get("cluster_severity", "HEALTHY")
        overall = worst(overall, cluster_sev)
        header = f"\nLocal cluster: {res['cluster']}  ({res.get('base_url', '?')})"
        print(_c(header, "BOLD", use_color))
        print(f"  cluster status: {_c(cluster_sev, cluster_sev, use_color)}")

        if res.get("error"):
            print(f"    {_c('!', 'CRITICAL', use_color)} {res['error']}")
            continue

        if not res["verdicts"]:
            print("    (no remotes configured in baseline)")
            continue

        for v in res["verdicts"]:
            sev = v["severity"]
            tag = _c(f"[{sev}]", sev, use_color)
            print(f"    {tag} {v['remote']}")
            print(f"        {v['reason']}")

    print()
    print(_c("-" * 78, "BOLD", use_color))
    print(f" OVERALL: {_c(overall, overall, use_color)}")
    print(_c("-" * 78, "BOLD", use_color))
    return overall


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="CCS remote connection-state health check (Phase 1).")
    p.add_argument("--clusters", default="es_clusters.json", help="Path to cluster inventory JSON.")
    p.add_argument("--credentials", default="credentials.json", help="Path to credentials JSON.")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI color output.")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    use_color = (not args.no_color) and sys.stdout.isatty()

    try:
        inventory = load_json(args.clusters)
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"Failed to load clusters file '{args.clusters}': {exc}\n")
        return 2

    try:
        credentials = load_json(args.credentials)
    except (OSError, ValueError) as exc:
        sys.stderr.write(
            f"Failed to load credentials file '{args.credentials}': {exc}\n"
            f"Copy credentials.example.json to '{args.credentials}' and fill in API keys.\n"
        )
        return 2

    clusters = inventory.get("clusters", [])
    if not clusters:
        sys.stderr.write("No clusters defined in inventory.\n")
        return 2

    results = [evaluate_cluster(cluster, credentials) for cluster in clusters]
    overall = print_report(results, use_color)

    # Non-zero exit if anything is worse than healthy — handy for later scheduling.
    return 0 if overall in ("HEALTHY", "INFO") else 1


if __name__ == "__main__":
    sys.exit(main())
