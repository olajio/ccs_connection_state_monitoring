"""Baseline comparison: observed `_remote/info` state -> severity verdicts.

Two structural rules from the project plan are enforced here:

* **Isolation.** Every remote and every cluster is evaluated independently. One
  failing remote never aborts the loop for the others, and one unreachable
  cluster never aborts the run.
* **No silent gaps.** A baselined remote missing from `_remote/info` is CRITICAL
  (config drift), and an unreachable local cluster produces one CRITICAL verdict
  rather than no verdict at all.

Connection-mode note: `sniff` remotes report `num_nodes_connected` /
`max_connections_per_cluster`, while `proxy` remotes report
`num_proxy_sockets_connected` / `max_proxy_socket_connections`. Both are read so
a proxy-mode remote is never scored as "no data".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .config import ClusterConfig, RemoteBaseline
from .probe import ProbeResult
from .severity import worst

# Stable, greppable reason codes. These are indexed as `ccs.reason_codes` and are
# what the runbook and the Kibana rules key off — keep them stable.
RC_HEALTHY = "healthy"
RC_DISCONNECTED = "disconnected"
RC_PARTIAL_POOL = "partial_pool"
RC_POOL_COLLAPSED = "pool_collapsed"
RC_MODE_DRIFT = "mode_drift"
RC_TIMEOUT_DRIFT = "timeout_drift"
RC_SKIP_UNAVAILABLE_DRIFT = "skip_unavailable_drift"
RC_SKIP_UNAVAILABLE_RISK = "skip_unavailable_risk"
RC_MISSING_REMOTE = "missing_remote"
RC_UNMONITORED_REMOTE = "unmonitored_remote"
RC_UNREACHABLE_CLUSTER = "unreachable_cluster"
RC_MALFORMED_RESPONSE = "malformed_remote_info"
RC_NO_BASELINE = "no_baseline_configured"

DOC_TYPE_REMOTE = "remote"
DOC_TYPE_CLUSTER = "cluster"
DOC_TYPE_RUN = "run"


@dataclass
class Verdict:
    """One judgement about one remote (or, for probe failures, one cluster)."""

    cluster: str
    environment: str
    remote: Optional[str]
    severity: str
    doc_type: str = DOC_TYPE_REMOTE
    monitored: bool = True
    connected: Optional[bool] = None
    nodes_expected: Optional[int] = None
    nodes_actual: Optional[int] = None
    nodes_max: Optional[int] = None
    nodes_deficit: Optional[int] = None
    mode_expected: Optional[str] = None
    mode_actual: Optional[str] = None
    mode_drift: Optional[bool] = None
    timeout_expected: Optional[str] = None
    timeout_actual: Optional[str] = None
    timeout_drift: Optional[bool] = None
    skip_unavailable: Optional[bool] = None
    skip_unavailable_expected: Optional[bool] = None
    skip_unavailable_drift: Optional[bool] = None
    seeds: List[str] = field(default_factory=list)
    proxy_address: Optional[str] = None
    reason: str = ""
    reason_codes: List[str] = field(default_factory=list)
    probe_ok: bool = True
    probe_duration_ms: Optional[float] = None
    probe_error: Optional[str] = None
    probe_error_kind: Optional[str] = None

    @property
    def alert_key(self) -> str:
        """Grouping key for Kibana rules — unique per (local cluster, remote).

        Grouping on this rather than the bare remote name keeps a remote that
        exists on several local clusters from collapsing into one alert.
        """
        return f"{self.cluster}:{self.remote or '_cluster'}"

    def expected_or_max(self) -> Optional[int]:
        """Baseline node count, falling back to the pool ceiling the cluster reports."""
        if self.nodes_expected is not None:
            return self.nodes_expected
        return self.nodes_max

    def pool_unit(self) -> str:
        """Wording for this remote's pool members: proxy mode counts sockets."""
        return "proxy sockets" if self.mode_actual == "proxy" else "nodes"


@dataclass
class ClusterVerdict:
    """All verdicts for one local cluster, plus its rolled-up severity."""

    cluster: str
    environment: str
    base_url: str
    severity: str
    verdicts: List[Verdict] = field(default_factory=list)
    probe_ok: bool = True
    probe_duration_ms: Optional[float] = None
    error: Optional[str] = None
    error_kind: Optional[str] = None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def connected_count(observed: Dict[str, Any]) -> Optional[int]:
    """Connected nodes (sniff) or proxy sockets (proxy), whichever is reported."""
    for key in ("num_nodes_connected", "num_proxy_sockets_connected"):
        value = observed.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def configured_max(observed: Dict[str, Any]) -> Optional[int]:
    """The pool ceiling the local cluster is configured for."""
    for key in ("max_connections_per_cluster", "max_proxy_socket_connections"):
        value = observed.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def _seeds(observed: Dict[str, Any]) -> List[str]:
    seeds = observed.get("seeds")
    if isinstance(seeds, list):
        return [str(s) for s in seeds]
    return []


# --------------------------------------------------------------------------- #
# Per-remote evaluation
# --------------------------------------------------------------------------- #

def evaluate_remote(
    cluster: ClusterConfig,
    remote_name: str,
    baseline: Optional[RemoteBaseline],
    observed: Optional[Dict[str, Any]],
    policy: Dict[str, Any],
) -> Verdict:
    """Judge one remote against its Phase-0 baseline."""
    base = Verdict(
        cluster=cluster.name,
        environment=cluster.environment,
        remote=remote_name,
        severity="HEALTHY",
        monitored=baseline is not None,
        nodes_expected=baseline.expected_nodes if baseline else None,
        mode_expected=baseline.expected_mode if baseline else None,
        timeout_expected=baseline.expected_initial_connect_timeout if baseline else None,
        skip_unavailable_expected=baseline.expected_skip_unavailable if baseline else None,
    )

    # --- Case 1: baselined remote absent from _remote/info entirely ----------
    if observed is None:
        base.severity = policy["missing_remote"]
        base.connected = None
        base.reason_codes = [RC_MISSING_REMOTE]
        base.reason = (
            f"Baseline remote '{remote_name}' is absent from _remote/info on cluster "
            f"'{cluster.name}' (removed remote or config drift)"
        )
        return base

    # --- Case 2: unmonitored remote (present, but not in the baseline) -------
    if baseline is None:
        base.severity = policy["unmonitored_remote"]
        base.connected = observed.get("connected")
        base.nodes_actual = connected_count(observed)
        base.nodes_max = configured_max(observed)
        base.mode_actual = observed.get("mode")
        base.timeout_actual = observed.get("initial_connect_timeout")
        base.skip_unavailable = observed.get("skip_unavailable")
        base.seeds = _seeds(observed)
        base.proxy_address = observed.get("proxy_address")
        base.reason_codes = [RC_UNMONITORED_REMOTE, RC_NO_BASELINE]
        base.reason = (
            f"Unmonitored remote '{remote_name}' is present in _remote/info on cluster "
            f"'{cluster.name}' but absent from the Phase-0 baseline (undocumented config change)"
        )
        return base

    # --- Case 3: baselined remote, observed -----------------------------------
    base.connected = observed.get("connected")
    base.nodes_actual = connected_count(observed)
    base.nodes_max = configured_max(observed)
    base.mode_actual = observed.get("mode")
    base.timeout_actual = observed.get("initial_connect_timeout")
    base.skip_unavailable = observed.get("skip_unavailable")
    base.seeds = _seeds(observed)
    base.proxy_address = observed.get("proxy_address")

    reasons: List[str] = []
    codes: List[str] = []
    severity = "HEALTHY"

    if not isinstance(base.connected, bool):
        # Neither true nor false: a body we cannot trust is a fault, not health.
        severity = "CRITICAL"
        codes.append(RC_MALFORMED_RESPONSE)
        reasons.append(
            f"_remote/info entry for '{remote_name}' has no boolean 'connected' field "
            f"(got {base.connected!r})"
        )
    elif not base.connected:
        severity = worst(severity, policy["disconnected"])
        codes.append(RC_DISCONNECTED)
        reasons.append("connected=false: connection pool collapsed or remote unreachable")
    else:
        # Pool saturation is only meaningful on a connected remote.
        if base.nodes_actual is not None:
            critical_below = policy.get("critical_below_nodes")
            expected = base.expected_or_max()
            if expected is not None and base.nodes_actual < expected:
                base.nodes_deficit = expected - base.nodes_actual
            else:
                base.nodes_deficit = 0

            if critical_below is not None and base.nodes_actual < critical_below:
                severity = worst(severity, "CRITICAL")
                codes.append(RC_POOL_COLLAPSED)
                reasons.append(
                    f"pool collapsed: {base.nodes_actual} connected "
                    f"{base.pool_unit()} is below the critical floor of {critical_below}"
                )
            elif base.nodes_deficit:
                severity = worst(severity, policy["partial_pool"])
                codes.append(RC_PARTIAL_POOL)
                reasons.append(
                    f"partial pool: {base.nodes_actual}/{expected} "
                    f"{base.pool_unit()} connected"
                )


    # Configuration drift is assessed whether or not the remote is connected: a
    # mode or timeout change is often the cause of a disconnect, and naming it in
    # the alert is what turns a page into a fix.
    if base.mode_expected and base.mode_actual:
        if base.mode_actual != base.mode_expected:
            base.mode_drift = True
            severity = worst(severity, policy["mode_drift"])
            codes.append(RC_MODE_DRIFT)
            reasons.append(f"mode drift: expected '{base.mode_expected}', observed '{base.mode_actual}'")
        else:
            base.mode_drift = False

    # initial_connect_timeout drift (only checked when a baseline value is set).
    if base.timeout_expected and base.timeout_actual:
        if base.timeout_actual != base.timeout_expected:
            base.timeout_drift = True
            severity = worst(severity, policy["timeout_drift"])
            codes.append(RC_TIMEOUT_DRIFT)
            reasons.append(
                f"initial_connect_timeout drift: expected '{base.timeout_expected}', "
                f"observed '{base.timeout_actual}'"
            )
        else:
            base.timeout_drift = False

    # skip_unavailable posture drift is checked even when disconnected: it is a
    # configuration fact, not a runtime one.
    if base.skip_unavailable_expected is not None and isinstance(base.skip_unavailable, bool):
        if base.skip_unavailable != base.skip_unavailable_expected:
            base.skip_unavailable_drift = True
            severity = worst(severity, policy["skip_unavailable_drift"])
            codes.append(RC_SKIP_UNAVAILABLE_DRIFT)
            reasons.append(
                f"skip_unavailable drift: expected {str(base.skip_unavailable_expected).lower()}, "
                f"observed {str(base.skip_unavailable).lower()}"
            )
        else:
            base.skip_unavailable_drift = False

    # skip_unavailable=true means a degraded remote can be dropped from results
    # without any downstream error — the silent-failure case this project exists
    # to surface. Optionally escalate warnings on such remotes.
    if base.skip_unavailable is True and severity != "HEALTHY":
        codes.append(RC_SKIP_UNAVAILABLE_RISK)
        reasons.append(
            "skip_unavailable=true: this degradation can be silently dropped from CCS results"
        )
        if policy.get("escalate_warning_when_skip_unavailable") and severity == "WARNING":
            severity = "CRITICAL"
            reasons.append("severity escalated WARNING -> CRITICAL by policy for a skippable remote")

    if severity == "HEALTHY" and not codes:
        codes.append(RC_HEALTHY)
        pool = (
            f"{base.nodes_actual}/{base.expected_or_max()} {base.pool_unit()}"
            if base.nodes_actual is not None and base.expected_or_max() is not None
            else f"{base.nodes_actual} {base.pool_unit()}"
        )
        reasons.append(f"connected, {pool}, mode '{base.mode_actual}'")

    base.severity = severity
    base.reason_codes = codes
    base.reason = "; ".join(reasons)
    return base


# --------------------------------------------------------------------------- #
# Per-cluster evaluation
# --------------------------------------------------------------------------- #

def evaluate_cluster(cluster: ClusterConfig, probe: ProbeResult) -> ClusterVerdict:
    """Turn one cluster's probe result into its full set of verdicts."""
    result = ClusterVerdict(
        cluster=cluster.name,
        environment=cluster.environment,
        base_url=cluster.base_url,
        severity="HEALTHY",
        probe_ok=probe.ok,
        probe_duration_ms=probe.duration_ms,
    )

    # Unreachable local cluster: exactly one CRITICAL verdict, never a gap.
    if not probe.ok:
        policy = cluster.policy_for(None)
        severity = policy["unreachable_cluster"]
        result.severity = severity
        result.error = probe.error
        result.error_kind = probe.error_kind
        result.verdicts = [
            Verdict(
                cluster=cluster.name,
                environment=cluster.environment,
                remote=None,
                severity=severity,
                doc_type=DOC_TYPE_CLUSTER,
                monitored=True,
                reason=(
                    f"Local cluster '{cluster.name}' could not be probed "
                    f"({probe.error_kind}): {probe.error}"
                ),
                reason_codes=[RC_UNREACHABLE_CLUSTER, probe.error_kind or "request_error"],
                probe_ok=False,
                probe_duration_ms=probe.duration_ms,
                probe_error=probe.error,
                probe_error_kind=probe.error_kind,
            )
        ]
        return result

    severity = "HEALTHY"

    # Every baselined remote, present or missing.
    for remote_name, baseline in cluster.expected_remotes.items():
        policy = cluster.policy_for(baseline)
        verdict = evaluate_remote(
            cluster, remote_name, baseline, probe.remotes.get(remote_name), policy
        )
        verdict.probe_duration_ms = probe.duration_ms
        severity = worst(severity, verdict.severity)
        result.verdicts.append(verdict)

    # Every observed remote that is not baselined.
    cluster_policy = cluster.policy_for(None)
    for observed_name, observed in probe.remotes.items():
        if observed_name in cluster.expected_remotes:
            continue
        verdict = evaluate_remote(cluster, observed_name, None, observed, cluster_policy)
        verdict.probe_duration_ms = probe.duration_ms
        severity = worst(severity, verdict.severity)
        result.verdicts.append(verdict)

    result.severity = severity
    return result


def overall_severity(cluster_verdicts: List[ClusterVerdict]) -> str:
    """Worst severity across every cluster in the run."""
    return worst(*[cv.severity for cv in cluster_verdicts]) if cluster_verdicts else "HEALTHY"


def severity_counts(cluster_verdicts: List[ClusterVerdict]) -> Dict[str, int]:
    """Verdict counts per severity, used by the run document and the summary."""
    counts = {"HEALTHY": 0, "INFO": 0, "WARNING": 0, "CRITICAL": 0}
    for cluster_verdict in cluster_verdicts:
        for verdict in cluster_verdict.verdicts:
            counts[verdict.severity] = counts.get(verdict.severity, 0) + 1
    return counts
