"""Severity vocabulary, ordering, and per-environment policy resolution.

The severity *policy* is what makes Phase-0 open decision #3 ("is one-of-three
nodes down a warning or critical in prod?") configurable instead of hard-coded.
Policies merge in three layers, most specific winning:

    defaults.severity_policy   (whole run)
      -> cluster.severity_policy   (one local cluster / environment)
        -> remote.severity_policy  (one remote on that cluster)
"""

from __future__ import annotations

from typing import Any, Dict, Iterable

# Ordered best -> worst, so `worst()` can pick the more serious of two.
SEVERITY_ORDER = ["HEALTHY", "INFO", "WARNING", "CRITICAL"]
SEVERITY_RANK: Dict[str, int] = {name: i for i, name in enumerate(SEVERITY_ORDER)}

#: Severities that mean "nothing is wrong" (INFO is an observation, not a fault).
OK_SEVERITIES = frozenset({"HEALTHY", "INFO"})

#: Baseline policy. Every key is overridable per cluster and per remote.
DEFAULT_SEVERITY_POLICY: Dict[str, Any] = {
    # Remote reports connected: false -> pool collapsed.
    "disconnected": "CRITICAL",
    # Connected, but num_nodes_connected < expected_nodes.
    "partial_pool": "WARNING",
    # Connected, but fewer than this many nodes/sockets are connected ->
    # escalate to CRITICAL. The default of 1 means "connected: true with zero
    # connected nodes is a collapsed pool, not a partial one". Raise it to 2 in
    # prod to make one-of-three down critical; null disables the escalation.
    "critical_below_nodes": 1,
    # mode (sniff/proxy) differs from the Phase-0 baseline.
    "mode_drift": "WARNING",
    # initial_connect_timeout differs from the baseline (only checked when a
    # baseline value is configured for the remote).
    "timeout_drift": "WARNING",
    # skip_unavailable differs from the documented posture.
    "skip_unavailable_drift": "WARNING",
    # A baselined remote is absent from _remote/info entirely.
    "missing_remote": "CRITICAL",
    # The local cluster itself could not be probed (network/auth/TLS).
    "unreachable_cluster": "CRITICAL",
    # A remote is present in _remote/info but absent from the baseline.
    "unmonitored_remote": "INFO",
    # skip_unavailable: true means a degraded remote can be silently dropped
    # from results. When true, escalate any WARNING on that remote to CRITICAL.
    "escalate_warning_when_skip_unavailable": False,
}

#: Policy keys whose value must be a severity name.
_SEVERITY_VALUED_KEYS = frozenset(
    {
        "disconnected",
        "partial_pool",
        "mode_drift",
        "timeout_drift",
        "skip_unavailable_drift",
        "missing_remote",
        "unreachable_cluster",
        "unmonitored_remote",
    }
)
_INT_VALUED_KEYS = frozenset({"critical_below_nodes"})
_BOOL_VALUED_KEYS = frozenset({"escalate_warning_when_skip_unavailable"})

POLICY_KEYS = frozenset(DEFAULT_SEVERITY_POLICY)


class PolicyError(ValueError):
    """Raised when a severity policy contains unknown keys or bad values."""


def worst(*severities: str) -> str:
    """Return the most serious severity of those given."""
    result = "HEALTHY"
    for sev in severities:
        if sev is None:
            continue
        if SEVERITY_RANK[sev] > SEVERITY_RANK[result]:
            result = sev
    return result


def is_ok(severity: str) -> bool:
    """True when the severity does not represent a fault."""
    return severity in OK_SEVERITIES


def validate_policy(policy: Dict[str, Any], where: str) -> None:
    """Validate one policy fragment. Raises PolicyError with a located message."""
    if not isinstance(policy, dict):
        raise PolicyError(f"{where}: severity_policy must be an object")

    for key, value in policy.items():
        if key.startswith("_"):
            continue  # "_comment" style annotations are allowed anywhere
        if key not in POLICY_KEYS:
            known = ", ".join(sorted(POLICY_KEYS))
            raise PolicyError(f"{where}: unknown severity_policy key '{key}'. Known keys: {known}")

        if key in _SEVERITY_VALUED_KEYS:
            if value not in SEVERITY_RANK:
                raise PolicyError(
                    f"{where}: severity_policy.{key} must be one of "
                    f"{SEVERITY_ORDER}, got {value!r}"
                )
        elif key in _INT_VALUED_KEYS:
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise PolicyError(
                    f"{where}: severity_policy.{key} must be a non-negative integer or null, "
                    f"got {value!r}"
                )
        elif key in _BOOL_VALUED_KEYS:
            if not isinstance(value, bool):
                raise PolicyError(
                    f"{where}: severity_policy.{key} must be true or false, got {value!r}"
                )


def merge_policies(*layers: Dict[str, Any]) -> Dict[str, Any]:
    """Merge policy layers left-to-right onto the defaults; later layers win."""
    merged = dict(DEFAULT_SEVERITY_POLICY)
    for layer in layers:
        if layer:
            merged.update({k: v for k, v in layer.items() if not k.startswith("_")})
    return merged


def describe_policy(policy: Dict[str, Any]) -> str:
    """One-line human summary, used by --show-policy and the baseline tooling."""
    parts: Iterable[str] = (f"{k}={policy[k]}" for k in sorted(policy))
    return ", ".join(parts)
