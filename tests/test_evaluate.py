"""Unit tests for the severity model and the baseline comparison.

These are the tests that matter most: every branch here is a decision about
whether a human gets paged. Run with:

    python3 -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ccs_monitor.config import ClusterConfig, RemoteBaseline  # noqa: E402
from ccs_monitor.evaluate import (  # noqa: E402
    DOC_TYPE_CLUSTER,
    RC_DISCONNECTED,
    RC_MISSING_REMOTE,
    RC_MODE_DRIFT,
    RC_PARTIAL_POOL,
    RC_POOL_COLLAPSED,
    RC_SKIP_UNAVAILABLE_RISK,
    RC_TIMEOUT_DRIFT,
    RC_UNMONITORED_REMOTE,
    RC_UNREACHABLE_CLUSTER,
    evaluate_cluster,
    evaluate_remote,
    overall_severity,
    severity_counts,
)
from ccs_monitor.probe import ProbeResult  # noqa: E402
from ccs_monitor.severity import DEFAULT_SEVERITY_POLICY, merge_policies, worst  # noqa: E402


def sniff(connected=True, nodes=3, maximum=3, mode="sniff", timeout="30s", skip=False):
    """A sniff-mode _remote/info entry, as Elasticsearch reports it."""
    return {
        "connected": connected,
        "mode": mode,
        "seeds": ["10.0.0.1:9300"],
        "num_nodes_connected": nodes,
        "max_connections_per_cluster": maximum,
        "initial_connect_timeout": timeout,
        "skip_unavailable": skip,
    }


def proxy(connected=True, sockets=2, maximum=2, timeout="30s", skip=False):
    """A proxy-mode entry: different field names for the same idea."""
    return {
        "connected": connected,
        "mode": "proxy",
        "proxy_address": "remote.example.com:9400",
        "num_proxy_sockets_connected": sockets,
        "max_proxy_socket_connections": maximum,
        "initial_connect_timeout": timeout,
        "skip_unavailable": skip,
    }


def cluster(name="prod", environment="prod", policy=None, remotes=None):
    return ClusterConfig(
        name=name,
        base_url="https://es.example.com:9200",
        environment=environment,
        policy=merge_policies(policy or {}),
        expected_remotes=remotes or {},
    )


def baseline(nodes=3, mode="sniff", skip=None, timeout=None, policy=None):
    return RemoteBaseline(
        name="remote_a",
        expected_nodes=nodes,
        expected_mode=mode,
        expected_skip_unavailable=skip,
        expected_initial_connect_timeout=timeout,
        policy=policy or {},
    )


def judge(observed, base=None, policy=None, local=None):
    local = local or cluster()
    base = base if base is not None else baseline()
    effective = merge_policies(local.policy, policy or {}, base.policy if base else {})
    return evaluate_remote(local, "remote_a", base, observed, effective)


class SeverityOrderingTests(unittest.TestCase):
    def test_worst_picks_the_most_serious(self):
        self.assertEqual(worst("HEALTHY", "INFO"), "INFO")
        self.assertEqual(worst("INFO", "WARNING"), "WARNING")
        self.assertEqual(worst("WARNING", "CRITICAL"), "CRITICAL")
        self.assertEqual(worst("CRITICAL", "HEALTHY", "WARNING"), "CRITICAL")

    def test_worst_of_nothing_is_healthy(self):
        self.assertEqual(worst(), "HEALTHY")

    def test_policy_layers_override_left_to_right(self):
        merged = merge_policies({"partial_pool": "CRITICAL"}, {"partial_pool": "INFO"})
        self.assertEqual(merged["partial_pool"], "INFO")
        # Untouched keys keep their defaults.
        self.assertEqual(merged["missing_remote"], DEFAULT_SEVERITY_POLICY["missing_remote"])


class HealthyPathTests(unittest.TestCase):
    def test_matching_baseline_is_healthy(self):
        verdict = judge(sniff())
        self.assertEqual(verdict.severity, "HEALTHY")
        self.assertEqual(verdict.nodes_actual, 3)
        self.assertFalse(verdict.mode_drift)

    def test_more_nodes_than_expected_is_still_healthy(self):
        # A pool larger than baseline is not degradation.
        self.assertEqual(judge(sniff(nodes=5, maximum=5)).severity, "HEALTHY")

    def test_proxy_mode_sockets_are_counted(self):
        # The proxy-mode field names must not read as "no data".
        verdict = judge(proxy(sockets=2), base=baseline(nodes=2, mode="proxy"))
        self.assertEqual(verdict.severity, "HEALTHY")
        self.assertEqual(verdict.nodes_actual, 2)
        self.assertIn("proxy sockets", verdict.reason)

    def test_proxy_partial_pool_is_detected(self):
        verdict = judge(proxy(sockets=1, maximum=2), base=baseline(nodes=2, mode="proxy"))
        self.assertEqual(verdict.severity, "WARNING")
        self.assertIn(RC_PARTIAL_POOL, verdict.reason_codes)


class DegradationTests(unittest.TestCase):
    def test_disconnected_is_critical(self):
        verdict = judge(sniff(connected=False, nodes=0))
        self.assertEqual(verdict.severity, "CRITICAL")
        self.assertIn(RC_DISCONNECTED, verdict.reason_codes)

    def test_partial_pool_is_warning(self):
        verdict = judge(sniff(nodes=2))
        self.assertEqual(verdict.severity, "WARNING")
        self.assertIn(RC_PARTIAL_POOL, verdict.reason_codes)
        self.assertEqual(verdict.nodes_deficit, 1)

    def test_connected_with_zero_nodes_is_critical_by_default(self):
        # connected: true with an empty pool is a collapsed pool, not a partial one.
        verdict = judge(sniff(nodes=0))
        self.assertEqual(verdict.severity, "CRITICAL")
        self.assertIn(RC_POOL_COLLAPSED, verdict.reason_codes)

    def test_prod_policy_makes_one_of_three_critical(self):
        # Phase-0 open decision #3, expressed as configuration.
        verdict = judge(sniff(nodes=1), policy={"critical_below_nodes": 2})
        self.assertEqual(verdict.severity, "CRITICAL")
        self.assertIn(RC_POOL_COLLAPSED, verdict.reason_codes)

    def test_same_state_is_only_a_warning_under_the_default_policy(self):
        self.assertEqual(judge(sniff(nodes=1)).severity, "WARNING")

    def test_missing_remote_is_critical_not_healthy_by_omission(self):
        verdict = judge(None)
        self.assertEqual(verdict.severity, "CRITICAL")
        self.assertIn(RC_MISSING_REMOTE, verdict.reason_codes)
        self.assertIsNone(verdict.connected)

    def test_mode_drift_is_warning(self):
        verdict = judge(proxy(), base=baseline(nodes=2, mode="sniff"))
        self.assertEqual(verdict.severity, "WARNING")
        self.assertIn(RC_MODE_DRIFT, verdict.reason_codes)
        self.assertTrue(verdict.mode_drift)

    def test_timeout_drift_only_checked_when_baselined(self):
        self.assertEqual(judge(sniff(timeout="5s")).severity, "HEALTHY")
        verdict = judge(sniff(timeout="5s"), base=baseline(timeout="30s"))
        self.assertEqual(verdict.severity, "WARNING")
        self.assertIn(RC_TIMEOUT_DRIFT, verdict.reason_codes)

    def test_drift_is_reported_even_when_disconnected(self):
        # A mode change is often the cause of the disconnect — name it in the alert.
        verdict = judge(
            {"connected": False, "mode": "proxy", "initial_connect_timeout": "5s"},
            base=baseline(mode="sniff", timeout="30s"),
        )
        self.assertEqual(verdict.severity, "CRITICAL")
        self.assertIn(RC_DISCONNECTED, verdict.reason_codes)
        self.assertIn(RC_MODE_DRIFT, verdict.reason_codes)
        self.assertIn(RC_TIMEOUT_DRIFT, verdict.reason_codes)

    def test_malformed_entry_is_critical_not_healthy(self):
        verdict = judge({"mode": "sniff"})  # no 'connected' field at all
        self.assertEqual(verdict.severity, "CRITICAL")

    def test_reason_text_names_the_numbers(self):
        self.assertIn("2/3", judge(sniff(nodes=2)).reason)


class SkipUnavailableTests(unittest.TestCase):
    def test_skip_unavailable_risk_is_flagged_on_degradation(self):
        verdict = judge(sniff(nodes=2, skip=True))
        self.assertEqual(verdict.severity, "WARNING")
        self.assertIn(RC_SKIP_UNAVAILABLE_RISK, verdict.reason_codes)

    def test_healthy_skippable_remote_is_not_flagged(self):
        verdict = judge(sniff(skip=True))
        self.assertEqual(verdict.severity, "HEALTHY")
        self.assertNotIn(RC_SKIP_UNAVAILABLE_RISK, verdict.reason_codes)

    def test_escalation_policy_promotes_warning_to_critical(self):
        verdict = judge(
            sniff(nodes=2, skip=True), policy={"escalate_warning_when_skip_unavailable": True}
        )
        self.assertEqual(verdict.severity, "CRITICAL")

    def test_escalation_does_not_touch_a_healthy_remote(self):
        verdict = judge(sniff(skip=True), policy={"escalate_warning_when_skip_unavailable": True})
        self.assertEqual(verdict.severity, "HEALTHY")

    def test_posture_drift_is_detected(self):
        verdict = judge(sniff(skip=True), base=baseline(skip=False))
        self.assertEqual(verdict.severity, "WARNING")
        self.assertTrue(verdict.skip_unavailable_drift)


class UnmonitoredRemoteTests(unittest.TestCase):
    def test_unbaselined_remote_is_info(self):
        local = cluster()
        verdict = evaluate_remote(local, "surprise", None, sniff(), merge_policies(local.policy))
        self.assertEqual(verdict.severity, "INFO")
        self.assertFalse(verdict.monitored)
        self.assertIn(RC_UNMONITORED_REMOTE, verdict.reason_codes)

    def test_unmonitored_remote_still_records_its_state(self):
        local = cluster()
        verdict = evaluate_remote(
            local, "surprise", None, sniff(nodes=1, skip=True), merge_policies(local.policy)
        )
        self.assertEqual(verdict.nodes_actual, 1)
        self.assertTrue(verdict.skip_unavailable)


class ClusterLevelTests(unittest.TestCase):
    def test_unreachable_cluster_yields_exactly_one_critical_verdict(self):
        local = cluster(remotes={"remote_a": baseline(), "remote_b": baseline()})
        probe = ProbeResult(
            cluster="prod", base_url=local.base_url, ok=False, duration_ms=12.0,
            error="connection refused", error_kind="connection_error",
        )
        result = evaluate_cluster(local, probe)
        self.assertEqual(result.severity, "CRITICAL")
        self.assertEqual(len(result.verdicts), 1)
        self.assertEqual(result.verdicts[0].doc_type, DOC_TYPE_CLUSTER)
        self.assertIsNone(result.verdicts[0].remote)
        self.assertIn(RC_UNREACHABLE_CLUSTER, result.verdicts[0].reason_codes)
        self.assertIn("connection_error", result.verdicts[0].reason_codes)

    def test_one_bad_remote_does_not_hide_the_others(self):
        local = cluster(remotes={
            "remote_a": baseline(),
            "remote_b": baseline(),
            "remote_c": baseline(),
        })
        probe = ProbeResult(
            cluster="prod", base_url=local.base_url, ok=True, duration_ms=8.0,
            remotes={
                "remote_a": sniff(connected=False, nodes=0),
                "remote_b": sniff(nodes=2),
                "remote_c": sniff(),
            },
        )
        result = evaluate_cluster(local, probe)
        by_name = {v.remote: v.severity for v in result.verdicts}
        self.assertEqual(by_name["remote_a"], "CRITICAL")
        self.assertEqual(by_name["remote_b"], "WARNING")
        self.assertEqual(by_name["remote_c"], "HEALTHY")
        self.assertEqual(result.severity, "CRITICAL")

    def test_missing_and_unmonitored_are_both_reported(self):
        local = cluster(remotes={"remote_a": baseline(), "remote_gone": baseline()})
        probe = ProbeResult(
            cluster="prod", base_url=local.base_url, ok=True, duration_ms=5.0,
            remotes={"remote_a": sniff(), "remote_new": sniff()},
        )
        result = evaluate_cluster(local, probe)
        by_name = {v.remote: v for v in result.verdicts}
        self.assertEqual(len(result.verdicts), 3)
        self.assertEqual(by_name["remote_a"].severity, "HEALTHY")
        self.assertEqual(by_name["remote_gone"].severity, "CRITICAL")
        self.assertEqual(by_name["remote_new"].severity, "INFO")

    def test_no_remotes_anywhere_is_healthy_not_a_crash(self):
        local = cluster(remotes={})
        probe = ProbeResult(cluster="prod", base_url=local.base_url, ok=True,
                            duration_ms=3.0, remotes={})
        result = evaluate_cluster(local, probe)
        self.assertEqual(result.severity, "HEALTHY")
        self.assertEqual(result.verdicts, [])

    def test_alert_key_separates_the_same_remote_on_different_clusters(self):
        dev = evaluate_remote(cluster("dev", "dev"), "shared", baseline(), sniff(),
                              merge_policies({}))
        prod = evaluate_remote(cluster("prod", "prod"), "shared", baseline(), sniff(),
                               merge_policies({}))
        self.assertNotEqual(dev.alert_key, prod.alert_key)
        self.assertEqual(prod.alert_key, "prod:shared")

    def test_overall_and_counts_roll_up(self):
        local = cluster(remotes={"remote_a": baseline(), "remote_b": baseline()})
        probe = ProbeResult(
            cluster="prod", base_url=local.base_url, ok=True, duration_ms=5.0,
            remotes={"remote_a": sniff(), "remote_b": sniff(nodes=2)},
        )
        results = [evaluate_cluster(local, probe)]
        self.assertEqual(overall_severity(results), "WARNING")
        counts = severity_counts(results)
        self.assertEqual(counts["HEALTHY"], 1)
        self.assertEqual(counts["WARNING"], 1)


if __name__ == "__main__":
    unittest.main()
