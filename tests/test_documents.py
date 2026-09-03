"""Document-shape tests, including a check against the strict index mapping.

`setup/index_template.json` sets `dynamic: strict`, so any field the collector
emits that the mapping does not declare is REJECTED at index time — silently
losing verdicts in production. The mapping-conformance test below is what stops
that from ever shipping.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from typing import Any, Dict, Set

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

from ccs_monitor.config import ClusterConfig, RemoteBaseline  # noqa: E402
from ccs_monitor.documents import (  # noqa: E402
    build_documents,
    new_run_id,
    prune,
    run_document,
    utc_now_iso,
    verdict_document,
)
from ccs_monitor.evaluate import DOC_TYPE_RUN, evaluate_cluster, overall_severity, severity_counts  # noqa: E402
from ccs_monitor.probe import ProbeResult  # noqa: E402


def flatten_mapping(mapping: Dict[str, Any], prefix: str = "") -> Set[str]:
    """Every leaf field path an index mapping declares."""
    paths: Set[str] = set()
    for name, definition in (mapping.get("properties") or {}).items():
        path = f"{prefix}{name}"
        if "properties" in definition:
            paths |= flatten_mapping(definition, prefix=f"{path}.")
        else:
            paths.add(path)
    return paths


def flatten_document(document: Any, prefix: str = "") -> Set[str]:
    """Every leaf field path a document actually carries."""
    paths: Set[str] = set()
    for name, value in document.items():
        path = f"{prefix}{name}"
        if isinstance(value, dict):
            paths |= flatten_document(value, prefix=f"{path}.")
        else:
            paths.add(path)
    return paths


def sample_cluster_verdicts():
    """One cluster exercising every verdict shape at once."""
    cluster = ClusterConfig(
        name="prod",
        base_url="https://prod.example.com:9200",
        environment="prod",
        expected_remotes={
            "remote_ok": RemoteBaseline(
                name="remote_ok", expected_nodes=3, expected_mode="sniff",
                expected_skip_unavailable=False, expected_initial_connect_timeout="30s",
            ),
            "remote_partial": RemoteBaseline(
                name="remote_partial", expected_nodes=3, expected_mode="proxy",
                expected_skip_unavailable=True, expected_initial_connect_timeout="30s",
            ),
            "remote_gone": RemoteBaseline(name="remote_gone", expected_nodes=2, expected_mode="sniff"),
        },
    )
    probe = ProbeResult(
        cluster="prod", base_url=cluster.base_url, ok=True, duration_ms=42.5,
        remotes={
            "remote_ok": {
                "connected": True, "mode": "sniff", "seeds": ["10.0.0.1:9300"],
                "num_nodes_connected": 3, "max_connections_per_cluster": 3,
                "initial_connect_timeout": "30s", "skip_unavailable": False,
            },
            "remote_partial": {
                "connected": True, "mode": "proxy", "proxy_address": "r.example.com:9400",
                "num_proxy_sockets_connected": 1, "max_proxy_socket_connections": 3,
                "initial_connect_timeout": "10s", "skip_unavailable": True,
            },
            "remote_surprise": {
                "connected": True, "mode": "sniff", "num_nodes_connected": 1,
                "max_connections_per_cluster": 3, "initial_connect_timeout": "30s",
                "skip_unavailable": False,
            },
        },
    )
    unreachable_cluster = ClusterConfig(
        name="qa", base_url="https://qa.example.com:9200", environment="qa",
        expected_remotes={"remote_qa": RemoteBaseline(name="remote_qa", expected_nodes=3)},
    )
    unreachable_probe = ProbeResult(
        cluster="qa", base_url=unreachable_cluster.base_url, ok=False, duration_ms=10000.0,
        error="TLS verification failed", error_kind="tls_error",
    )
    return [
        evaluate_cluster(cluster, probe),
        evaluate_cluster(unreachable_cluster, unreachable_probe),
    ]


class PruneTests(unittest.TestCase):
    def test_none_is_dropped_but_false_and_zero_survive(self):
        pruned = prune({"a": None, "b": False, "c": 0, "d": "", "e": []})
        self.assertNotIn("a", pruned)
        self.assertIs(pruned["b"], False)
        self.assertEqual(pruned["c"], 0)
        self.assertEqual(pruned["d"], "")

    def test_nested_empty_objects_are_dropped(self):
        self.assertEqual(prune({"outer": {"inner": None}}), {})


class TimestampTests(unittest.TestCase):
    def test_timestamp_is_iso8601_utc_with_milliseconds(self):
        stamp = utc_now_iso()
        self.assertTrue(stamp.endswith("Z"), stamp)
        self.assertRegex(stamp, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

    def test_run_ids_are_unique(self):
        self.assertNotEqual(new_run_id(), new_run_id())


class DocumentShapeTests(unittest.TestCase):
    def setUp(self):
        self.cluster_verdicts = sample_cluster_verdicts()
        self.documents = build_documents(
            self.cluster_verdicts,
            run_id="testrun",
            overall=overall_severity(self.cluster_verdicts),
            counts=severity_counts(self.cluster_verdicts),
            duration_ms=1234.5,
        )

    def test_one_document_per_verdict_plus_one_run_document(self):
        verdicts = sum(len(cv.verdicts) for cv in self.cluster_verdicts)
        self.assertEqual(len(self.documents), verdicts + 1)
        self.assertEqual(self.documents[-1]["ccs"]["doc_type"], DOC_TYPE_RUN)

    def test_every_document_in_a_cycle_shares_one_timestamp(self):
        # One timestamp per cycle keeps a cycle's verdicts inside a single
        # alerting window, which is what prevents split-window flapping.
        stamps = {doc["@timestamp"] for doc in self.documents}
        self.assertEqual(len(stamps), 1)

    def test_run_document_counts_match_the_verdicts(self):
        run = self.documents[-1]["ccs"]
        self.assertEqual(run["clusters_total"], 2)
        self.assertEqual(run["clusters_unreachable"], 1)
        self.assertEqual(run["verdicts_total"], sum(run["counts"].values()))

    def test_unreachable_cluster_document_has_no_remote_but_has_an_alert_key(self):
        cluster_docs = [d for d in self.documents if d["ccs"]["doc_type"] == "cluster"]
        self.assertEqual(len(cluster_docs), 1)
        self.assertNotIn("remote", cluster_docs[0]["ccs"])
        self.assertEqual(cluster_docs[0]["ccs"]["alert_key"], "qa:_cluster")
        self.assertEqual(cluster_docs[0]["ccs"]["probe"]["error_kind"], "tls_error")

    def test_severity_rank_matches_severity(self):
        for document in self.documents:
            ccs = document["ccs"]
            expected = {"HEALTHY": 0, "INFO": 1, "WARNING": 2, "CRITICAL": 3}[ccs["severity"]]
            self.assertEqual(ccs["severity_rank"], expected)

    def test_documents_are_json_serialisable(self):
        for document in self.documents:
            json.loads(json.dumps(document))

    def test_run_document_can_be_disabled(self):
        documents = build_documents(self.cluster_verdicts, "r", include_run_document=False)
        self.assertFalse([d for d in documents if d["ccs"]["doc_type"] == DOC_TYPE_RUN])


class MappingConformanceTests(unittest.TestCase):
    """Every emitted field must exist in the strict mapping, or ES rejects the doc."""

    def setUp(self):
        with open(os.path.join(ROOT, "setup", "index_template.json"), "r", encoding="utf-8") as fh:
            self.mapping = json.load(fh)
        self.mapped = flatten_mapping(self.mapping)

    def test_mapping_is_strict(self):
        self.assertEqual(self.mapping.get("dynamic"), "strict")

    def test_every_emitted_field_is_mapped(self):
        cluster_verdicts = sample_cluster_verdicts()
        documents = build_documents(
            cluster_verdicts, "run", overall=overall_severity(cluster_verdicts),
            counts=severity_counts(cluster_verdicts), duration_ms=10.0,
        )
        emitted: Set[str] = set()
        for document in documents:
            emitted |= flatten_document(document)

        unmapped = emitted - self.mapped
        self.assertEqual(
            unmapped, set(),
            f"These fields are emitted but not declared in setup/index_template.json, "
            f"so a strict mapping would reject the document: {sorted(unmapped)}",
        )

    def test_fields_the_alerting_rules_query_are_mapped(self):
        # If any of these are renamed, alerting/rules/*.json must change with them.
        for field in (
            "ccs.severity", "ccs.doc_type", "ccs.alert_key", "ccs.monitored",
            "ccs.remote", "ccs.local_cluster", "ccs.reason", "@timestamp",
        ):
            self.assertIn(field, self.mapped, f"{field} is queried by the Kibana rules")


class SingleVerdictDocumentTests(unittest.TestCase):
    def test_verdict_document_carries_the_baseline_and_the_observation(self):
        cluster_verdicts = sample_cluster_verdicts()
        partial = next(
            v for v in cluster_verdicts[0].verdicts if v.remote == "remote_partial"
        )
        document = verdict_document(partial, "run-1")["ccs"]
        self.assertEqual(document["nodes"], {"expected": 3, "actual": 1, "max_configured": 3, "deficit": 2})
        self.assertEqual(document["mode"], {"expected": "proxy", "actual": "proxy", "drift": False})
        self.assertEqual(document["initial_connect_timeout"]["actual"], "10s")
        self.assertTrue(document["skip_unavailable"])
        self.assertIn("skip_unavailable_risk", document["reason_codes"])

    def test_run_document_reports_the_overall_severity(self):
        document = run_document("run-2", [], "CRITICAL", {"CRITICAL": 1}, 100.0)
        self.assertEqual(document["ccs"]["severity"], "CRITICAL")
        self.assertEqual(document["ccs"]["alert_key"], "_run")
        self.assertEqual(document["event"]["kind"], "metric")


if __name__ == "__main__":
    unittest.main()
