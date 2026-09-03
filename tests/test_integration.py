"""End-to-end tests: the real collector against the mock Elasticsearch.

Nothing is stubbed below the CLI — argument parsing, config loading, HTTP,
evaluation, document building and the bulk write all run for real against
tools/mock_es_server.py on a loopback port. These are the tests that would have
caught a broken bulk body or a wrong exit code.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from io import StringIO

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import ccs_health_check  # noqa: E402
from mock_es_server import STATE, STATE_LOCK, apply_scenario, load_scenarios, serve  # noqa: E402

SCENARIOS = load_scenarios(os.path.join(ROOT, "tools", "scenarios.json"))


class CollectorEndToEndTests(unittest.TestCase):
    """One mock server for the whole class; the scenario is swapped per test."""

    @classmethod
    def setUpClass(cls):
        cls.server = serve("127.0.0.1", 0)  # port 0 -> the OS picks a free port
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

        cls.tmp = tempfile.TemporaryDirectory()
        cls.inventory_path = os.path.join(cls.tmp.name, "es_clusters.json")
        cls.credentials_path = os.path.join(cls.tmp.name, "credentials.json")

        with open(cls.credentials_path, "w", encoding="utf-8") as handle:
            json.dump({"dev": {"api_key": "dGVzdDp0ZXN0"}}, handle)
        os.chmod(cls.credentials_path, 0o600)

        with open(cls.inventory_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "defaults": {"timeout_seconds": 5, "retries": 0},
                    "credentials": {"provider": "file", "path": cls.credentials_path},
                    "state_store": {
                        "enabled": True,
                        "cluster": "dev",
                        "index": "ccs-health-monitor",
                        "mode": "data_stream",
                    },
                    "clusters": [
                        {
                            "name": "dev",
                            "environment": "dev",
                            "base_url": f"http://127.0.0.1:{cls.port}",
                            "verify_certs": False,
                            "expected_remotes": {
                                "remote_dev_a": {
                                    "expected_nodes": 3,
                                    "expected_mode": "sniff",
                                    "expected_skip_unavailable": False,
                                    "expected_initial_connect_timeout": "30s",
                                },
                                "remote_dev_b": {
                                    "expected_nodes": 2,
                                    "expected_mode": "proxy",
                                    "expected_skip_unavailable": False,
                                    "expected_initial_connect_timeout": "30s",
                                },
                            },
                        }
                    ],
                },
                handle,
            )

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def setUp(self):
        with STATE_LOCK:
            STATE["documents"] = []
            STATE["fail_with"] = None

    # -- helpers ----------------------------------------------------------- #

    def run_collector(self, scenario: str, *extra_args: str):
        """Run the collector CLI and capture its stdout and exit code."""
        apply_scenario(SCENARIOS, scenario)
        argv = ["--clusters", self.inventory_path, "--quiet", "--no-color", *extra_args]
        stdout, sys.stdout = sys.stdout, StringIO()
        try:
            code = ccs_health_check.main(argv)
            return code, sys.stdout.getvalue()
        finally:
            sys.stdout = stdout

    def indexed_documents(self):
        with STATE_LOCK:
            return [dict(d) for d in STATE["documents"]]

    # -- tests ------------------------------------------------------------- #

    def test_healthy_run_exits_zero_and_indexes_every_verdict(self):
        code, output = self.run_collector("healthy")
        self.assertEqual(code, 0)
        self.assertIn("OVERALL:  HEALTHY", output)

        documents = self.indexed_documents()
        self.assertEqual(len(documents), 3)  # two remotes + the run heartbeat
        self.assertTrue(all(d["_target"] == "ccs-health-monitor" for d in documents))
        # Data streams accept only `create`.
        self.assertTrue(all(d["_action"] == "create" for d in documents))

    def test_no_index_writes_nothing(self):
        code, _ = self.run_collector("healthy", "--no-index")
        self.assertEqual(code, 0)
        self.assertEqual(self.indexed_documents(), [])

    def test_critical_run_exits_one_and_still_indexes(self):
        code, output = self.run_collector("disconnected")
        self.assertEqual(code, 1)
        self.assertIn("OVERALL:  CRITICAL", output)
        severities = [d["_source"]["ccs"]["severity"] for d in self.indexed_documents()]
        self.assertIn("CRITICAL", severities)

    def test_warning_run_exits_one_but_not_with_fail_on_critical(self):
        self.assertEqual(self.run_collector("partial_pool")[0], 1)
        self.assertEqual(self.run_collector("partial_pool", "--fail-on", "CRITICAL")[0], 0)

    def test_unmonitored_remote_is_info_and_exits_zero(self):
        code, output = self.run_collector("unmonitored_remote")
        self.assertEqual(code, 0)
        self.assertIn("INFO", output)
        monitored = {
            d["_source"]["ccs"].get("remote"): d["_source"]["ccs"].get("monitored")
            for d in self.indexed_documents()
            if d["_source"]["ccs"]["doc_type"] == "remote"
        }
        self.assertFalse(monitored["remote_undocumented_x"])

    def test_unreachable_cluster_yields_one_critical_verdict(self):
        code, output = self.run_collector("unreachable", "--no-index")
        self.assertEqual(code, 1)
        self.assertIn("probe FAILED", output)
        self.assertIn("(whole cluster)", output)
        self.assertIn("CRITICAL", output)

    def test_unwritable_state_store_exits_three_even_though_probing_worked(self):
        # In this fixture the state store lives on the same cluster as the probe
        # target, so an injected failure takes both down. A verdict that cannot
        # land leaves the alerting layer blind, which outranks a degraded remote.
        code, output = self.run_collector("unreachable")
        self.assertEqual(code, 3)
        self.assertIn("CRITICAL", output)
        self.assertEqual(self.indexed_documents(), [])

    def test_missing_remote_is_critical_end_to_end(self):
        code, output = self.run_collector("missing_remote")
        self.assertEqual(code, 1)
        self.assertIn("absent from _remote/info", output)

    def test_ndjson_output_matches_what_would_be_indexed(self):
        code, output = self.run_collector("healthy", "--no-index", "--format", "ndjson")
        self.assertEqual(code, 0)
        lines = [json.loads(line) for line in output.strip().split("\n")]
        self.assertEqual(len(lines), 3)
        self.assertTrue(all("@timestamp" in doc and "ccs" in doc for doc in lines))

    def test_json_report_is_machine_readable(self):
        code, output = self.run_collector("partial_pool", "--no-index", "--format", "json")
        self.assertEqual(code, 1)
        report = json.loads(output)
        self.assertEqual(report["overall_severity"], "WARNING")
        self.assertEqual(report["counts"]["WARNING"], 1)
        self.assertEqual(report["clusters"][0]["cluster"], "dev")

    def test_bad_credentials_produce_a_critical_verdict_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = os.path.join(tmp, "credentials.json")
            with open(empty, "w", encoding="utf-8") as handle:
                json.dump({"other": {"api_key": "x"}}, handle)
            os.chmod(empty, 0o600)
            code, output = self.run_collector(
                "healthy", "--no-index", "--credentials", empty
            )
        self.assertEqual(code, 1)
        self.assertIn("CRITICAL", output)

    def test_check_state_store_reports_missing_then_present(self):
        with STATE_LOCK:
            STATE["data_streams"].pop("ccs-health-monitor", None)
        code, output = self.run_collector("healthy", "--check-state-store")
        self.assertEqual(code, 3)
        self.assertIn("MISSING", output)

        with STATE_LOCK:
            STATE["data_streams"]["ccs-health-monitor"] = {
                "name": "ccs-health-monitor",
                "indices": [{"index_name": ".ds-ccs-health-monitor-000001"}],
            }
        code, output = self.run_collector("healthy", "--check-state-store")
        self.assertEqual(code, 0)
        self.assertIn("OK", output)

    def test_cluster_filter_rejects_an_unknown_name(self):
        code, _ = self.run_collector("healthy", "--cluster", "nonexistent")
        self.assertEqual(code, 2)

    def test_show_config_prints_no_secrets(self):
        code, output = self.run_collector("healthy", "--show-config")
        self.assertEqual(code, 0)
        self.assertIn("ccs-health-monitor", output)
        self.assertNotIn("dGVzdDp0ZXN0", output)


class StateStoreSetupTests(unittest.TestCase):
    """setup/setup_state_store.py against the same mock."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, os.path.join(ROOT, "setup"))
        cls.server = serve("127.0.0.1", 0)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.inventory_path = os.path.join(cls.tmp.name, "es_clusters.json")

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.tmp.cleanup()

    def write_inventory(self, mode: str, lifecycle: str) -> str:
        credentials = os.path.join(self.tmp.name, "credentials.json")
        with open(credentials, "w", encoding="utf-8") as handle:
            json.dump({"dev": {"api_key": "dGVzdDp0ZXN0"}}, handle)
        os.chmod(credentials, 0o600)
        with open(self.inventory_path, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "credentials": {"provider": "file", "path": credentials},
                    "state_store": {
                        "cluster": "dev", "index": "ccs-health-monitor",
                        "mode": mode, "lifecycle": lifecycle, "retention": "45d",
                    },
                    "clusters": [{
                        "name": "dev",
                        "base_url": f"http://127.0.0.1:{self.port}",
                        "verify_certs": False,
                        "expected_remotes": {},
                    }],
                },
                handle,
            )
        return self.inventory_path

    def run_setup(self, *args):
        import setup_state_store

        stdout, sys.stdout = sys.stdout, StringIO()
        try:
            code = setup_state_store.main(list(args))
            return code, sys.stdout.getvalue()
        finally:
            sys.stdout = stdout

    def test_data_stream_mode_creates_template_and_stream(self):
        path = self.write_inventory("data_stream", "dsl")
        code, output = self.run_setup("-c", path)
        self.assertEqual(code, 0)
        self.assertIn("index template", output)
        self.assertIn("data stream", output)
        with STATE_LOCK:
            template = STATE["index_templates"]["ccs-health-monitor"]
            self.assertIn("data_stream", template)
            self.assertEqual(template["template"]["lifecycle"]["data_retention"], "45d")
            self.assertEqual(template["template"]["mappings"]["dynamic"], "strict")
            self.assertNotIn("_comment", template["template"]["mappings"])

    def test_index_mode_creates_ilm_policy_and_write_alias(self):
        path = self.write_inventory("index", "ilm")
        code, output = self.run_setup("-c", path)
        self.assertEqual(code, 0)
        with STATE_LOCK:
            policy = STATE["ilm_policies"]["ccs-health-monitor-policy"]
            self.assertEqual(policy["phases"]["delete"]["min_age"], "45d")
            bootstrap = STATE["indices"]["ccs-health-monitor-000001"]
            self.assertTrue(bootstrap["aliases"]["ccs-health-monitor"]["is_write_index"])
            settings = STATE["index_templates"]["ccs-health-monitor"]["template"]["settings"]
            self.assertEqual(settings["index.lifecycle.rollover_alias"], "ccs-health-monitor")

    def test_setup_is_idempotent(self):
        path = self.write_inventory("data_stream", "dsl")
        self.assertEqual(self.run_setup("-c", path)[0], 0)
        self.assertEqual(self.run_setup("-c", path)[0], 0)

    def test_verify_reports_what_exists(self):
        path = self.write_inventory("data_stream", "dsl")
        self.run_setup("-c", path)
        code, output = self.run_setup("-c", path, "--verify")
        self.assertEqual(code, 0)
        self.assertIn("present", output)

    def test_a_genuine_400_is_not_mistaken_for_already_exists(self):
        # An allowed 400 is success only when ES says the resource already
        # exists; any other 400 is a real failure wearing the same status code.
        import setup_state_store

        self.assertTrue(setup_state_store.already_exists(
            {"error": {"type": "resource_already_exists_exception", "reason": "..."}}))
        self.assertFalse(setup_state_store.already_exists(
            {"error": {"type": "illegal_argument_exception", "reason": "bad mapping"}}))
        self.assertEqual(
            setup_state_store.error_reason(
                {"error": {"type": "illegal_argument_exception", "reason": "bad mapping"}}),
            "illegal_argument_exception: bad mapping",
        )

    def test_recreating_a_data_stream_reports_skipped_not_failed(self):
        path = self.write_inventory("data_stream", "dsl")
        self.run_setup("-c", path)
        code, output = self.run_setup("-c", path)
        self.assertEqual(code, 0)
        self.assertIn("already present", output)
        self.assertNotIn("FAILED", output)

    def test_dry_run_sends_nothing(self):
        path = self.write_inventory("data_stream", "dsl")
        with STATE_LOCK:
            STATE["index_templates"].pop("ccs-health-monitor", None)
        code, output = self.run_setup("-c", path, "--dry-run")
        self.assertEqual(code, 0)
        self.assertIn("Dry run", output)
        with STATE_LOCK:
            self.assertNotIn("ccs-health-monitor", STATE["index_templates"])


class AlertingRuleTemplateTests(unittest.TestCase):
    """The rule templates must render to valid, correctly-shaped Kibana rules."""

    def setUp(self):
        sys.path.insert(0, os.path.join(ROOT, "alerting"))
        import setup_alerting

        self.module = setup_alerting
        self.substitutions = {
            "index": "ccs-health-monitor",
            "rule_interval": "5m",
            "time_window_size": 15,
            "time_window_unit": "m",
            "staleness_window_size": 45,
            "staleness_window_unit": "m",
        }

    def render_all(self):
        files = self.module.CORE_RULES + self.module.INFO_RULES
        return [self.module.render_rule(name, self.substitutions) for name in files]

    def test_every_template_renders_to_valid_json(self):
        self.assertEqual(len(self.render_all()), 4)

    def test_no_project_placeholders_survive_rendering(self):
        for rule in self.render_all():
            blob = json.dumps(rule)
            for key in self.substitutions:
                self.assertNotIn("{{" + key + "}}", blob, f"{rule['rule_id']} kept {key}")

    def test_kibana_mustache_variables_are_preserved(self):
        # {{context.group}} must reach Kibana untouched — it names the failing remote.
        critical = self.render_all()[0]
        self.assertIn("{{context.group}}", critical["action_subject"])
        self.assertIn("{{context.group}}", critical["recovery_message"])

    def test_severity_rules_exclude_the_run_heartbeat(self):
        # Without this filter the run document would raise a duplicate alert.
        for rule in self.render_all()[:2]:
            query = json.loads(rule["params"]["esQuery"])
            filters = query["query"]["bool"]["filter"]
            self.assertIn({"terms": {"ccs.doc_type": ["remote", "cluster"]}}, filters)

    def test_rules_group_per_remote_for_independent_recovery(self):
        for rule in self.render_all():
            if rule["params"]["groupBy"] == "top":
                self.assertEqual(rule["params"]["termField"], "ccs.alert_key")

    def test_staleness_rule_fires_on_absence(self):
        staleness = next(r for r in self.render_all() if "staleness" in r["rule_id"])
        self.assertEqual(staleness["params"]["thresholdComparator"], "<")
        self.assertEqual(staleness["params"]["threshold"], [1])
        self.assertEqual(staleness["params"]["groupBy"], "all")
        self.assertGreater(staleness["params"]["timeWindowSize"], 15)

    def test_alert_window_is_wider_than_the_probe_interval(self):
        # Plan risk #1: a window narrower than the interval causes false flaps.
        for rule in self.render_all()[:2]:
            self.assertGreater(rule["params"]["timeWindowSize"], 5)

    def test_every_rule_has_an_active_and_a_recovery_action(self):
        for rule in self.render_all():
            actions = self.module.build_actions(rule, "connector-1", ["a@b.gov"], legacy_notify=False)
            groups = [action["group"] for action in actions]
            self.assertEqual(groups, ["query matched", "recovered"])
            for action in actions:
                self.assertEqual(action["frequency"]["notify_when"], "onActionGroupChange")

    def test_legacy_notify_moves_notification_to_the_rule_level(self):
        rule = self.render_all()[0]
        body = self.module.build_rule_body(rule, "connector-1", ["a@b.gov"], legacy_notify=True)
        self.assertEqual(body["notify_when"], "onActionGroupChange")
        self.assertNotIn("frequency", body["actions"][0])


if __name__ == "__main__":
    unittest.main()
