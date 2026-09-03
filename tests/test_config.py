"""Configuration parsing and validation tests.

A silently mis-parsed baseline becomes a silently wrong verdict, so the parser is
strict and these tests pin that strictness down.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ccs_monitor.config import (  # noqa: E402
    ConfigError,
    load_config,
    parse_config,
    state_store_endpoint,
)
from ccs_monitor.credentials import (  # noqa: E402
    CredentialError,
    EnvCredentialProvider,
    FileCredentialProvider,
    build_auth_header,
)


def minimal(**overrides):
    document = {
        "clusters": [
            {
                "name": "dev",
                "base_url": "https://dev.example.com:9200",
                "expected_remotes": {"remote_a": {"expected_nodes": 3, "expected_mode": "sniff"}},
            }
        ],
        "state_store": {"cluster": "dev"},
    }
    document.update(overrides)
    return document


class ClusterParsingTests(unittest.TestCase):
    def test_minimal_config_parses(self):
        config = parse_config(minimal())
        self.assertEqual(len(config.clusters), 1)
        self.assertEqual(config.clusters[0].name, "dev")
        # environment defaults to the cluster name.
        self.assertEqual(config.clusters[0].environment, "dev")
        self.assertEqual(config.clusters[0].expected_remotes["remote_a"].expected_nodes, 3)

    def test_trailing_slash_is_stripped_from_base_url(self):
        document = minimal()
        document["clusters"][0]["base_url"] = "https://dev.example.com:9200/"
        self.assertEqual(parse_config(document).clusters[0].base_url, "https://dev.example.com:9200")

    def test_non_http_base_url_is_rejected(self):
        document = minimal()
        document["clusters"][0]["base_url"] = "dev.example.com:9200"
        with self.assertRaisesRegex(ConfigError, "http"):
            parse_config(document)

    def test_duplicate_cluster_names_are_rejected(self):
        document = minimal()
        document["clusters"].append(dict(document["clusters"][0]))
        with self.assertRaisesRegex(ConfigError, "duplicate"):
            parse_config(document)

    def test_empty_cluster_list_is_rejected(self):
        with self.assertRaisesRegex(ConfigError, "non-empty"):
            parse_config({"clusters": []})

    def test_unknown_remote_key_is_rejected(self):
        # A typo'd key must fail loudly, not be ignored into a wrong baseline.
        document = minimal()
        document["clusters"][0]["expected_remotes"]["remote_a"]["expected_node"] = 3
        with self.assertRaisesRegex(ConfigError, "unknown key"):
            parse_config(document)

    def test_bad_mode_is_rejected(self):
        document = minimal()
        document["clusters"][0]["expected_remotes"]["remote_a"]["expected_mode"] = "gossip"
        with self.assertRaisesRegex(ConfigError, "sniff"):
            parse_config(document)

    def test_comment_keys_are_allowed_everywhere(self):
        document = minimal()
        document["_comment"] = "notes"
        document["clusters"][0]["expected_remotes"]["_comment"] = "ignored"
        document["clusters"][0]["expected_remotes"]["remote_a"]["_comment"] = "also ignored"
        document["clusters"][0]["severity_policy"] = {"_comment": "why", "partial_pool": "INFO"}
        config = parse_config(document)
        self.assertNotIn("_comment", config.clusters[0].expected_remotes)
        self.assertEqual(config.clusters[0].policy["partial_pool"], "INFO")


class SeverityPolicyTests(unittest.TestCase):
    def test_unknown_policy_key_is_rejected(self):
        document = minimal()
        document["clusters"][0]["severity_policy"] = {"partial_poool": "WARNING"}
        with self.assertRaisesRegex(ConfigError, "unknown severity_policy key"):
            parse_config(document)

    def test_invalid_severity_value_is_rejected(self):
        document = minimal()
        document["clusters"][0]["severity_policy"] = {"partial_pool": "BAD"}
        with self.assertRaisesRegex(ConfigError, "must be one of"):
            parse_config(document)

    def test_negative_node_floor_is_rejected(self):
        document = minimal()
        document["clusters"][0]["severity_policy"] = {"critical_below_nodes": -1}
        with self.assertRaisesRegex(ConfigError, "non-negative"):
            parse_config(document)

    def test_cluster_policy_overrides_defaults_and_remote_overrides_cluster(self):
        document = minimal(defaults={"severity_policy": {"partial_pool": "INFO"}})
        document["clusters"][0]["severity_policy"] = {"partial_pool": "WARNING"}
        document["clusters"][0]["expected_remotes"]["remote_a"]["severity_policy"] = {
            "partial_pool": "CRITICAL"
        }
        config = parse_config(document)
        cluster = config.clusters[0]
        effective = cluster.policy_for(cluster.expected_remotes["remote_a"])
        self.assertEqual(effective["partial_pool"], "CRITICAL")
        self.assertEqual(cluster.policy_for(None)["partial_pool"], "WARNING")


class TlsTests(unittest.TestCase):
    def test_ca_cert_becomes_the_verify_value(self):
        document = minimal()
        document["clusters"][0]["ca_cert"] = "/etc/pki/agency-ca.pem"
        self.assertEqual(parse_config(document).clusters[0].verify, "/etc/pki/agency-ca.pem")

    def test_verify_false_is_honoured(self):
        document = minimal()
        document["clusters"][0]["verify_certs"] = False
        self.assertIs(parse_config(document).clusters[0].verify, False)

    def test_ca_cert_with_verification_off_is_rejected(self):
        # Silently ignoring a configured CA bundle would be the worst outcome.
        document = minimal()
        document["clusters"][0]["ca_cert"] = "/etc/pki/agency-ca.pem"
        document["clusters"][0]["verify_certs"] = False
        with self.assertRaisesRegex(ConfigError, "refusing"):
            parse_config(document)


class StateStoreTests(unittest.TestCase):
    def test_default_index_is_visible_not_hidden(self):
        self.assertEqual(parse_config(minimal()).state_store.index, "ccs-health-monitor")

    def test_dot_prefixed_index_is_rejected(self):
        # This project deliberately uses a visible index.
        document = minimal(state_store={"cluster": "dev", "index": ".ccs-health-monitor"})
        with self.assertRaisesRegex(ConfigError, "hidden"):
            parse_config(document)

    def test_unknown_state_store_cluster_is_rejected(self):
        document = minimal(state_store={"cluster": "nope"})
        with self.assertRaisesRegex(ConfigError, "not in the inventory"):
            parse_config(document)

    def test_state_store_needs_a_target(self):
        document = minimal(state_store={"enabled": True})
        with self.assertRaisesRegex(ConfigError, "cluster.*base_url"):
            parse_config(document)

    def test_dsl_lifecycle_is_rejected_for_alias_mode(self):
        document = minimal(state_store={"cluster": "dev", "mode": "index", "lifecycle": "dsl"})
        with self.assertRaisesRegex(ConfigError, "data_stream"):
            parse_config(document)

    def test_endpoint_inherits_url_and_tls_from_the_named_cluster(self):
        document = minimal()
        document["clusters"][0]["ca_cert"] = "/etc/pki/ca.pem"
        endpoint = state_store_endpoint(parse_config(document))
        self.assertEqual(endpoint["base_url"], "https://dev.example.com:9200")
        self.assertEqual(endpoint["verify"], "/etc/pki/ca.pem")
        self.assertEqual(endpoint["credentials_key"], "dev")

    def test_explicit_base_url_wins_over_the_named_cluster(self):
        document = minimal(state_store={
            "cluster": "dev",
            "base_url": "https://monitoring.example.com:9200",
            "credentials_key": "monitoring",
        })
        endpoint = state_store_endpoint(parse_config(document))
        self.assertEqual(endpoint["base_url"], "https://monitoring.example.com:9200")
        self.assertEqual(endpoint["credentials_key"], "monitoring")

    def test_bootstrap_index_name(self):
        self.assertEqual(parse_config(minimal()).state_store.bootstrap_index,
                         "ccs-health-monitor-000001")


class CredentialTests(unittest.TestCase):
    def test_api_key_header(self):
        self.assertEqual(build_auth_header({"api_key": "abc123"}, "x"), "ApiKey abc123")

    def test_basic_auth_header(self):
        self.assertEqual(build_auth_header({"username": "u", "password": "p"}, "x"), "Basic dTpw")

    def test_placeholder_key_is_rejected(self):
        with self.assertRaisesRegex(CredentialError, "placeholder"):
            build_auth_header({"api_key": "REPLACE_WITH_BASE64_ID_COLON_APIKEY"}, "x")

    def test_empty_entry_is_rejected(self):
        with self.assertRaisesRegex(CredentialError, "no usable credential"):
            build_auth_header({}, "x")

    def test_file_provider_reads_a_cluster_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "credentials.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"dev": {"api_key": "devkey"}}, handle)
            os.chmod(path, 0o600)
            self.assertEqual(FileCredentialProvider(path).get("dev"), "ApiKey devkey")

    def test_file_provider_names_the_known_keys_when_one_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "credentials.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"dev": {"api_key": "devkey"}}, handle)
            with self.assertRaisesRegex(CredentialError, "dev"):
                FileCredentialProvider(path).get("prod")

    def test_missing_file_explains_the_fix(self):
        with self.assertRaisesRegex(CredentialError, "credentials.example.json"):
            FileCredentialProvider("/nonexistent/credentials.json").get("dev")

    def test_env_provider_uppercases_the_cluster_name(self):
        os.environ["CCS_API_KEY_PROD_EAST"] = "envkey"
        try:
            self.assertEqual(EnvCredentialProvider().get("prod-east"), "ApiKey envkey")
        finally:
            del os.environ["CCS_API_KEY_PROD_EAST"]

    def test_env_provider_names_the_variable_it_wanted(self):
        with self.assertRaisesRegex(CredentialError, "CCS_API_KEY_QA"):
            EnvCredentialProvider().get("qa")


class LoadConfigTests(unittest.TestCase):
    def test_missing_file_is_a_clear_error(self):
        with self.assertRaisesRegex(ConfigError, "not found"):
            load_config("/nonexistent/es_clusters.json")

    def test_invalid_json_is_a_clear_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{not json")
            with self.assertRaisesRegex(ConfigError, "not valid JSON"):
                load_config(path)

    def test_relative_credentials_path_resolves_against_the_inventory(self):
        # A cron job runs from a different working directory; the path must still resolve.
        with tempfile.TemporaryDirectory() as tmp:
            inventory = os.path.join(tmp, "es_clusters.json")
            with open(inventory, "w", encoding="utf-8") as handle:
                json.dump(minimal(credentials={"provider": "file", "path": "credentials.json"}), handle)
            config = load_config(inventory)
            self.assertEqual(config.credentials.path, os.path.join(tmp, "credentials.json"))

    def test_the_shipped_inventory_is_valid(self):
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config = load_config(os.path.join(root, "es_clusters.json"))
        self.assertEqual(config.state_store.index, "ccs-health-monitor")
        self.assertEqual({c.name for c in config.clusters}, {"dev", "qa", "prod", "ccs"})
        # The prod override from Phase-0 decision #3 must survive parsing.
        prod = config.cluster("prod")
        self.assertEqual(prod.policy_for(None)["critical_below_nodes"], 2)
        self.assertTrue(prod.policy_for(None)["escalate_warning_when_skip_unavailable"])


if __name__ == "__main__":
    unittest.main()
