#!/usr/bin/env python3
"""
setup_state_store.py — create the `ccs-health-monitor` state store (Phase 2).

Covers CCS-11 (index + explicit mapping) and CCS-12 (retention). Everything it
does is idempotent, so it is safe to re-run after editing the mapping or the
retention period.

What it creates, driven entirely by the `state_store` block of es_clusters.json:

  lifecycle "ilm"  ->  PUT _ilm/policy/<ilm_policy>
  always           ->  PUT _index_template/<index_template>   (mapping + settings)
  mode data_stream ->  PUT _data_stream/<index>
  mode index       ->  PUT <index>-000001 with <index> as its write alias

Usage:
    python3 setup/setup_state_store.py --clusters es_clusters.json --dry-run
    python3 setup/setup_state_store.py --clusters es_clusters.json
    python3 setup/setup_state_store.py --clusters es_clusters.json --verify
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List

# Make the project root importable when run as `python3 setup/setup_state_store.py`.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ccs_monitor.config import AppConfig, ConfigError, load_config, state_store_endpoint  # noqa: E402
from ccs_monitor.credentials import CredentialError, build_provider  # noqa: E402
from ccs_monitor.http import HttpError, build_session, request_json  # noqa: E402
from ccs_monitor.logging_setup import configure_logging  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
MAPPING_PATH = os.path.join(HERE, "index_template.json")
ILM_PATH = os.path.join(HERE, "ilm_policy.json")

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG_ERROR = 2


def load_json_file(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def already_exists(response: Dict[str, Any]) -> bool:
    """True when an error body says the resource is already there."""
    error = response.get("error")
    if isinstance(error, dict):
        error_type = str(error.get("type", ""))
        return "already_exists" in error_type or "resource_already_exists" in error_type
    return False


def error_reason(response: Dict[str, Any]) -> str:
    """Pull a readable reason out of an Elasticsearch error body."""
    error = response.get("error")
    if isinstance(error, dict):
        return f"{error.get('type', 'error')}: {error.get('reason', 'unknown')}"
    if isinstance(error, str):
        return error
    return ""


def strip_comments(value: Any) -> Any:
    """Drop `_comment` keys so annotated JSON can be sent to Elasticsearch as-is."""
    if isinstance(value, dict):
        return {k: strip_comments(v) for k, v in value.items() if k != "_comment"}
    if isinstance(value, list):
        return [strip_comments(v) for v in value]
    return value


# --------------------------------------------------------------------------- #
# Payload builders
# --------------------------------------------------------------------------- #

def build_ilm_policy(config: AppConfig) -> Dict[str, Any]:
    """Render the ILM policy with this deployment's rollover and retention values."""
    store = config.state_store
    raw = json.dumps(strip_comments(load_json_file(ILM_PATH)))
    rendered = (
        raw.replace("{{rollover_max_age}}", store.rollover_max_age)
        .replace("{{rollover_max_primary_shard_size}}", store.rollover_max_primary_shard_size)
        .replace("{{retention}}", store.retention)
    )
    return json.loads(rendered)


def build_index_template(config: AppConfig) -> Dict[str, Any]:
    """Assemble the index template: mapping + settings + lifecycle + data-stream flag."""
    store = config.state_store
    mappings = strip_comments(load_json_file(MAPPING_PATH))

    settings: Dict[str, Any] = {
        "index.number_of_shards": store.number_of_shards,
        "index.number_of_replicas": store.number_of_replicas,
        # Verdicts are queried by the alerting rules within a minute of landing.
        "index.refresh_interval": "5s",
    }

    template: Dict[str, Any] = {
        "index_patterns": [store.index] if store.mode == "data_stream" else [f"{store.index}-*"],
        "priority": 500,
        "_meta": {
            "description": "CCS remote connection-state verdicts",
            "project": "CCS Remote Connection-State Degradation Monitoring",
            "managed_by": "setup/setup_state_store.py",
        },
        "template": {"settings": settings, "mappings": mappings},
    }

    if store.mode == "data_stream":
        template["data_stream"] = {}
        if store.lifecycle == "dsl":
            # Data-stream lifecycle: retention is a property of the stream itself.
            template["template"]["lifecycle"] = {"data_retention": store.retention}
        elif store.lifecycle == "ilm":
            settings["index.lifecycle.name"] = store.ilm_policy
    else:
        # Alias-backed rollover: ILM needs to know which alias to roll.
        if store.lifecycle == "ilm":
            settings["index.lifecycle.name"] = store.ilm_policy
            settings["index.lifecycle.rollover_alias"] = store.index

    return template


def build_bootstrap_index(config: AppConfig) -> Dict[str, Any]:
    """Body for the first backing index in alias-rollover ('index') mode."""
    return {"aliases": {config.state_store.index: {"is_write_index": True}}}


# --------------------------------------------------------------------------- #
# Apply
# --------------------------------------------------------------------------- #

class Applier:
    def __init__(self, config: AppConfig, dry_run: bool = False):
        self.config = config
        self.store = config.state_store
        self.endpoint = state_store_endpoint(config)
        self.dry_run = dry_run
        self.session = None
        self.failures: List[str] = []

    def _ensure_session(self):
        if self.session is None:
            provider = build_provider(self.config.credentials)
            self.session = build_session(
                auth_header=provider.get(self.endpoint["credentials_key"]),
                retries=self.endpoint["retries"],
                backoff=self.endpoint["retry_backoff"],
            )
        return self.session

    def close(self) -> None:
        if self.session is not None:
            self.session.close()
            self.session = None

    def call(self, method: str, path: str, payload: Any = None, allow_statuses: tuple = ()) -> Any:
        url = f"{self.endpoint['base_url']}{path}"
        if self.dry_run:
            print(f"\n--- {method} {url}")
            if payload is not None:
                print(json.dumps(payload, indent=2))
            return {"acknowledged": True, "_dry_run": True}
        return request_json(
            self._ensure_session(),
            method,
            url,
            verify=self.endpoint["verify"],
            timeout=self.endpoint["timeout"],
            payload=payload,
            expected_statuses=(200, 201),
            allow_statuses=allow_statuses,
        )

    def step(self, description: str, method: str, path: str, payload: Any = None,
             allow_statuses: tuple = ()) -> bool:
        try:
            response = self.call(method, path, payload, allow_statuses)
        except HttpError as exc:
            self.failures.append(f"{description}: {exc}")
            print(f"  FAILED   {description}\n           {exc}")
            return False

        if self.dry_run:
            return True

        if response.get("_allowed"):
            # An allowed status is only a success when it means "already there".
            # Anything else at that status is a real failure wearing a 400.
            if already_exists(response):
                print(f"  SKIPPED  {description} (already present)")
                return True
            reason = error_reason(response) or f"HTTP {response.get('_status')}"
            self.failures.append(f"{description}: {reason}")
            print(f"  FAILED   {description}\n           {reason}")
            return False

        print(f"  OK       {description}")
        return True


def run_setup(config: AppConfig, dry_run: bool, skip_bootstrap: bool) -> int:
    store = config.state_store
    if not store.enabled:
        print("state_store.enabled is false in the inventory — nothing to create.")
        return EXIT_OK

    endpoint = state_store_endpoint(config)
    print(f"State store target: {endpoint['base_url']}")
    print(f"  index      : {store.index}  (mode={store.mode}, lifecycle={store.lifecycle})")
    print(f"  retention  : {store.retention}")
    print(f"  template   : {store.index_template}")
    if store.lifecycle == "ilm":
        print(f"  ilm policy : {store.ilm_policy}")
    print()

    applier = Applier(config, dry_run=dry_run)
    try:
        if store.lifecycle == "ilm":
            applier.step(
                f"ILM policy '{store.ilm_policy}'",
                "PUT",
                f"/_ilm/policy/{store.ilm_policy}",
                build_ilm_policy(config),
            )

        applier.step(
            f"index template '{store.index_template}'",
            "PUT",
            f"/_index_template/{store.index_template}",
            build_index_template(config),
        )

        if not skip_bootstrap:
            if store.mode == "data_stream":
                # 400 = the data stream already exists; treat that as success.
                applier.step(
                    f"data stream '{store.index}'",
                    "PUT",
                    f"/_data_stream/{store.index}",
                    None,
                    allow_statuses=(400,),
                )
            else:
                applier.step(
                    f"bootstrap index '{store.bootstrap_index}' with write alias '{store.index}'",
                    "PUT",
                    f"/{store.bootstrap_index}",
                    build_bootstrap_index(config),
                    allow_statuses=(400,),
                )
    finally:
        applier.close()

    if dry_run:
        print("\nDry run: nothing was sent to Elasticsearch.")
        return EXIT_OK

    print()
    if applier.failures:
        print(f"{len(applier.failures)} step(s) failed:")
        for failure in applier.failures:
            print(f"  - {failure}")
        return EXIT_FAILED

    print("State store ready. Verify with:")
    print(f"  python3 ccs_health_check.py --clusters {config.source_path} --check-state-store")
    return EXIT_OK


def run_verify(config: AppConfig) -> int:
    """Read back what was created and print it."""
    store = config.state_store
    applier = Applier(config, dry_run=False)
    ok = True
    try:
        print(f"Verifying state store '{store.index}' on {applier.endpoint['base_url']}\n")

        if store.lifecycle == "ilm":
            result = applier.call("GET", f"/_ilm/policy/{store.ilm_policy}", allow_statuses=(404,))
            present = not result.get("_allowed")
            print(f"  ilm policy    {store.ilm_policy}: {'present' if present else 'MISSING'}")
            ok = ok and present

        result = applier.call(
            "GET", f"/_index_template/{store.index_template}", allow_statuses=(404,)
        )
        present = not result.get("_allowed")
        print(f"  template      {store.index_template}: {'present' if present else 'MISSING'}")
        ok = ok and present

        if store.mode == "data_stream":
            result = applier.call("GET", f"/_data_stream/{store.index}", allow_statuses=(404,))
            present = not result.get("_allowed")
            print(f"  data stream   {store.index}: {'present' if present else 'MISSING'}")
            if present:
                for stream in result.get("data_streams", []):
                    backing = [i.get("index_name") for i in stream.get("indices", [])]
                    print(f"                backing indices: {backing}")
                    if stream.get("lifecycle"):
                        print(f"                lifecycle: {stream['lifecycle']}")
            ok = ok and present
        else:
            result = applier.call("GET", f"/{store.index}", allow_statuses=(404,))
            present = not result.get("_allowed")
            print(f"  write alias   {store.index}: {'present' if present else 'MISSING'}")
            if present:
                print(f"                resolves to: {[k for k in result if not k.startswith('_')]}")
            ok = ok and present
    except HttpError as exc:
        print(f"  verification request failed: {exc}")
        return EXIT_FAILED
    finally:
        applier.close()

    print()
    print("All components present." if ok else "One or more components are missing — re-run without --verify.")
    return EXIT_OK if ok else EXIT_FAILED


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Create the ccs-health-monitor state store (Phase 2).")
    parser.add_argument("-c", "--clusters", default="es_clusters.json",
                        help="Cluster inventory file (default: %(default)s).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print the exact requests instead of sending them.")
    parser.add_argument("--verify", action="store_true",
                        help="Check what exists instead of creating anything.")
    parser.add_argument("--skip-bootstrap", action="store_true",
                        help="Create the policy and template only; let the first write create the stream.")
    parser.add_argument("--log-level", default="WARNING",
                        choices=("DEBUG", "INFO", "WARNING", "ERROR"))
    args = parser.parse_args(argv)

    configure_logging(level=args.log_level)

    try:
        config = load_config(args.clusters)
    except ConfigError as exc:
        sys.stderr.write(f"Configuration error: {exc}\n")
        return EXIT_CONFIG_ERROR

    try:
        if args.verify:
            return run_verify(config)
        return run_setup(config, args.dry_run, args.skip_bootstrap)
    except (CredentialError, ConfigError) as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return EXIT_CONFIG_ERROR


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
