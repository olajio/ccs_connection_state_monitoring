#!/usr/bin/env python3
"""
setup_alerting.py — create the Kibana data view and alerting rules (Phase 3).

Covers CCS-15 (critical tier), CCS-16 (warning tier), CCS-17 (SMTP connector with
templated messages naming the failing remote), CCS-18 (recovery action group) and
CCS-19 (staleness / dead-collector rule).

The rule bodies live in `alerting/rules/*.json` as templates: `{{placeholders}}`
are substituted here before the JSON is parsed, which is why those files are not
directly loadable as JSON.

Anti-flap sizing (plan risk #1): the alert window must be wider than the probe
interval. Pass --probe-interval-minutes and the window defaults to 3x it, with
the staleness window at 3x the alert window.

Usage:
    # See what would be created, without touching Kibana:
    python3 alerting/setup_alerting.py --kibana-url https://kibana.example.com \
        --probe-interval-minutes 5 --dry-run

    # List the available connectors to find the SMTP one:
    python3 alerting/setup_alerting.py --kibana-url https://kibana.example.com \
        --kibana-user olajide --list-connectors

    # Create everything in the 'observability' space:
    python3 alerting/setup_alerting.py --kibana-url https://kibana.example.com \
        --space observability --kibana-user olajide \
        --connector-name "ITSMA SMTP" --to elk-oncall@example.gov \
        --probe-interval-minutes 5

    python3 alerting/setup_alerting.py --kibana-url ... --list-rules
    python3 alerting/setup_alerting.py --kibana-url ... --delete
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from typing import Any, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ccs_monitor.config import ConfigError, load_config  # noqa: E402
from ccs_monitor.credentials import build_auth_header  # noqa: E402
from ccs_monitor.http import HttpError, build_session, request_json  # noqa: E402
from ccs_monitor.logging_setup import configure_logging  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(HERE, "rules")

CORE_RULES = ["critical.json", "warning.json", "staleness.json"]
INFO_RULES = ["unmonitored.json"]

# Action group ids for the .es-query rule type.
ACTIVE_ACTION_GROUP = "query matched"
RECOVERY_ACTION_GROUP = "recovered"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG_ERROR = 2


# --------------------------------------------------------------------------- #
# Kibana client
# --------------------------------------------------------------------------- #

class Kibana:
    """Thin Kibana API client. Every request carries the required kbn-xsrf header."""

    def __init__(self, base_url: str, auth_header: str, space: Optional[str] = None,
                 verify: Any = True, timeout: float = 30.0):
        self.base_url = base_url.rstrip("/")
        self.space = space
        self.verify = verify
        self.timeout = timeout
        self.session = build_session(
            auth_header=auth_header,
            retries=2,
            backoff=0.5,
            extra_headers={"kbn-xsrf": "ccs-health-monitor"},
        )

    @property
    def root(self) -> str:
        """Space-aware base path — rules and data views are space-scoped objects."""
        if self.space and self.space != "default":
            return f"{self.base_url}/s/{self.space}"
        return self.base_url

    def call(self, method: str, path: str, payload: Any = None,
             expected: tuple = (200, 201), allow: tuple = ()) -> Dict[str, Any]:
        return request_json(
            self.session, method, f"{self.root}{path}",
            verify=self.verify, timeout=self.timeout, payload=payload,
            expected_statuses=expected, allow_statuses=allow,
        )

    def close(self) -> None:
        self.session.close()


# --------------------------------------------------------------------------- #
# Rule rendering
# --------------------------------------------------------------------------- #

def render_rule(filename: str, substitutions: Dict[str, Any]) -> Dict[str, Any]:
    """Substitute {{placeholders}} in a rule template, then parse it as JSON.

    Only the placeholders listed in `substitutions` are replaced; Mustache
    variables meant for Kibana ({{context.group}}, {{rule.name}}, ...) are left
    untouched because they never appear as substitution keys.
    """
    path = os.path.join(RULES_DIR, filename)
    with open(path, "r", encoding="utf-8") as handle:
        raw = handle.read()

    for key, value in substitutions.items():
        raw = raw.replace("{{" + key + "}}", str(value))

    try:
        rule = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"{path}: template did not render to valid JSON ({exc}). "
            f"An unsubstituted placeholder in a numeric position is the usual cause."
        )
    rule.pop("_comment", None)
    return rule


def build_actions(rule: Dict[str, Any], connector_id: str, recipients: List[str],
                  legacy_notify: bool) -> List[Dict[str, Any]]:
    """Active + recovery email actions (CCS-17, CCS-18).

    The recovery action is what makes alerts auto-resolve instead of needing a
    human to close them.
    """
    def email_params(subject_key: str, message_key: str) -> Dict[str, Any]:
        return {
            "to": recipients,
            "subject": rule[subject_key],
            "message": rule[message_key],
        }

    frequency = {"notify_when": "onActionGroupChange", "throttle": None, "summary": False}

    actions = [
        {
            "group": ACTIVE_ACTION_GROUP,
            "id": connector_id,
            "params": email_params("action_subject", "action_message"),
        },
        {
            "group": RECOVERY_ACTION_GROUP,
            "id": connector_id,
            "params": email_params("recovery_subject", "recovery_message"),
        },
    ]
    if not legacy_notify:
        # Kibana >= 8.6 puts notification frequency on each action.
        for action in actions:
            action["frequency"] = dict(frequency)
    return actions


def build_rule_body(rule: Dict[str, Any], connector_id: Optional[str],
                    recipients: List[str], legacy_notify: bool) -> Dict[str, Any]:
    body: Dict[str, Any] = {
        "name": rule["name"],
        "rule_type_id": rule["rule_type_id"],
        "consumer": rule["consumer"],
        "enabled": rule.get("enabled", True),
        "tags": rule.get("tags", []),
        "schedule": rule["schedule"],
        "params": rule["params"],
        "actions": (
            build_actions(rule, connector_id, recipients, legacy_notify) if connector_id else []
        ),
    }
    if legacy_notify:
        # Kibana < 8.6 takes notify_when/throttle at the top level instead.
        body["notify_when"] = "onActionGroupChange"
        body["throttle"] = None
    return body


# --------------------------------------------------------------------------- #
# Operations
# --------------------------------------------------------------------------- #

def ensure_data_view(kibana: Kibana, index: str, dry_run: bool) -> None:
    """Create the data view the rules and Discover use, if it is not there yet."""
    payload = {
        "data_view": {
            "title": index,
            "name": "CCS Health Monitor",
            "timeFieldName": "@timestamp",
            "allowNoIndex": True,
        },
        "override": False,
    }
    if dry_run:
        print(f"\n--- POST {kibana.root}/api/data_views/data_view")
        print(json.dumps(payload, indent=2))
        return

    try:
        existing = kibana.call("GET", "/api/data_views", expected=(200,))
        for data_view in existing.get("data_view", []):
            if data_view.get("title") == index:
                print(f"  SKIPPED  data view '{index}' (already exists, id={data_view.get('id')})")
                return
    except HttpError as exc:
        print(f"  WARNING  could not list data views ({exc}); attempting to create anyway")

    try:
        response = kibana.call("POST", "/api/data_views/data_view", payload)
        print(f"  OK       data view '{index}' (id={response.get('data_view', {}).get('id')})")
    except HttpError as exc:
        print(f"  FAILED   data view '{index}'\n           {exc}")


def list_connectors(kibana: Kibana) -> List[Dict[str, Any]]:
    return kibana.call("GET", "/api/actions/connectors", expected=(200,))  # type: ignore[return-value]


def resolve_connector(kibana: Kibana, connector_id: Optional[str],
                      connector_name: Optional[str]) -> Optional[str]:
    """Find the connector id to attach to every rule."""
    if connector_id:
        return connector_id
    if not connector_name:
        return None
    try:
        connectors = list_connectors(kibana)
    except HttpError as exc:
        raise SystemExit(f"Could not list Kibana connectors: {exc}")

    matches = [c for c in connectors if c.get("name") == connector_name]
    if not matches:
        available = ", ".join(f"{c.get('name')} ({c.get('connector_type_id')})" for c in connectors)
        raise SystemExit(
            f"No connector named '{connector_name}'. Available: {available or '(none)'}"
        )
    if len(matches) > 1:
        ids = ", ".join(c.get("id", "?") for c in matches)
        raise SystemExit(f"Several connectors are named '{connector_name}' — pass --connector-id ({ids})")
    return matches[0]["id"]


def create_rules(kibana: Kibana, rule_files: List[str], substitutions: Dict[str, Any],
                 connector_id: Optional[str], recipients: List[str],
                 legacy_notify: bool, dry_run: bool) -> int:
    failures = 0
    for filename in rule_files:
        rule = render_rule(filename, substitutions)
        rule_id = rule["rule_id"]
        body = build_rule_body(rule, connector_id, recipients, legacy_notify)

        if dry_run:
            print(f"\n--- POST {kibana.root}/api/alerting/rule/{rule_id}")
            print(json.dumps(body, indent=2))
            continue

        try:
            # A deterministic rule id makes this idempotent: 409 means it exists.
            kibana.call("POST", f"/api/alerting/rule/{rule_id}", body, expected=(200,))
            print(f"  OK       rule '{rule['name']}' (id={rule_id})")
            continue
        except HttpError as exc:
            if exc.status_code != 409:
                failures += 1
                print(f"  FAILED   rule '{rule['name']}'\n           {exc}")
                continue

        # Already present: update the mutable subset of the rule.
        update = {
            "name": body["name"],
            "tags": body["tags"],
            "schedule": body["schedule"],
            "params": body["params"],
            "actions": body["actions"],
        }
        if legacy_notify:
            update["notify_when"] = body["notify_when"]
            update["throttle"] = body["throttle"]
        try:
            kibana.call("PUT", f"/api/alerting/rule/{rule_id}", update, expected=(200,))
            print(f"  UPDATED  rule '{rule['name']}' (id={rule_id})")
        except HttpError as exc:
            failures += 1
            print(f"  FAILED   updating rule '{rule['name']}'\n           {exc}")
    return failures


def delete_rules(kibana: Kibana, rule_files: List[str], substitutions: Dict[str, Any]) -> int:
    failures = 0
    for filename in rule_files:
        rule = render_rule(filename, substitutions)
        rule_id = rule["rule_id"]
        try:
            result = kibana.call(
                "DELETE", f"/api/alerting/rule/{rule_id}", expected=(200, 204), allow=(404,)
            )
            if result.get("_allowed"):
                print(f"  SKIPPED  rule {rule_id} (not present)")
            else:
                print(f"  DELETED  rule {rule_id}")
        except HttpError as exc:
            failures += 1
            print(f"  FAILED   deleting {rule_id}: {exc}")
    return failures


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_auth(args: argparse.Namespace) -> str:
    if args.kibana_api_key:
        return build_auth_header({"api_key": args.kibana_api_key}, "--kibana-api-key")
    if args.kibana_user:
        password = args.kibana_password or os.environ.get("CCS_KIBANA_PASSWORD")
        if not password:
            password = getpass.getpass(f"Kibana password for {args.kibana_user}: ")
        return build_auth_header(
            {"username": args.kibana_user, "password": password}, "--kibana-user"
        )
    raise SystemExit("Provide --kibana-user or --kibana-api-key.")


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Create the Kibana data view and CCS connection-state alerting rules."
    )
    target = parser.add_argument_group("kibana")
    target.add_argument("--kibana-url", required=True, help="Kibana base URL.")
    target.add_argument("--space", default="default",
                        help="Kibana space that hosts the rules and data view (Phase-0 decision #5).")
    target.add_argument("--kibana-user", help="Kibana username (prompts for the password).")
    target.add_argument("--kibana-password", help="Kibana password. Prefer CCS_KIBANA_PASSWORD.")
    target.add_argument("--kibana-api-key", help="Kibana API key (base64 id:api_key).")
    target.add_argument("--ca-cert", help="CA bundle for TLS verification.")
    target.add_argument("--insecure", action="store_true",
                        help="Disable TLS verification. Not for FedRAMP environments.")

    rules = parser.add_argument_group("rules")
    rules.add_argument("-c", "--clusters", default="es_clusters.json",
                       help="Inventory file, read for the state-store index name.")
    rules.add_argument("--index", help="Override the state-store index name.")
    rules.add_argument("--probe-interval-minutes", type=int, default=5,
                       help="How often the collector runs. Windows are sized from it (default: %(default)s).")
    rules.add_argument("--window-multiplier", type=int, default=3,
                       help="Alert window = interval x this, to absorb cron jitter (default: %(default)s).")
    rules.add_argument("--staleness-multiplier", type=int, default=3,
                       help="Staleness window = alert window x this (default: %(default)s).")
    rules.add_argument("--rule-interval", default=None,
                       help="How often the rules run, e.g. '1m'. Default: the probe interval.")
    rules.add_argument("--include-info", action="store_true",
                       help="Also create the informational unmonitored-remote rule.")

    actions = parser.add_argument_group("actions and connector")
    actions.add_argument("--connector-id", help="Kibana connector id to notify.")
    actions.add_argument("--connector-name", help="Kibana connector name, resolved to its id.")
    actions.add_argument("--to", action="append", default=[], metavar="EMAIL",
                         help="Recipient address (repeatable). Phase-0 decision #6.")
    actions.add_argument("--legacy-notify", action="store_true",
                         help="Kibana < 8.6: send notify_when at the rule level, not per action.")

    modes = parser.add_argument_group("modes")
    modes.add_argument("--dry-run", action="store_true", help="Print the requests, send nothing.")
    modes.add_argument("--list-connectors", action="store_true", help="List Kibana connectors and exit.")
    modes.add_argument("--list-rules", action="store_true", help="List this project's rules and exit.")
    modes.add_argument("--delete", action="store_true", help="Delete this project's rules and exit.")
    modes.add_argument("--skip-data-view", action="store_true", help="Do not create the data view.")
    parser.add_argument("--log-level", default="WARNING", choices=("DEBUG", "INFO", "WARNING", "ERROR"))

    args = parser.parse_args(argv)
    configure_logging(level=args.log_level)

    index = args.index
    if not index:
        try:
            index = load_config(args.clusters).state_store.index
        except ConfigError as exc:
            sys.stderr.write(f"Configuration error: {exc}\nPass --index to skip reading the inventory.\n")
            return EXIT_CONFIG_ERROR

    window = max(1, args.probe_interval_minutes * args.window_multiplier)
    substitutions = {
        "index": index,
        "rule_interval": args.rule_interval or f"{max(1, args.probe_interval_minutes)}m",
        "time_window_size": window,
        "time_window_unit": "m",
        "staleness_window_size": max(1, window * args.staleness_multiplier),
        "staleness_window_unit": "m",
    }

    rule_files = list(CORE_RULES) + (INFO_RULES if args.include_info else [])

    if args.dry_run:
        print(f"Kibana:  {args.kibana_url} (space: {args.space})")
        print(f"Index:   {index}")
        print(f"Windows: alert={window}m  staleness={substitutions['staleness_window_size']}m  "
              f"rule interval={substitutions['rule_interval']}")
        kibana = type("DryKibana", (), {"root": f"{args.kibana_url.rstrip('/')}"
                                                f"{'/s/' + args.space if args.space != 'default' else ''}"})()
        if not args.skip_data_view:
            ensure_data_view(kibana, index, dry_run=True)  # type: ignore[arg-type]
        create_rules(kibana, rule_files, substitutions,  # type: ignore[arg-type]
                     args.connector_id or "<CONNECTOR_ID>", args.to or ["<RECIPIENT>"],
                     args.legacy_notify, dry_run=True)
        print("\nDry run: nothing was sent to Kibana.")
        return EXIT_OK

    kibana = Kibana(
        base_url=args.kibana_url,
        auth_header=build_auth(args),
        space=args.space,
        verify=args.ca_cert or (not args.insecure),
    )

    try:
        if args.list_connectors:
            for connector in list_connectors(kibana):
                print(f"  {connector.get('id')}  {connector.get('name')!r}  "
                      f"type={connector.get('connector_type_id')}")
            return EXIT_OK

        if args.list_rules:
            found = kibana.call(
                "GET", "/api/alerting/rules/_find?search=ccs&search_fields=tags&per_page=50",
                expected=(200,),
            )
            for rule in found.get("data", []):
                print(f"  {rule.get('id')}  {rule.get('name')!r}  enabled={rule.get('enabled')} "
                      f"status={rule.get('execution_status', {}).get('status')}")
            return EXIT_OK

        if args.delete:
            return EXIT_FAILED if delete_rules(kibana, rule_files, substitutions) else EXIT_OK

        connector_id = resolve_connector(kibana, args.connector_id, args.connector_name)
        if connector_id and not args.to:
            raise SystemExit("A connector was given but no --to recipient. Add at least one --to address.")
        if not connector_id:
            print("No connector given — creating the rules without notification actions.\n"
                  "Re-run with --connector-name/--connector-id and --to once the SMTP connector is chosen.\n")

        print(f"Kibana:  {kibana.root}")
        print(f"Index:   {index}")
        print(f"Windows: alert={window}m  staleness={substitutions['staleness_window_size']}m  "
              f"rule interval={substitutions['rule_interval']}\n")

        if not args.skip_data_view:
            ensure_data_view(kibana, index, dry_run=False)

        failures = create_rules(
            kibana, rule_files, substitutions, connector_id, args.to, args.legacy_notify, dry_run=False
        )
        print()
        if failures:
            print(f"{failures} rule(s) failed.")
            return EXIT_FAILED
        print("Rules created. Validate with an induced non-prod failure — see docs/HOWTO.md, step 8.")
        return EXIT_OK
    finally:
        kibana.close()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
