#!/usr/bin/env python3
"""
setup_security.py — least-privilege roles and API keys (CCS-9, CCS-14).

Creates two roles from `setup/roles/`:

  ccs_health_collector  cluster:monitor  + append-only on ccs-health-monitor
  ccs_health_alerting   cluster:monitor  + read-only  on ccs-health-monitor

and can mint a collector API key scoped to the collector role. The key is
printed once, in the exact base64 `id:api_key` form the collector wants — paste
it into credentials.json, or store it in Secrets Manager for Phase-1 hardening.

Run this with an ADMINISTRATIVE credential (a superuser or a user holding
manage_security); the collector's own key cannot create roles, by design.

Usage:
    python3 setup/setup_security.py --url https://ccs-es.example.com:9200 --dry-run
    python3 setup/setup_security.py --url https://ccs-es.example.com:9200 \
        --admin-user elastic --ca-cert /etc/pki/agency-ca.pem
    python3 setup/setup_security.py --url https://ccs-es.example.com:9200 \
        --admin-user elastic --create-api-key --key-name ccs-collector-prod
    # Read the index name straight out of the inventory instead of retyping it:
    python3 setup/setup_security.py --clusters es_clusters.json --cluster ccs --admin-user elastic
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
ROLES_DIR = os.path.join(HERE, "roles")

COLLECTOR_ROLE = "ccs_health_collector"
ALERTING_ROLE = "ccs_health_alerting"

ROLE_FILES = {
    COLLECTOR_ROLE: os.path.join(ROLES_DIR, "ccs_collector_role.json"),
    ALERTING_ROLE: os.path.join(ROLES_DIR, "ccs_alerting_role.json"),
}

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_CONFIG_ERROR = 2


def strip_comments(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: strip_comments(v) for k, v in value.items() if k != "_comment"}
    if isinstance(value, list):
        return [strip_comments(v) for v in value]
    return value


def load_role(path: str, index_name: str) -> Dict[str, Any]:
    """Load a role definition, retargeting it at the configured index name."""
    with open(path, "r", encoding="utf-8") as handle:
        role = strip_comments(json.load(handle))

    if index_name != "ccs-health-monitor":
        for entry in role.get("indices", []):
            entry["names"] = [
                name.replace("ccs-health-monitor", index_name) for name in entry["names"]
            ]
    return role


def build_admin_session(args: argparse.Namespace):
    """Build the administrative session used to create roles and keys."""
    if args.admin_api_key:
        auth = build_auth_header({"api_key": args.admin_api_key}, "--admin-api-key")
    elif args.admin_user:
        password = args.admin_password or os.environ.get("CCS_ADMIN_PASSWORD")
        if not password:
            password = getpass.getpass(f"Password for {args.admin_user}: ")
        auth = build_auth_header({"username": args.admin_user, "password": password}, "--admin-user")
    else:
        raise SystemExit("Provide --admin-user or --admin-api-key (an administrative credential).")
    return build_session(auth_header=auth, retries=2, backoff=0.5)


def resolve_target(args: argparse.Namespace) -> Dict[str, Any]:
    """Work out the Elasticsearch URL, TLS setting, and index name."""
    url: Optional[str] = args.url
    verify: Any = args.ca_cert or (not args.insecure)
    index_name = args.index

    if args.clusters:
        try:
            config = load_config(args.clusters)
        except ConfigError as exc:
            raise SystemExit(f"Configuration error: {exc}")
        index_name = index_name or config.state_store.index
        if not url:
            target = config.cluster(args.cluster) if args.cluster else None
            if target is None and config.state_store.cluster:
                target = config.cluster(config.state_store.cluster)
            if target is None:
                raise SystemExit(
                    "Could not resolve a cluster URL from the inventory — pass --url or --cluster."
                )
            url = target.base_url
            if not args.ca_cert and not args.insecure:
                verify = target.verify

    if not url:
        raise SystemExit("Provide --url (or --clusters with --cluster).")
    return {"url": url.rstrip("/"), "verify": verify, "index": index_name or "ccs-health-monitor"}


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Create least-privilege roles and API keys for CCS health monitoring."
    )
    target = parser.add_argument_group("target")
    target.add_argument("--url", help="Elasticsearch base URL.")
    target.add_argument("-c", "--clusters", help="Read the URL and index name from this inventory file.")
    target.add_argument("--cluster", help="Which inventory cluster to target (with --clusters).")
    target.add_argument("--index", help="State-store index name (default: from the inventory).")
    target.add_argument("--ca-cert", help="CA bundle for TLS verification.")
    target.add_argument("--insecure", action="store_true",
                        help="Disable TLS verification. Not for FedRAMP environments.")

    admin = parser.add_argument_group("administrative credential")
    admin.add_argument("--admin-user", help="Administrative username (prompts for the password).")
    admin.add_argument("--admin-password", help="Administrative password. Prefer CCS_ADMIN_PASSWORD.")
    admin.add_argument("--admin-api-key", help="Administrative API key (base64 id:api_key).")

    actions = parser.add_argument_group("actions")
    actions.add_argument("--roles-only", action="store_true", help="Create the roles and stop.")
    actions.add_argument("--create-api-key", action="store_true",
                         help="Also mint a collector API key bound to the collector role.")
    actions.add_argument("--key-name", default="ccs-health-collector", help="Name for the API key.")
    actions.add_argument("--key-expiration", default=None,
                         help="API key expiration, e.g. '90d'. Default: no expiration.")
    actions.add_argument("--dry-run", action="store_true", help="Print the requests, send nothing.")
    parser.add_argument("--log-level", default="WARNING", choices=("DEBUG", "INFO", "WARNING", "ERROR"))

    args = parser.parse_args(argv)
    configure_logging(level=args.log_level)

    resolved = resolve_target(args)
    url, verify, index_name = resolved["url"], resolved["verify"], resolved["index"]

    roles = {name: load_role(path, index_name) for name, path in ROLE_FILES.items()}

    if args.dry_run:
        for role_name, body in roles.items():
            print(f"\n--- PUT {url}/_security/role/{role_name}")
            print(json.dumps(body, indent=2))
        if args.create_api_key:
            print(f"\n--- POST {url}/_security/api_key")
            print(json.dumps(build_api_key_body(args), indent=2))
        print("\nDry run: nothing was sent to Elasticsearch.")
        return EXIT_OK

    session = build_admin_session(args)
    failures: List[str] = []
    print(f"Target: {url}   (state-store index: {index_name})\n")

    try:
        for role_name, body in roles.items():
            try:
                request_json(
                    session, "PUT", f"{url}/_security/role/{role_name}",
                    verify=verify, timeout=15.0, payload=body, expected_statuses=(200, 201),
                )
                print(f"  OK       role '{role_name}'")
            except HttpError as exc:
                failures.append(f"role '{role_name}': {exc}")
                print(f"  FAILED   role '{role_name}'\n           {exc}")

        if args.create_api_key and not args.roles_only:
            try:
                response = request_json(
                    session, "POST", f"{url}/_security/api_key",
                    verify=verify, timeout=15.0, payload=build_api_key_body(args),
                    expected_statuses=(200, 201),
                )
                print_api_key(response, args.key_name)
            except HttpError as exc:
                failures.append(f"api key: {exc}")
                print(f"  FAILED   API key '{args.key_name}'\n           {exc}")
    finally:
        session.close()

    print()
    if failures:
        print(f"{len(failures)} step(s) failed:")
        for failure in failures:
            print(f"  - {failure}")
        return EXIT_FAILED

    print("Done. Next: assign 'ccs_health_alerting' to the Kibana user that owns the rules (CCS-14).")
    return EXIT_OK


def build_api_key_body(args: argparse.Namespace) -> Dict[str, Any]:
    """An API key whose privileges are capped at the collector role."""
    body: Dict[str, Any] = {
        "name": args.key_name,
        # role_descriptors intersects with the creating user's privileges, so the
        # key can never be broader than the collector role even if the admin is a
        # superuser. This is the mechanism behind CCS-9.
        "role_descriptors": {COLLECTOR_ROLE: load_role(ROLE_FILES[COLLECTOR_ROLE], args.index or "ccs-health-monitor")},
        "metadata": {
            "project": "CCS Remote Connection-State Degradation Monitoring",
            "issue": "CCS-9",
        },
    }
    if args.key_expiration:
        body["expiration"] = args.key_expiration
    return body


def print_api_key(response: Dict[str, Any], key_name: str) -> None:
    """Print the key material once, in the form the collector consumes."""
    import base64

    encoded = response.get("encoded")
    if not encoded and response.get("id") and response.get("api_key"):
        encoded = base64.b64encode(
            f"{response['id']}:{response['api_key']}".encode("utf-8")
        ).decode("ascii")

    print(f"  OK       API key '{key_name}' created")
    print("\n" + "=" * 72)
    print(" Copy this value into credentials.json as the cluster's \"api_key\".")
    print(" It is shown ONCE and cannot be retrieved again.")
    print("=" * 72)
    print(f"  id      : {response.get('id')}")
    print(f"  api_key : {encoded}")
    print("=" * 72)
    print(" For Phase-1 hardening, store it in AWS Secrets Manager instead:")
    print("   aws secretsmanager create-secret --name ccs/es/api-keys \\")
    print(f"     --secret-string '{{\"<cluster>\": {{\"api_key\": \"{encoded}\"}}}}'")
    print()


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
