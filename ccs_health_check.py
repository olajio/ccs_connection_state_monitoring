#!/usr/bin/env python3
"""
ccs_health_check.py — CCS Remote Connection-State Degradation Monitoring collector.

Probes `GET /_remote/info` on every LOCAL Elasticsearch cluster in the inventory,
compares each remote against its Phase-0 baseline, and emits a severity verdict
per remote. Verdicts are printed and (unless --no-index) written to the
`ccs-health-monitor` state store, where the Kibana rules read them.

    HEALTHY   connected, pool at or above the baseline, no configuration drift
    WARNING   connected but partial pool, or mode / timeout / skip_unavailable drift
    CRITICAL  connected=false, pool below the critical floor, a baselined remote
              missing from _remote/info, or the local cluster is unreachable
    INFO      a remote present in _remote/info but absent from the baseline

Every remote and every cluster is evaluated in isolation: one failing remote or
one unreachable cluster never aborts the rest of the run.

Exit codes:
    0  all verdicts HEALTHY/INFO
    1  at least one verdict at or above --fail-on (default WARNING)
    2  configuration or usage error (nothing was probed)
    3  probing succeeded but writing to the state store failed

Examples:
    ./ccs_health_check.py
    ./ccs_health_check.py --no-index --format table          # Phase-1 dress rehearsal
    ./ccs_health_check.py --no-index --format ndjson         # exactly what would be indexed
    ./ccs_health_check.py --cluster prod --log-level DEBUG
    ./ccs_health_check.py --credentials-provider aws_secrets_manager \
        --secret-id ccs/es/api-keys --aws-region us-gov-east-1
    ./ccs_health_check.py --check-state-store
"""

from __future__ import annotations

import argparse
import logging
import sys
import time
from typing import List, Optional

from ccs_monitor import __version__
from ccs_monitor.config import AppConfig, ConfigError, load_config
from ccs_monitor.credentials import CredentialError, build_provider
from ccs_monitor.documents import build_documents, new_run_id, utc_now_iso
from ccs_monitor.evaluate import evaluate_cluster, overall_severity, severity_counts
from ccs_monitor.logging_setup import configure_logging
from ccs_monitor.probe import probe_cluster
from ccs_monitor.report import (
    build_json_report,
    print_json,
    print_ndjson,
    print_table,
    should_use_color,
)
from ccs_monitor.severity import SEVERITY_RANK
from ccs_monitor.sink import StateStoreWriter

LOG = logging.getLogger("ccs.collector")

EXIT_OK = 0
EXIT_DEGRADED = 1
EXIT_CONFIG_ERROR = 2
EXIT_SINK_ERROR = 3


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ccs_health_check.py",
        description="CCS remote connection-state health check.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exit codes: 0 healthy · 1 degraded · 2 config error · 3 state-store write failure"
        ),
    )
    parser.add_argument("--version", action="version", version=f"ccs-health-monitor {__version__}")

    source = parser.add_argument_group("inventory and credentials")
    source.add_argument("-c", "--clusters", default="es_clusters.json",
                        help="Cluster inventory / baseline file (default: %(default)s).")
    source.add_argument("--credentials", default=None,
                        help="Credentials file for the 'file' provider (overrides the inventory).")
    source.add_argument("--credentials-provider", choices=("file", "aws_secrets_manager", "env"),
                        default=None, help="Override the credential provider.")
    source.add_argument("--secret-id", default=None,
                        help="Secrets Manager secret holding every cluster's key.")
    source.add_argument("--secret-id-template", default=None,
                        help="Per-cluster secret id template, e.g. 'ccs/es/{cluster}'.")
    source.add_argument("--aws-region", default=None, help="AWS region for Secrets Manager.")
    source.add_argument("--aws-profile", default=None, help="AWS profile for Secrets Manager.")

    selection = parser.add_argument_group("selection")
    selection.add_argument("--cluster", action="append", dest="only_clusters", metavar="NAME",
                           help="Probe only this local cluster (repeatable).")
    selection.add_argument("--timeout", type=float, default=None,
                           help="Override the per-request timeout, in seconds.")

    output = parser.add_argument_group("output")
    output.add_argument("-f", "--format", choices=("table", "json", "ndjson"), default="table",
                        help="Report format (default: %(default)s).")
    output.add_argument("--no-color", action="store_true", help="Disable ANSI color.")
    output.add_argument("--problems-only", action="store_true",
                        help="Hide HEALTHY verdicts in the table report.")
    output.add_argument("--quiet", action="store_true",
                        help="Suppress log output on stderr (the report still prints).")
    output.add_argument("--log-level", default="INFO",
                        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"))
    output.add_argument("--log-file", default=None, help="Also write logs to this file.")
    output.add_argument("--log-format", choices=("text", "json"), default="text")

    store = parser.add_argument_group("state store")
    store.add_argument("--no-index", "--dry-run", dest="no_index", action="store_true",
                       help="Do not write to the state store (Phase-1 behaviour).")
    store.add_argument("--index", dest="force_index", action="store_true",
                       help="Force indexing even if state_store.enabled is false.")
    store.add_argument("--check-state-store", action="store_true",
                       help="Verify the state store exists and is reachable, then exit.")
    store.add_argument("--fail-on", choices=("WARNING", "CRITICAL", "never"), default="WARNING",
                       help="Lowest severity that produces exit code 1 (default: %(default)s).")

    misc = parser.add_argument_group("diagnostics")
    misc.add_argument("--show-config", action="store_true",
                      help="Print the resolved configuration and exit (no secrets shown).")

    return parser.parse_args(argv)


def apply_overrides(config: AppConfig, args: argparse.Namespace) -> AppConfig:
    """Apply CLI overrides onto the loaded configuration."""
    creds = config.credentials
    if args.credentials_provider:
        creds.provider = args.credentials_provider
    if args.credentials:
        creds.path = args.credentials
        if not args.credentials_provider:
            creds.provider = "file"
    if args.secret_id:
        creds.secret_id = args.secret_id
        if not args.credentials_provider:
            creds.provider = "aws_secrets_manager"
    if args.secret_id_template:
        creds.secret_id_template = args.secret_id_template
        if not args.credentials_provider:
            creds.provider = "aws_secrets_manager"
    if args.aws_region:
        creds.region = args.aws_region
    if args.aws_profile:
        creds.profile = args.aws_profile

    if creds.provider == "aws_secrets_manager" and not (creds.secret_id or creds.secret_id_template):
        raise ConfigError(
            "provider 'aws_secrets_manager' needs --secret-id or --secret-id-template "
            "(or the equivalent keys in the inventory's 'credentials' block)."
        )

    if args.timeout is not None:
        if args.timeout <= 0:
            raise ConfigError("--timeout must be greater than zero")
        for cluster in config.clusters:
            cluster.timeout = args.timeout
        config.state_store.timeout = args.timeout

    if args.only_clusters:
        known = {c.name for c in config.clusters}
        unknown = [name for name in args.only_clusters if name not in known]
        if unknown:
            raise ConfigError(
                f"--cluster: unknown cluster(s) {', '.join(unknown)}. "
                f"Known: {', '.join(sorted(known))}"
            )
        selected = set(args.only_clusters)
        for cluster in config.clusters:
            cluster.enabled = cluster.name in selected

    if args.force_index:
        config.state_store.enabled = True
    return config


def show_config(config: AppConfig) -> None:
    """Print the resolved configuration — never any secret material."""
    print(f"inventory:   {config.source_path}")
    print(f"credentials: provider={config.credentials.provider}")
    if config.credentials.provider == "file":
        print(f"             path={config.credentials.path}")
    elif config.credentials.provider == "aws_secrets_manager":
        print(f"             secret_id={config.credentials.secret_id}")
        print(f"             secret_id_template={config.credentials.secret_id_template}")
        print(f"             region={config.credentials.region} profile={config.credentials.profile}")
    else:
        print(f"             env_prefix={config.credentials.env_prefix}")

    store = config.state_store
    print(
        f"state store: enabled={store.enabled} index={store.index} mode={store.mode} "
        f"lifecycle={store.lifecycle} retention={store.retention}"
    )
    print(f"             target={store.cluster or store.base_url}")

    for cluster in config.clusters:
        flag = "" if cluster.enabled else "  (disabled)"
        print(f"\ncluster {cluster.name} [{cluster.environment}]{flag}")
        print(f"  url:     {cluster.base_url}")
        print(f"  verify:  {cluster.verify}   timeout={cluster.timeout}s retries={cluster.retries}")
        print(f"  creds:   key={cluster.credential_name}")
        if not cluster.expected_remotes:
            print("  remotes: (none baselined — every remote will report as unmonitored INFO)")
        for name, baseline in cluster.expected_remotes.items():
            policy = cluster.policy_for(baseline)
            print(
                f"  remote {name}: nodes={baseline.expected_nodes} mode={baseline.expected_mode} "
                f"skip_unavailable={baseline.expected_skip_unavailable} "
                f"timeout={baseline.expected_initial_connect_timeout}"
            )
            print(
                f"      policy: partial_pool={policy['partial_pool']} "
                f"critical_below_nodes={policy['critical_below_nodes']} "
                f"mode_drift={policy['mode_drift']} "
                f"escalate_when_skippable={policy['escalate_warning_when_skip_unavailable']}"
            )


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv if argv is not None else sys.argv[1:])
    configure_logging(
        level=args.log_level,
        log_file=args.log_file,
        log_format=args.log_format,
        quiet=args.quiet,
    )

    try:
        config = apply_overrides(load_config(args.clusters), args)
    except ConfigError as exc:
        LOG.error("configuration error: %s", exc)
        sys.stderr.write(f"Configuration error: {exc}\n")
        return EXIT_CONFIG_ERROR

    if args.show_config:
        show_config(config)
        return EXIT_OK

    try:
        provider = build_provider(config.credentials)
    except CredentialError as exc:
        LOG.error("credential provider error: %s", exc)
        sys.stderr.write(f"Credential error: {exc}\n")
        return EXIT_CONFIG_ERROR

    if args.check_state_store:
        return check_state_store(config, provider)

    clusters = config.enabled_clusters
    if not clusters:
        sys.stderr.write("No clusters selected — nothing to probe.\n")
        return EXIT_CONFIG_ERROR

    run_id = new_run_id()
    started = time.perf_counter()
    LOG.info("run_id=%s starting: %d local cluster(s)", run_id, len(clusters))

    # Isolation: probe + evaluate each cluster independently.
    cluster_verdicts = []
    for cluster in clusters:
        probe = probe_cluster(cluster, provider)
        cluster_verdicts.append(evaluate_cluster(cluster, probe))

    duration_ms = (time.perf_counter() - started) * 1000
    overall = overall_severity(cluster_verdicts)
    counts = severity_counts(cluster_verdicts)
    timestamp = utc_now_iso()

    # ---- report ---------------------------------------------------------- #
    if args.format == "table":
        print_table(
            cluster_verdicts,
            overall,
            run_id,
            timestamp,
            use_color=should_use_color(args.no_color),
            show_healthy=not args.problems_only,
        )
    elif args.format == "json":
        print_json(build_json_report(cluster_verdicts, overall, run_id, timestamp, duration_ms))
    else:
        print_ndjson(
            cluster_verdicts,
            run_id,
            overall,
            duration_ms,
            include_run_document=config.state_store.write_run_document,
        )

    # ---- state store ----------------------------------------------------- #
    sink_failed = False
    if config.state_store.enabled and not args.no_index:
        documents = build_documents(
            cluster_verdicts,
            run_id,
            include_run_document=config.state_store.write_run_document,
            overall=overall,
            counts=counts,
            duration_ms=duration_ms,
        )
        try:
            writer = StateStoreWriter(config, provider)
            result = writer.write(documents)
        except ConfigError as exc:
            LOG.error("state store misconfigured: %s", exc)
            sys.stderr.write(f"State store error: {exc}\n")
            return EXIT_CONFIG_ERROR

        if result.skipped:
            LOG.info("state store write skipped: %s", result.reason)
        elif not result.ok:
            sink_failed = True
            sys.stderr.write(
                f"State-store write failed: {result.failed}/{result.attempted} documents "
                f"rejected. First errors: {'; '.join(result.errors[:3])}\n"
            )
        else:
            LOG.info(
                "run_id=%s wrote %d document(s) to %s", run_id, result.indexed, config.state_store.index
            )
    elif args.no_index:
        LOG.info("run_id=%s --no-index: %d verdict(s) not written", run_id, sum(counts.values()))

    LOG.info(
        "run_id=%s finished overall=%s duration_ms=%.0f counts=%s",
        run_id, overall, duration_ms, counts,
    )

    # A write failure outranks a degraded verdict: if verdicts cannot land, the
    # alerting layer is blind and that is the more urgent problem.
    if sink_failed:
        return EXIT_SINK_ERROR
    if args.fail_on != "never" and SEVERITY_RANK[overall] >= SEVERITY_RANK[args.fail_on]:
        return EXIT_DEGRADED
    return EXIT_OK


def check_state_store(config: AppConfig, provider) -> int:
    """--check-state-store: confirm the verdict target exists and is reachable."""
    store = config.state_store
    if not store.enabled:
        print("state_store.enabled is false — nothing to check.")
        return EXIT_OK
    try:
        info = StateStoreWriter(config, provider).verify_target()
    except (ConfigError, CredentialError) as exc:
        sys.stderr.write(f"State store check failed: {exc}\n")
        return EXIT_CONFIG_ERROR
    except Exception as exc:  # noqa: BLE001 - HttpError and friends
        sys.stderr.write(f"State store check failed: {exc}\n")
        return EXIT_SINK_ERROR

    if info.get("exists"):
        print(f"OK: {info['kind']} '{info['name']}' exists and is reachable.")
        for key in ("backing_indices", "resolved", "lifecycle"):
            if info.get(key):
                print(f"    {key}: {info[key]}")
        return EXIT_OK

    print(
        f"MISSING: {info['kind']} '{info['name']}' does not exist.\n"
        f"Create it with:  python3 setup/setup_state_store.py --clusters {config.source_path}"
    )
    return EXIT_SINK_ERROR


if __name__ == "__main__":
    sys.exit(main())
