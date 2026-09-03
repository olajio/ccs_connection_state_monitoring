"""ccs_monitor — CCS Remote Connection-State Degradation Monitoring.

Shared library behind the collector (`ccs_health_check.py`), the state-store and
security bootstrap scripts (`setup/`), the Kibana alerting bootstrap
(`alerting/`), and the Phase-0 baseline tooling (`tools/`).

Module map
----------
config       Load + validate `es_clusters.json` into typed config objects.
credentials  Pluggable credential providers (file, AWS Secrets Manager, env).
severity     Severity vocabulary, ordering, and policy resolution.
http         requests.Session builder: TLS verification, timeouts, retries.
probe        `GET /_remote/info` against a local cluster.
evaluate     Baseline comparison -> per-remote / per-cluster verdicts.
documents    Verdict -> `ccs-health-monitor` document.
sink         Bulk writer for the `ccs-health-monitor` state store.
report       Human-readable and machine-readable output.
logging_setup Structured logging configuration.
"""

__version__ = "1.0.0"

APP_NAME = "ccs-health-monitor"

__all__ = ["__version__", "APP_NAME"]
