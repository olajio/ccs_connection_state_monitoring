"""Load and validate `es_clusters.json` into typed configuration objects.

The file carries four things:

  defaults      run-wide HTTP + severity policy defaults
  credentials   which credential provider to use and how to address it
  state_store   where verdicts are written (the `ccs-health-monitor` index)
  clusters[]    the local-cluster inventory and per-remote Phase-0 baselines

Validation is strict and every error message names the offending path, because a
silently mis-parsed baseline turns into a silently wrong verdict.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union

from .severity import merge_policies, validate_policy, PolicyError

#: Default state-store index. Deliberately NOT dot-prefixed: a visible index is
#: simpler to grant, to build a data view on, and to inspect in Discover.
DEFAULT_INDEX = "ccs-health-monitor"
DEFAULT_ILM_POLICY = "ccs-health-monitor-policy"
DEFAULT_INDEX_TEMPLATE = "ccs-health-monitor"
DEFAULT_RETENTION = "90d"

DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_RETRIES = 2
DEFAULT_RETRY_BACKOFF = 0.5

VALID_STATE_STORE_MODES = ("data_stream", "index")
VALID_LIFECYCLE = ("dsl", "ilm", "none")
VALID_PROVIDERS = ("file", "aws_secrets_manager", "env")


class ConfigError(ValueError):
    """Raised for any malformed or inconsistent configuration."""


# --------------------------------------------------------------------------- #
# Typed config objects
# --------------------------------------------------------------------------- #

@dataclass
class RemoteBaseline:
    """Phase-0 expectations for a single remote on a single local cluster."""

    name: str
    expected_nodes: Optional[int] = None
    expected_mode: Optional[str] = None
    expected_skip_unavailable: Optional[bool] = None
    expected_initial_connect_timeout: Optional[str] = None
    description: Optional[str] = None
    policy: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ClusterConfig:
    """One LOCAL Elasticsearch cluster that is probed for its remotes."""

    name: str
    base_url: str
    environment: str
    verify: Union[bool, str] = True
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    retries: int = DEFAULT_RETRIES
    retry_backoff: float = DEFAULT_RETRY_BACKOFF
    credentials_key: Optional[str] = None
    expected_remotes: Dict[str, RemoteBaseline] = field(default_factory=dict)
    policy: Dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    @property
    def credential_name(self) -> str:
        return self.credentials_key or self.name

    def policy_for(self, remote: Optional[RemoteBaseline]) -> Dict[str, Any]:
        """Effective policy for a remote on this cluster (defaults<cluster<remote)."""
        return merge_policies(self.policy, remote.policy if remote else {})


@dataclass
class StateStoreConfig:
    """Where verdict documents are written (Phase 2)."""

    enabled: bool = True
    mode: str = "data_stream"
    lifecycle: str = "dsl"
    index: str = DEFAULT_INDEX
    index_template: str = DEFAULT_INDEX_TEMPLATE
    ilm_policy: str = DEFAULT_ILM_POLICY
    retention: str = DEFAULT_RETENTION
    number_of_shards: int = 1
    number_of_replicas: int = 1
    rollover_max_age: str = "30d"
    rollover_max_primary_shard_size: str = "10gb"
    cluster: Optional[str] = None
    base_url: Optional[str] = None
    verify: Union[bool, str] = True
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    retries: int = DEFAULT_RETRIES
    retry_backoff: float = DEFAULT_RETRY_BACKOFF
    credentials_key: Optional[str] = None
    write_run_document: bool = True

    @property
    def credential_name(self) -> str:
        return self.credentials_key or self.cluster or "state_store"

    @property
    def bootstrap_index(self) -> str:
        """First backing index when running in alias-rollover ('index') mode."""
        return f"{self.index}-000001"


@dataclass
class CredentialsConfig:
    """How the collector obtains cluster credentials."""

    provider: str = "file"
    path: str = "credentials.json"
    secret_id: Optional[str] = None
    secret_id_template: Optional[str] = None
    region: Optional[str] = None
    profile: Optional[str] = None
    env_prefix: str = "CCS_API_KEY_"


@dataclass
class AppConfig:
    clusters: List[ClusterConfig]
    state_store: StateStoreConfig
    credentials: CredentialsConfig
    defaults: Dict[str, Any]
    source_path: Optional[str] = None

    def cluster(self, name: str) -> Optional[ClusterConfig]:
        for cluster in self.clusters:
            if cluster.name == name:
                return cluster
        return None

    @property
    def enabled_clusters(self) -> List[ClusterConfig]:
        return [c for c in self.clusters if c.enabled]


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #

def _opt_int(raw: Dict[str, Any], key: str, where: str) -> Optional[int]:
    value = raw.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ConfigError(f"{where}.{key}: expected a non-negative integer, got {value!r}")
    return value


def _opt_str(raw: Dict[str, Any], key: str, where: str) -> Optional[str]:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{where}.{key}: expected a non-empty string, got {value!r}")
    return value


def _opt_bool(raw: Dict[str, Any], key: str, where: str) -> Optional[bool]:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ConfigError(f"{where}.{key}: expected true or false, got {value!r}")
    return value


def _num(raw: Dict[str, Any], key: str, default: float, where: str) -> float:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ConfigError(f"{where}.{key}: expected a positive number, got {value!r}")
    return float(value)


def resolve_verify(raw: Dict[str, Any], where: str) -> Union[bool, str]:
    """Turn `verify_certs` / `ca_cert` into the value requests' `verify=` wants.

    A CA bundle path wins over the boolean: FedRAMP deployments pin the agency
    CA rather than trusting the ambient trust store.
    """
    ca_cert = raw.get("ca_cert")
    verify_certs = raw.get("verify_certs", True)

    if ca_cert is not None:
        if not isinstance(ca_cert, str) or not ca_cert.strip():
            raise ConfigError(f"{where}.ca_cert: expected a path string or null, got {ca_cert!r}")
        if verify_certs is False:
            raise ConfigError(
                f"{where}: ca_cert is set but verify_certs is false — refusing to "
                f"silently ignore the CA bundle. Set verify_certs to true."
            )
        return ca_cert

    if not isinstance(verify_certs, bool):
        raise ConfigError(f"{where}.verify_certs: expected true or false, got {verify_certs!r}")
    return verify_certs


def _parse_policy(raw: Dict[str, Any], where: str) -> Dict[str, Any]:
    policy = raw.get("severity_policy") or {}
    try:
        validate_policy(policy, where)
    except PolicyError as exc:
        raise ConfigError(str(exc)) from exc
    return {k: v for k, v in policy.items() if not k.startswith("_")}


def _parse_remote(name: str, raw: Any, where: str) -> RemoteBaseline:
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: expected an object of baseline values, got {type(raw).__name__}")

    unknown = set(raw) - {
        "expected_nodes",
        "expected_mode",
        "expected_skip_unavailable",
        "expected_initial_connect_timeout",
        "description",
        "severity_policy",
        "_comment",
    }
    if unknown:
        raise ConfigError(f"{where}: unknown key(s): {', '.join(sorted(unknown))}")

    mode = _opt_str(raw, "expected_mode", where)
    if mode is not None and mode not in ("sniff", "proxy"):
        raise ConfigError(f"{where}.expected_mode: expected 'sniff' or 'proxy', got {mode!r}")

    return RemoteBaseline(
        name=name,
        expected_nodes=_opt_int(raw, "expected_nodes", where),
        expected_mode=mode,
        expected_skip_unavailable=_opt_bool(raw, "expected_skip_unavailable", where),
        expected_initial_connect_timeout=_opt_str(raw, "expected_initial_connect_timeout", where),
        description=_opt_str(raw, "description", where),
        policy=_parse_policy(raw, where),
    )


def _parse_cluster(raw: Any, index: int, defaults: Dict[str, Any]) -> ClusterConfig:
    where = f"clusters[{index}]"
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: expected an object, got {type(raw).__name__}")

    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise ConfigError(f"{where}.name: expected a non-empty string, got {name!r}")
    where = f"clusters[{index}] ('{name}')"

    base_url = raw.get("base_url")
    if not isinstance(base_url, str) or not base_url.startswith(("http://", "https://")):
        raise ConfigError(f"{where}.base_url: expected an http(s) URL, got {base_url!r}")

    expected_remotes_raw = raw.get("expected_remotes") or {}
    if not isinstance(expected_remotes_raw, dict):
        raise ConfigError(f"{where}.expected_remotes: expected an object keyed by remote name")

    remotes: Dict[str, RemoteBaseline] = {}
    for remote_name, remote_raw in expected_remotes_raw.items():
        if remote_name.startswith("_"):
            continue  # allow "_comment" style annotations
        remotes[remote_name] = _parse_remote(
            remote_name, remote_raw, f"{where}.expected_remotes.{remote_name}"
        )

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigError(f"{where}.enabled: expected true or false, got {enabled!r}")

    return ClusterConfig(
        name=name,
        base_url=base_url.rstrip("/"),
        environment=_opt_str(raw, "environment", where) or name,
        verify=resolve_verify(raw, where),
        timeout=_num(raw, "timeout_seconds", defaults.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS), where),
        retries=int(raw.get("retries", defaults.get("retries", DEFAULT_RETRIES))),
        retry_backoff=float(raw.get("retry_backoff_seconds", defaults.get("retry_backoff_seconds", DEFAULT_RETRY_BACKOFF))),
        credentials_key=_opt_str(raw, "credentials_key", where),
        expected_remotes=remotes,
        policy=merge_policies(defaults.get("severity_policy") or {}, _parse_policy(raw, where)),
        enabled=enabled,
    )


def _parse_state_store(raw: Any, defaults: Dict[str, Any]) -> StateStoreConfig:
    where = "state_store"
    if raw is None:
        return StateStoreConfig()
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: expected an object, got {type(raw).__name__}")

    mode = raw.get("mode", "data_stream")
    if mode not in VALID_STATE_STORE_MODES:
        raise ConfigError(f"{where}.mode: expected one of {VALID_STATE_STORE_MODES}, got {mode!r}")

    lifecycle = raw.get("lifecycle", "dsl")
    if lifecycle not in VALID_LIFECYCLE:
        raise ConfigError(f"{where}.lifecycle: expected one of {VALID_LIFECYCLE}, got {lifecycle!r}")
    if mode == "index" and lifecycle == "dsl":
        raise ConfigError(
            f"{where}: lifecycle 'dsl' (data-stream lifecycle) only applies to "
            f"mode 'data_stream'. Use lifecycle 'ilm' with mode 'index'."
        )

    index = raw.get("index", DEFAULT_INDEX)
    if not isinstance(index, str) or not index.strip():
        raise ConfigError(f"{where}.index: expected a non-empty string, got {index!r}")
    if index.startswith("."):
        raise ConfigError(
            f"{where}.index: {index!r} is a dot-prefixed (hidden) index name. This project "
            f"deliberately uses a visible index — use '{index.lstrip('.')}' instead."
        )

    enabled = raw.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigError(f"{where}.enabled: expected true or false, got {enabled!r}")

    write_run_document = raw.get("write_run_document", True)
    if not isinstance(write_run_document, bool):
        raise ConfigError(f"{where}.write_run_document: expected true or false")

    return StateStoreConfig(
        enabled=enabled,
        mode=mode,
        lifecycle=lifecycle,
        index=index,
        index_template=_opt_str(raw, "index_template", where) or index,
        ilm_policy=_opt_str(raw, "ilm_policy", where) or f"{index}-policy",
        retention=_opt_str(raw, "retention", where) or DEFAULT_RETENTION,
        number_of_shards=_opt_int(raw, "number_of_shards", where) or 1,
        number_of_replicas=(
            0 if raw.get("number_of_replicas") == 0 else (_opt_int(raw, "number_of_replicas", where) or 1)
        ),
        rollover_max_age=_opt_str(raw, "rollover_max_age", where) or "30d",
        rollover_max_primary_shard_size=_opt_str(raw, "rollover_max_primary_shard_size", where) or "10gb",
        cluster=_opt_str(raw, "cluster", where),
        base_url=(_opt_str(raw, "base_url", where) or "").rstrip("/") or None,
        verify=resolve_verify(raw, where),
        timeout=_num(raw, "timeout_seconds", defaults.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS), where),
        retries=int(raw.get("retries", defaults.get("retries", DEFAULT_RETRIES))),
        retry_backoff=float(raw.get("retry_backoff_seconds", defaults.get("retry_backoff_seconds", DEFAULT_RETRY_BACKOFF))),
        credentials_key=_opt_str(raw, "credentials_key", where),
        write_run_document=write_run_document,
    )


def _parse_credentials(raw: Any) -> CredentialsConfig:
    where = "credentials"
    if raw is None:
        return CredentialsConfig()
    if not isinstance(raw, dict):
        raise ConfigError(f"{where}: expected an object, got {type(raw).__name__}")

    provider = raw.get("provider", "file")
    if provider not in VALID_PROVIDERS:
        raise ConfigError(f"{where}.provider: expected one of {VALID_PROVIDERS}, got {provider!r}")

    cfg = CredentialsConfig(
        provider=provider,
        path=_opt_str(raw, "path", where) or "credentials.json",
        secret_id=_opt_str(raw, "secret_id", where),
        secret_id_template=_opt_str(raw, "secret_id_template", where),
        region=_opt_str(raw, "region", where),
        profile=_opt_str(raw, "profile", where),
        env_prefix=_opt_str(raw, "env_prefix", where) or "CCS_API_KEY_",
    )

    if provider == "aws_secrets_manager" and not (cfg.secret_id or cfg.secret_id_template):
        raise ConfigError(
            f"{where}: provider 'aws_secrets_manager' needs either 'secret_id' (one secret "
            f"holding all clusters) or 'secret_id_template' (e.g. 'ccs/es/{{cluster}}')."
        )
    if cfg.secret_id_template and "{cluster}" not in cfg.secret_id_template:
        raise ConfigError(f"{where}.secret_id_template: must contain the '{{cluster}}' placeholder")
    return cfg


# --------------------------------------------------------------------------- #
# Entry points
# --------------------------------------------------------------------------- #

def load_config(path: str) -> AppConfig:
    """Read and validate a cluster inventory file."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except FileNotFoundError as exc:
        raise ConfigError(f"Cluster inventory not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path} is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"Cannot read {path}: {exc}") from exc

    config = parse_config(raw)
    config.source_path = path

    # Relative credential/CA paths are resolved against the inventory file so a
    # cron job with a different working directory still finds them.
    base_dir = os.path.dirname(os.path.abspath(path))
    if config.credentials.provider == "file" and not os.path.isabs(config.credentials.path):
        candidate = os.path.join(base_dir, config.credentials.path)
        if os.path.exists(candidate) or not os.path.exists(config.credentials.path):
            config.credentials.path = candidate
    return config


def parse_config(raw: Any) -> AppConfig:
    """Validate an already-parsed inventory document."""
    if not isinstance(raw, dict):
        raise ConfigError(f"Top level: expected an object, got {type(raw).__name__}")

    defaults = raw.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise ConfigError("defaults: expected an object")
    try:
        validate_policy(defaults.get("severity_policy") or {}, "defaults")
    except PolicyError as exc:
        raise ConfigError(str(exc)) from exc

    clusters_raw = raw.get("clusters")
    if not isinstance(clusters_raw, list) or not clusters_raw:
        raise ConfigError("clusters: expected a non-empty array of local clusters")

    clusters = [_parse_cluster(c, i, defaults) for i, c in enumerate(clusters_raw)]

    seen: Dict[str, int] = {}
    for i, cluster in enumerate(clusters):
        if cluster.name in seen:
            raise ConfigError(
                f"clusters[{i}]: duplicate cluster name '{cluster.name}' "
                f"(already defined at clusters[{seen[cluster.name]}])"
            )
        seen[cluster.name] = i

    state_store = _parse_state_store(raw.get("state_store"), defaults)
    if state_store.enabled and not state_store.base_url:
        if not state_store.cluster:
            raise ConfigError(
                "state_store: set either 'cluster' (reuse a cluster from the inventory) "
                "or 'base_url' (a dedicated monitoring cluster)."
            )
        if state_store.cluster not in seen:
            raise ConfigError(
                f"state_store.cluster: '{state_store.cluster}' is not in the inventory "
                f"(known clusters: {', '.join(sorted(seen))})"
            )

    return AppConfig(
        clusters=clusters,
        state_store=state_store,
        credentials=_parse_credentials(raw.get("credentials")),
        defaults=defaults,
    )


def state_store_endpoint(config: AppConfig) -> Dict[str, Any]:
    """Resolve the state store's effective URL / TLS / timeout settings.

    When `state_store.cluster` names an inventory cluster, its base_url and TLS
    settings are inherited unless the state_store block overrides them.
    """
    store = config.state_store
    base_url = store.base_url
    verify: Union[bool, str] = store.verify
    credentials_key = store.credentials_key

    if store.cluster:
        parent = config.cluster(store.cluster)
        if parent is None:
            raise ConfigError(f"state_store.cluster: unknown cluster '{store.cluster}'")
        if not base_url:
            base_url = parent.base_url
        if store.verify is True:  # untouched default -> inherit the parent's
            verify = parent.verify
        if not credentials_key:
            credentials_key = parent.credential_name

    if not base_url:
        raise ConfigError("state_store: no base_url could be resolved")

    return {
        "base_url": base_url.rstrip("/"),
        "verify": verify,
        "timeout": store.timeout,
        "retries": store.retries,
        "retry_backoff": store.retry_backoff,
        "credentials_key": credentials_key or "state_store",
    }
