"""Credential providers for the collector.

Everything that touches a secret lives behind `CredentialProvider.get()`, so
Phase-1 hardening (CCS-8: file -> AWS Secrets Manager) is a provider swap and
nothing else in the codebase changes.

A credential entry is either:

    {"api_key":  "<base64 id:api_key>"}      preferred (CCS-9 least privilege)
    {"username": "...", "password": "..."}   basic auth fallback

Secrets are never logged; `__repr__` on the providers deliberately omits them.
"""

from __future__ import annotations

import base64
import json
import os
import stat
from typing import Any, Dict, Optional

from .config import CredentialsConfig


class CredentialError(RuntimeError):
    """Raised when a credential cannot be found or is malformed."""


def build_auth_header(entry: Dict[str, Any], where: str) -> str:
    """Turn a credential entry into an HTTP Authorization header value."""
    if not isinstance(entry, dict):
        raise CredentialError(f"{where}: expected an object with 'api_key' or 'username'/'password'")

    api_key = entry.get("api_key")
    if api_key:
        if not isinstance(api_key, str):
            raise CredentialError(f"{where}.api_key: expected a string")
        if api_key.startswith("REPLACE_WITH"):
            raise CredentialError(
                f"{where}.api_key is still the placeholder from credentials.example.json — "
                f"fill in the real base64 'id:api_key' value."
            )
        return f"ApiKey {api_key}"

    username, password = entry.get("username"), entry.get("password")
    if username and password is not None:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return f"Basic {token}"

    raise CredentialError(
        f"{where}: no usable credential — provide 'api_key', or 'username' + 'password'"
    )


class CredentialProvider:
    """Interface: map a cluster name to an Authorization header value."""

    name = "base"

    def get(self, cluster_name: str) -> str:  # pragma: no cover - interface
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"<{type(self).__name__} provider={self.name!r}>"


class FileCredentialProvider(CredentialProvider):
    """Phase-1 interim provider: a git-ignored JSON file on disk (CCS-7)."""

    name = "file"

    def __init__(self, path: str, require_secure_permissions: bool = True):
        self.path = path
        self._require_secure_permissions = require_secure_permissions
        self._data: Optional[Dict[str, Any]] = None

    def _load(self) -> Dict[str, Any]:
        if self._data is not None:
            return self._data
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except FileNotFoundError as exc:
            raise CredentialError(
                f"Credentials file not found: {self.path}\n"
                f"Copy credentials.example.json to it and fill in each cluster's API key."
            ) from exc
        except json.JSONDecodeError as exc:
            raise CredentialError(f"{self.path} is not valid JSON: {exc}") from exc
        except OSError as exc:
            raise CredentialError(f"Cannot read {self.path}: {exc}") from exc

        if not isinstance(data, dict):
            raise CredentialError(f"{self.path}: expected a JSON object keyed by cluster name")

        self._check_permissions()
        self._data = data
        return data

    def _check_permissions(self) -> None:
        """Warn loudly if the secret file is group/world readable (FISMA hygiene)."""
        if not self._require_secure_permissions or os.name != "posix":
            return
        try:
            mode = os.stat(self.path).st_mode
        except OSError:  # pragma: no cover - racy stat
            return
        if mode & (stat.S_IRWXG | stat.S_IRWXO):
            import logging

            logging.getLogger("ccs.credentials").warning(
                "Credentials file %s is group/world accessible (mode %o). Run: chmod 600 %s",
                self.path,
                stat.S_IMODE(mode),
                self.path,
            )

    def get(self, cluster_name: str) -> str:
        data = self._load()
        entry = data.get(cluster_name)
        if entry is None:
            known = ", ".join(k for k in data if not k.startswith("_")) or "(none)"
            raise CredentialError(
                f"No credential for cluster '{cluster_name}' in {self.path}. Present keys: {known}"
            )
        return build_auth_header(entry, f"{self.path}[{cluster_name}]")


class EnvCredentialProvider(CredentialProvider):
    """Read API keys from the environment: `<PREFIX><CLUSTER_UPPER>`.

    Handy for containers and CI; the value is the base64 `id:api_key` string.
    """

    name = "env"

    def __init__(self, prefix: str = "CCS_API_KEY_"):
        self.prefix = prefix

    def _var_name(self, cluster_name: str) -> str:
        safe = "".join(ch if ch.isalnum() else "_" for ch in cluster_name).upper()
        return f"{self.prefix}{safe}"

    def get(self, cluster_name: str) -> str:
        var = self._var_name(cluster_name)
        value = os.environ.get(var)
        if not value:
            raise CredentialError(
                f"No credential for cluster '{cluster_name}': environment variable {var} is unset"
            )
        return build_auth_header({"api_key": value}, var)


class SecretsManagerCredentialProvider(CredentialProvider):
    """Phase-1 hardening provider: AWS Secrets Manager via boto3 (CCS-8).

    Two layouts are supported:

    * `secret_id` — one secret whose value is the same JSON object as the
      credentials file: ``{"prod": {"api_key": "..."}, ...}``
    * `secret_id_template` — one secret per cluster, e.g. ``ccs/es/{cluster}``,
      whose value is either ``{"api_key": "..."}`` or the raw key string.
    """

    name = "aws_secrets_manager"

    def __init__(
        self,
        secret_id: Optional[str] = None,
        secret_id_template: Optional[str] = None,
        region: Optional[str] = None,
        profile: Optional[str] = None,
    ):
        if not secret_id and not secret_id_template:
            raise CredentialError("Secrets Manager provider needs secret_id or secret_id_template")
        self.secret_id = secret_id
        self.secret_id_template = secret_id_template
        self.region = region
        self.profile = profile
        self._client = None
        self._cache: Dict[str, Any] = {}

    def _get_client(self):
        if self._client is not None:
            return self._client
        try:
            import boto3  # imported lazily so file-based runs need no AWS SDK
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise CredentialError(
                "provider 'aws_secrets_manager' requires boto3. Install it with:\n"
                "    pip install 'boto3>=1.34.0'"
            ) from exc

        try:
            session = boto3.session.Session(profile_name=self.profile, region_name=self.region)
            self._client = session.client("secretsmanager")
        except Exception as exc:  # noqa: BLE001 - botocore raises many types
            raise CredentialError(f"Cannot create a Secrets Manager client: {exc}") from exc
        return self._client

    def _fetch(self, secret_id: str) -> Any:
        if secret_id in self._cache:
            return self._cache[secret_id]

        client = self._get_client()
        try:
            response = client.get_secret_value(SecretId=secret_id)
        except Exception as exc:  # noqa: BLE001 - ClientError et al.
            raise CredentialError(f"Secrets Manager get_secret_value('{secret_id}') failed: {exc}") from exc

        payload = response.get("SecretString")
        if payload is None and response.get("SecretBinary") is not None:
            payload = response["SecretBinary"].decode("utf-8")
        if payload is None:
            raise CredentialError(f"Secret '{secret_id}' has no value")

        try:
            value: Any = json.loads(payload)
        except json.JSONDecodeError:
            value = payload.strip()  # plain API-key string

        self._cache[secret_id] = value
        return value

    def get(self, cluster_name: str) -> str:
        if self.secret_id_template:
            secret_id = self.secret_id_template.format(cluster=cluster_name)
            value = self._fetch(secret_id)
            entry = {"api_key": value} if isinstance(value, str) else value
            return build_auth_header(entry, f"secret '{secret_id}'")

        assert self.secret_id is not None
        value = self._fetch(self.secret_id)
        if not isinstance(value, dict):
            raise CredentialError(
                f"Secret '{self.secret_id}' must be a JSON object keyed by cluster name "
                f"when 'secret_id' is used; use 'secret_id_template' for per-cluster secrets."
            )
        entry = value.get(cluster_name)
        if entry is None:
            known = ", ".join(k for k in value if not k.startswith("_")) or "(none)"
            raise CredentialError(
                f"No credential for cluster '{cluster_name}' in secret '{self.secret_id}'. "
                f"Present keys: {known}"
            )
        if isinstance(entry, str):
            entry = {"api_key": entry}
        return build_auth_header(entry, f"secret '{self.secret_id}'[{cluster_name}]")


def build_provider(cfg: CredentialsConfig) -> CredentialProvider:
    """Instantiate the provider named by the configuration."""
    if cfg.provider == "file":
        return FileCredentialProvider(cfg.path)
    if cfg.provider == "env":
        return EnvCredentialProvider(cfg.env_prefix)
    if cfg.provider == "aws_secrets_manager":
        return SecretsManagerCredentialProvider(
            secret_id=cfg.secret_id,
            secret_id_template=cfg.secret_id_template,
            region=cfg.region,
            profile=cfg.profile,
        )
    raise CredentialError(f"Unknown credential provider: {cfg.provider!r}")
