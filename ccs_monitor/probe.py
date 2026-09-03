"""The probe itself: `GET /_remote/info` against one LOCAL cluster.

Metadata read only — no query probes — so probing prod remotes costs nothing
measurable (Risk: "Probe load on prod remotes").
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .config import ClusterConfig
from .credentials import CredentialError, CredentialProvider
from .http import HttpError, build_session, request_json

LOG = logging.getLogger("ccs.probe")

REMOTE_INFO_PATH = "/_remote/info"


@dataclass
class ProbeResult:
    """Outcome of one `_remote/info` call."""

    cluster: str
    base_url: str
    ok: bool
    duration_ms: float
    remotes: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    error_kind: Optional[str] = None
    status_code: Optional[int] = None


def probe_cluster(
    cluster: ClusterConfig,
    provider: CredentialProvider,
    session_factory=build_session,
) -> ProbeResult:
    """Fetch `_remote/info` for one local cluster.

    Never raises: any failure (credential, network, TLS, auth, malformed body)
    becomes `ok=False` with a classified error, which the evaluator turns into a
    single CRITICAL verdict for the cluster. That is what stops a dead probe
    from looking like health.
    """
    url = f"{cluster.base_url}{REMOTE_INFO_PATH}"
    started = time.perf_counter()

    try:
        auth_header = provider.get(cluster.credential_name)
    except CredentialError as exc:
        LOG.error("cluster=%s credential lookup failed: %s", cluster.name, exc)
        return ProbeResult(
            cluster=cluster.name,
            base_url=cluster.base_url,
            ok=False,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            error=str(exc),
            error_kind="credential_error",
        )

    session = session_factory(
        auth_header=auth_header, retries=cluster.retries, backoff=cluster.retry_backoff
    )
    try:
        body = request_json(
            session,
            "GET",
            url,
            verify=cluster.verify,
            timeout=cluster.timeout,
            expected_statuses=(200,),
        )
    except HttpError as exc:
        LOG.error("cluster=%s probe failed kind=%s: %s", cluster.name, exc.kind, exc)
        return ProbeResult(
            cluster=cluster.name,
            base_url=cluster.base_url,
            ok=False,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
            error=str(exc),
            error_kind=exc.kind,
            status_code=exc.status_code,
        )
    finally:
        session.close()

    duration_ms = round((time.perf_counter() - started) * 1000, 2)

    # _remote/info returns {} when no remotes are configured — a valid response.
    remotes = {k: v for k, v in body.items() if isinstance(v, dict)}
    LOG.info(
        "cluster=%s probe ok remotes=%d duration_ms=%.1f", cluster.name, len(remotes), duration_ms
    )
    return ProbeResult(
        cluster=cluster.name,
        base_url=cluster.base_url,
        ok=True,
        duration_ms=duration_ms,
        remotes=remotes,
    )
