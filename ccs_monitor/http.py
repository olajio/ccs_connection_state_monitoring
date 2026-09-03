"""HTTP plumbing: sessions with TLS verification, timeouts, and bounded retries.

Retries cover transient transport faults only (connection resets, 429, 502/503/504).
An auth or TLS failure is *not* retried — it is a real, reportable degradation
signal and retrying it only delays the CRITICAL verdict.
"""

from __future__ import annotations

import json as _json
import logging
from typing import Any, Dict, Optional, Union

import requests
from requests.adapters import HTTPAdapter

try:  # urllib3 v2 and v1 expose Retry at different paths
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover - very old urllib3
    from requests.packages.urllib3.util.retry import Retry  # type: ignore

from . import __version__

LOG = logging.getLogger("ccs.http")

USER_AGENT = f"ccs-health-monitor/{__version__}"

#: Status codes worth a retry: rate limiting and transient gateway errors.
RETRY_STATUSES = (429, 502, 503, 504)


class HttpError(RuntimeError):
    """Any non-recoverable HTTP/transport failure, with a classification tag."""

    def __init__(self, message: str, kind: str = "request_error", status_code: Optional[int] = None):
        super().__init__(message)
        self.kind = kind
        self.status_code = status_code


def build_session(
    auth_header: Optional[str] = None,
    retries: int = 2,
    backoff: float = 0.5,
    extra_headers: Optional[Dict[str, str]] = None,
) -> requests.Session:
    """Create a Session with retry/backoff on idempotent methods."""
    session = requests.Session()
    session.headers.update(
        {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": USER_AGENT,
        }
    )
    if auth_header:
        session.headers["Authorization"] = auth_header
    if extra_headers:
        session.headers.update(extra_headers)

    retry = Retry(
        total=max(0, int(retries)),
        connect=max(0, int(retries)),
        read=max(0, int(retries)),
        status=max(0, int(retries)),
        backoff_factor=max(0.0, float(backoff)),
        status_forcelist=RETRY_STATUSES,
        allowed_methods=frozenset({"GET", "HEAD", "PUT", "POST", "DELETE"}),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=4, pool_maxsize=8)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


def classify_exception(exc: Exception) -> str:
    """Map a requests exception to a stable, alertable error kind."""
    if isinstance(exc, requests.exceptions.SSLError):
        return "tls_error"
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return "connect_timeout"
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return "read_timeout"
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection_error"
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return "too_many_redirects"
    if isinstance(exc, requests.exceptions.InvalidURL):
        return "invalid_url"
    if isinstance(exc, ValueError):
        return "invalid_json"
    return "request_error"


def classify_status(status_code: int) -> str:
    """Map an HTTP status to an error kind so alerts can distinguish causes."""
    if status_code in (401, 403):
        return "auth_error"
    if status_code == 404:
        return "not_found"
    if 400 <= status_code < 500:
        return "client_error"
    return "server_error"


def _short_body(response: requests.Response, limit: int = 400) -> str:
    text = (response.text or "").strip().replace("\n", " ")
    return text[:limit] + ("…" if len(text) > limit else "")


def request_json(
    session: requests.Session,
    method: str,
    url: str,
    *,
    verify: Union[bool, str] = True,
    timeout: float = 10.0,
    payload: Any = None,
    body: Optional[str] = None,
    content_type: Optional[str] = None,
    expected_statuses: tuple = (200, 201),
    allow_statuses: tuple = (),
) -> Dict[str, Any]:
    """Perform a request and return the parsed JSON body.

    `allow_statuses` are returned to the caller instead of raising (e.g. a 404
    when checking whether an index template already exists).
    """
    headers: Dict[str, str] = {}
    data: Optional[Union[str, bytes]] = None
    if body is not None:
        data = body.encode("utf-8")
        if content_type:
            headers["Content-Type"] = content_type
    elif payload is not None:
        data = _json.dumps(payload).encode("utf-8")

    LOG.debug("%s %s", method, url)
    try:
        response = session.request(
            method, url, data=data, headers=headers or None, timeout=timeout, verify=verify
        )
    except Exception as exc:  # noqa: BLE001 - normalized into HttpError below
        kind = classify_exception(exc)
        raise HttpError(f"{method} {url} failed ({kind}): {exc}", kind=kind) from exc

    if response.status_code in allow_statuses:
        # Hand back the body too: an allowed 400 might be "already exists" or a
        # genuinely bad request, and only the caller can tell those apart.
        try:
            body = response.json() if response.content else {}
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        return {**body, "_status": response.status_code, "_allowed": True}

    if response.status_code not in expected_statuses:
        kind = classify_status(response.status_code)
        raise HttpError(
            f"{method} {url} returned HTTP {response.status_code}: {_short_body(response)}",
            kind=kind,
            status_code=response.status_code,
        )

    if not response.content:
        return {}
    try:
        parsed = response.json()
    except ValueError as exc:
        raise HttpError(
            f"{method} {url} returned a non-JSON body: {_short_body(response)}",
            kind="invalid_json",
            status_code=response.status_code,
        ) from exc

    if not isinstance(parsed, dict):
        raise HttpError(
            f"{method} {url} returned JSON of type {type(parsed).__name__}, expected an object",
            kind="invalid_json",
            status_code=response.status_code,
        )
    return parsed
