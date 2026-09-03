"""Bulk writer for the `ccs-health-monitor` state store (Phase 2, CCS-13).

The state store decouples measuring from reacting: the collector only writes
verdicts, and Kibana rules read them. That is what gives history, auto-recovery,
and a staleness signal for a dead collector.

Write semantics per state-store mode:

  data_stream  bulk `create` into the data stream `ccs-health-monitor`
  index        bulk `index` into the write alias `ccs-health-monitor`

Both are append-only, so a verdict is never overwritten and history is retained.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .config import AppConfig, state_store_endpoint
from .credentials import CredentialError, CredentialProvider
from .http import HttpError, build_session, request_json

LOG = logging.getLogger("ccs.sink")


@dataclass
class BulkResult:
    """Outcome of one bulk write."""

    attempted: int = 0
    indexed: int = 0
    failed: int = 0
    errors: List[str] = field(default_factory=list)
    took_ms: Optional[int] = None
    skipped: bool = False
    reason: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.failed == 0 and not self.errors


class StateStoreWriter:
    """Writes verdict documents to Elasticsearch."""

    def __init__(self, config: AppConfig, provider: CredentialProvider):
        self.config = config
        self.provider = provider
        self.store = config.state_store
        self.endpoint = state_store_endpoint(config)

    # -- helpers ----------------------------------------------------------- #

    def _session(self):
        auth_header = self.provider.get(self.endpoint["credentials_key"])
        return build_session(
            auth_header=auth_header,
            retries=self.endpoint["retries"],
            backoff=self.endpoint["retry_backoff"],
        )

    def _bulk_action(self) -> Dict[str, Any]:
        # Data streams accept only `create`; the alias-backed index uses `index`.
        return {"create": {}} if self.store.mode == "data_stream" else {"index": {}}

    def _bulk_body(self, documents: List[Dict[str, Any]]) -> str:
        action = json.dumps(self._bulk_action())
        lines: List[str] = []
        for doc in documents:
            lines.append(action)
            lines.append(json.dumps(doc, default=str))
        return "\n".join(lines) + "\n"

    # -- public API -------------------------------------------------------- #

    def write(self, documents: List[Dict[str, Any]]) -> BulkResult:
        """Index documents. Never raises — a write failure is reported, not fatal.

        A failed write must not mask the verdicts themselves: the console report
        has already been produced, and the exit code reflects both.
        """
        result = BulkResult(attempted=len(documents))

        if not self.store.enabled:
            result.skipped = True
            result.reason = "state_store.enabled is false"
            return result
        if not documents:
            result.skipped = True
            result.reason = "no documents to write"
            return result

        url = f"{self.endpoint['base_url']}/{self.store.index}/_bulk"
        try:
            session = self._session()
        except CredentialError as exc:
            result.failed = len(documents)
            result.errors.append(f"credential lookup for the state store failed: {exc}")
            LOG.error("state store credential lookup failed: %s", exc)
            return result

        try:
            response = request_json(
                session,
                "POST",
                url,
                verify=self.endpoint["verify"],
                timeout=self.endpoint["timeout"],
                body=self._bulk_body(documents),
                content_type="application/x-ndjson",
                expected_statuses=(200, 201),
            )
        except HttpError as exc:
            result.failed = len(documents)
            result.errors.append(str(exc))
            LOG.error("bulk write to %s failed: %s", url, exc)
            return result
        finally:
            session.close()

        result.took_ms = response.get("took")
        for item in response.get("items", []):
            outcome = next(iter(item.values()), {})
            if outcome.get("error"):
                result.failed += 1
                if len(result.errors) < 5:  # keep the log readable
                    error = outcome["error"]
                    result.errors.append(
                        f"{error.get('type', 'error')}: {error.get('reason', 'unknown')}"
                    )
            else:
                result.indexed += 1

        if result.failed:
            LOG.error(
                "bulk write partially failed: %d/%d documents rejected (%s)",
                result.failed,
                result.attempted,
                "; ".join(result.errors),
            )
        else:
            LOG.info("indexed %d document(s) into %s", result.indexed, self.store.index)
        return result

    def verify_target(self) -> Dict[str, Any]:
        """Check that the state store exists and is writable-looking.

        Used by `--check-state-store` so a misconfigured index is caught during
        setup rather than at 03:00 on a cron run.
        """
        session = self._session()
        base = self.endpoint["base_url"]
        try:
            if self.store.mode == "data_stream":
                url = f"{base}/_data_stream/{self.store.index}"
                body = request_json(
                    session,
                    "GET",
                    url,
                    verify=self.endpoint["verify"],
                    timeout=self.endpoint["timeout"],
                    expected_statuses=(200,),
                    allow_statuses=(404,),
                )
                if body.get("_allowed"):
                    return {"exists": False, "kind": "data_stream", "name": self.store.index}
                streams = body.get("data_streams", [])
                return {
                    "exists": bool(streams),
                    "kind": "data_stream",
                    "name": self.store.index,
                    "backing_indices": [
                        i.get("index_name") for i in (streams[0].get("indices", []) if streams else [])
                    ],
                    "lifecycle": (streams[0].get("lifecycle") if streams else None),
                }

            url = f"{base}/{self.store.index}"
            body = request_json(
                session,
                "GET",
                url,
                verify=self.endpoint["verify"],
                timeout=self.endpoint["timeout"],
                expected_statuses=(200,),
                allow_statuses=(404,),
            )
            if body.get("_allowed"):
                return {"exists": False, "kind": "alias", "name": self.store.index}
            return {"exists": True, "kind": "alias", "name": self.store.index, "resolved": list(body)}
        finally:
            session.close()
