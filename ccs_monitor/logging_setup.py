"""Logging configuration (CCS-10: structured logging; CCS-21: rotatable logs).

Reports go to stdout, logs go to stderr and/or a file, so a cron job can mail
the report while the log file keeps the operational trail.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

LOG_FORMAT_TEXT = "%(asctime)s %(levelname)-8s %(name)s %(message)s"


class JsonLogFormatter(logging.Formatter):
    """One JSON object per line — ingestible by Filebeat without a grok pattern."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "@timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
            + "Z",
            "log": {"level": record.levelname, "logger": record.name},
            "message": record.getMessage(),
            "process": {"pid": record.process},
        }
        if record.exc_info:
            payload["error"] = {"stack_trace": self.formatException(record.exc_info)}
        return json.dumps(payload)


def configure_logging(
    level: str = "INFO",
    log_file: Optional[str] = None,
    log_format: str = "text",
    quiet: bool = False,
) -> logging.Logger:
    """Configure the `ccs` logger tree. Returns the root application logger."""
    root = logging.getLogger("ccs")
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    root.handlers.clear()
    root.propagate = False

    formatter = JsonLogFormatter() if log_format == "json" else logging.Formatter(LOG_FORMAT_TEXT)

    if not quiet:
        stream_handler = logging.StreamHandler(sys.stderr)
        stream_handler.setFormatter(formatter)
        root.addHandler(stream_handler)

    if log_file:
        directory = os.path.dirname(os.path.abspath(log_file))
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        # Plain FileHandler on purpose: rotation is logrotate's job (CCS-21), and
        # copytruncate keeps this handler's file descriptor valid.
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    if not root.handlers:
        root.addHandler(logging.NullHandler())
    return root
