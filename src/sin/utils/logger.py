"""
sin.utils.logger - Structured JSON logging for the SIN platform

Outputs newline-delimited JSON to stdout so log aggregators (Loki,
CloudWatch, Datadog, etc.) can index every field without regex parsing.

Each log line is a JSON object with at minimum:
  timestamp, level, logger, message

Plus any extra kwargs passed to logger.info(..., extra={...}).

Usage:
    from sin.utils.logger import get_logger
    logger = get_logger("sin.api.server")
    logger.info("Device scanned", extra={"ip": "192.168.1.5", "risk": "HIGH"})
"""

import json
import logging
import sys
import traceback
from datetime import datetime, timezone
from typing import Any

from sin.core.config import settings


class _JsonFormatter(logging.Formatter):
    """Emit each log record as a single-line JSON object."""

    # Fields already encoded at the top level; skip from 'extra'
    _RESERVED = frozenset(
        logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
    ) | {"message", "asctime"}

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        record.message = record.getMessage()

        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.message,
        }

        # Attach any caller extras (e.g. extra={"ip": "..."})
        for key, value in record.__dict__.items():
            if key not in self._RESERVED and not key.startswith("_"):
                payload[key] = value

        # Attach exception info when present
        if record.exc_info:
            payload["exception"] = "".join(
                traceback.format_exception(*record.exc_info)
            ).strip()

        return json.dumps(payload, default=str)


def get_logger(name: str) -> logging.Logger:
    """
    Return a structured-JSON logger.

    Idempotent: calling twice with the same name returns the same logger
    without adding duplicate handlers.
    """
    logger = logging.getLogger(name)

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO))

    return logger
