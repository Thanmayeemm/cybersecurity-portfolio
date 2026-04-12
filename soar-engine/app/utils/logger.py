"""
Structured logging setup for API calls, decisions, and response actions.
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app import config


def _json_formatter_extra(record: logging.LogRecord) -> str:
    """Format log record as a single JSON line for machine parsing."""
    payload: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": record.levelname,
        "logger": record.name,
        "message": record.getMessage(),
    }
    ef = getattr(record, "extra_fields", None)
    if isinstance(ef, dict):
        payload.update(ef)
    return json.dumps(payload, default=str)


class JsonLineFormatter(logging.Formatter):
    """One JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        return _json_formatter_extra(record)


def setup_logging(name: str = "soar_engine") -> logging.Logger:
    """
    Configure root logger: console (human-readable) + file (JSON lines).
    """
    config.ensure_directories()
    log_file = config.LOGS_DIR / "soar_engine.log"

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    console = logging.StreamHandler(sys.stdout)
    console.setLevel(logging.INFO)
    console.setFormatter(
        logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")
    )
    logger.addHandler(console)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(JsonLineFormatter())
    logger.addHandler(file_handler)

    return logger


def log_with_extra(logger: logging.Logger, level: int, msg: str, **fields: Any) -> None:
    """Log a message with optional structured fields (attached to JSON output)."""
    logger.log(level, msg, extra={"extra_fields": fields})
