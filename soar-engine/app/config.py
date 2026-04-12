"""
Application configuration: environment variables, paths, and threshold loading.

Threat-intel keys: loaded with .env override, cleaned (quotes/CRLF), with .env file fallback
if the OS exposes empty variables that would otherwise shadow .env.
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any

# Importing this module runs app.env_bootstrap.bootstrap_dotenv() first.
from app.env_bootstrap import parse_env_file_contents

_BASE_DIR = Path(__file__).resolve().parent.parent
_ENV_PATH = _BASE_DIR / ".env"


def _clean_secret(raw: str | None) -> str:
    """Strip whitespace, quotes, inline # comments, and CR/LF from .env values."""
    if not raw:
        return ""
    s = raw.strip()
    if "#" in s:
        s = s.split("#", 1)[0].strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        s = s[1:-1].strip()
    s = re.sub(r"[\r\n]+", "", s).strip()
    return s


def _read_kv_from_env_file(key: str) -> str:
    """Read KEY=value from project .env (flexible format, UTF-8 BOM ok)."""
    if not _ENV_PATH.is_file():
        return ""
    try:
        text = _ENV_PATH.read_text(encoding="utf-8-sig")
    except OSError:
        return ""
    data = parse_env_file_contents(text)
    return _clean_secret(data.get(key, ""))


def mask_secret(value: str) -> str:
    """Mask API keys for logs (never log full secrets)."""
    if not value:
        return "(empty)"
    if len(value) <= 10:
        return "****"
    return f"{value[:4]}...{value[-4:]}"


def _resolve_api_key(env_name: str) -> str:
    v = _clean_secret(os.getenv(env_name))
    if v:
        return v
    file_val = _read_kv_from_env_file(env_name)
    if file_val:
        os.environ[env_name] = file_val
    return file_val


# --- API keys (never commit real keys) ---
VIRUSTOTAL_API_KEY: str = _resolve_api_key("VIRUSTOTAL_API_KEY")
ABUSEIPDB_API_KEY: str = _resolve_api_key("ABUSEIPDB_API_KEY")


def _clean_webhook_url(raw: str | None) -> str:
    if not raw:
        return ""
    s = raw.strip()
    if "#" in s:
        s = s.split("#", 1)[0].strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        s = s[1:-1].strip()
    s = re.sub(r"[\r\n]+", "", s).strip()
    return s


def _resolve_slack_webhook_url() -> str:
    v = _clean_webhook_url(os.getenv("SLACK_WEBHOOK_URL"))
    if v:
        return v
    file_val = _clean_webhook_url(_read_kv_from_env_file("SLACK_WEBHOOK_URL"))
    if file_val:
        os.environ["SLACK_WEBHOOK_URL"] = file_val
    return file_val


SLACK_WEBHOOK_URL: str = _resolve_slack_webhook_url()

SLACK_WEBHOOK_TIMEOUT_SECONDS: float = float(os.getenv("SLACK_WEBHOOK_TIMEOUT_SECONDS", "10"))

# --- HTTP ---
REQUEST_TIMEOUT_SECONDS: float = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "15"))
API_MAX_RETRIES: int = int(os.getenv("API_MAX_RETRIES", "4"))
API_RETRY_BACKOFF_BASE_SECONDS: float = float(os.getenv("API_RETRY_BACKOFF_BASE_SECONDS", "0.75"))
API_RETRY_BACKOFF_MAX_SECONDS: float = float(os.getenv("API_RETRY_BACKOFF_MAX_SECONDS", "30"))

# --- Paths ---
DATA_DIR: Path = _BASE_DIR / "data"
LOGS_DIR: Path = _BASE_DIR / "logs"
DB_PATH: Path = DATA_DIR / "incidents.db"
THRESHOLDS_PATH: Path = _BASE_DIR / "config" / "thresholds.json"

# --- Flask ---
FLASK_HOST: str = os.getenv("FLASK_HOST", "127.0.0.1")
FLASK_PORT: int = int(os.getenv("FLASK_PORT", "5000"))
FLASK_DEBUG: bool = os.getenv("FLASK_DEBUG", "false").lower() in ("1", "true", "yes")

DEFAULT_WEIGHT_VT: float = 0.6
DEFAULT_WEIGHT_ABUSE: float = 0.4

DEFAULT_THRESHOLDS: dict[str, Any] = {
    "malicious_min": 70,
    "suspicious_min": 40,
    "weight_vt": DEFAULT_WEIGHT_VT,
    "weight_abuse": DEFAULT_WEIGHT_ABUSE,
}


def load_thresholds() -> dict[str, Any]:
    merged = dict(DEFAULT_THRESHOLDS)
    if THRESHOLDS_PATH.is_file():
        try:
            with open(THRESHOLDS_PATH, encoding="utf-8") as f:
                file_data = json.load(f)
            if isinstance(file_data, dict):
                allowed = {
                    "malicious_min",
                    "suspicious_min",
                    "weight_vt",
                    "weight_abuse",
                }
                for key, val in file_data.items():
                    if key in allowed:
                        merged[key] = val
        except (json.JSONDecodeError, OSError):
            pass
    wv = float(merged.get("weight_vt", DEFAULT_WEIGHT_VT))
    wa = float(merged.get("weight_abuse", DEFAULT_WEIGHT_ABUSE))
    s = wv + wa
    if s > 0:
        merged["weight_vt"] = wv / s
        merged["weight_abuse"] = wa / s
    return merged


THRESHOLDS: dict[str, Any] = load_thresholds()


def ensure_directories() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)


def log_threat_intel_api_status(logger: logging.Logger) -> None:
    """Log masked keys and .env path at startup."""
    logger.info("Threat intel config: .env path=%s exists=%s", _ENV_PATH, _ENV_PATH.is_file())

    logger.info(
        "Loaded VIRUSTOTAL_API_KEY: %s",
        mask_secret(VIRUSTOTAL_API_KEY) if VIRUSTOTAL_API_KEY else "(empty)",
    )
    logger.info(
        "Loaded ABUSEIPDB_API_KEY: %s",
        mask_secret(ABUSEIPDB_API_KEY) if ABUSEIPDB_API_KEY else "(empty)",
    )

    if VIRUSTOTAL_API_KEY:
        logger.info("Using VirusTotal API key: %s", mask_secret(VIRUSTOTAL_API_KEY))
    else:
        logger.warning("VirusTotal API key not loaded - set VIRUSTOTAL_API_KEY in .env")
    if ABUSEIPDB_API_KEY:
        logger.info("Using AbuseIPDB API key: %s", mask_secret(ABUSEIPDB_API_KEY))
    else:
        logger.warning("AbuseIPDB API key not loaded - set ABUSEIPDB_API_KEY in .env")
