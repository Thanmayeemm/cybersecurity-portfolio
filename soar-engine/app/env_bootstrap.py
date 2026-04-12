"""
Load .env at process start before any module reads os.environ.

Resolves .env path from this file location (not cwd), tries sensible fallbacks,
calls load_dotenv(override=True), then merges parsed key/values for TI secrets
so keys still load if dotenv skips a line (BOM, spacing, etc.).
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

# app/env_bootstrap.py -> parent=app, parent.parent=project root (soar-engine/)
_APP_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _APP_DIR.parent

# If you run from repo root (cybersecurity-portfolio), cwd-based .env is wrong;
# __file__-based path is authoritative. Optional fallbacks:
def _candidate_env_files() -> list[Path]:
    roots = [
        _PROJECT_ROOT,
        Path.cwd(),
        Path.cwd() / "soar-engine",
    ]
    seen: set[Path] = set()
    out: list[Path] = []
    for root in roots:
        p = (root / ".env").resolve()
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _clean_value(raw: str) -> str:
    s = raw.strip()
    if "#" in s and not (s.startswith('"') or s.startswith("'")):
        s = s.split("#", 1)[0].strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        s = s[1:-1]
    return re.sub(r"[\r\n]+", "", s).strip()


def parse_env_file_contents(text: str) -> dict[str, str]:
    """
    Parse KEY=VALUE lines (flexible spacing, optional 'export', utf-8).
    """
    result: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, _, rest = line.partition("=")
        key = key.strip()
        if not key:
            continue
        result[key] = _clean_value(rest)
    return result


def _merge_ti_keys_from_file(env_path: Path) -> None:
    """
    Re-parse the same .env file and push TI/Slack keys into os.environ.

    Ensures values apply even if python-dotenv skipped a line (BOM, odd spacing).
    When the file defines a non-empty value, it wins for these keys.
    """
    if not env_path.is_file():
        return
    try:
        raw = env_path.read_bytes()
    except OSError:
        return
    text: str | None = None
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        return

    parsed = parse_env_file_contents(text)
    ti_keys = ("VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "SLACK_WEBHOOK_URL")
    for name in ti_keys:
        file_val = parsed.get(name)
        if file_val:
            os.environ[name] = file_val


def bootstrap_dotenv() -> Path | None:
    """
    Load the first existing .env among candidates. Returns path used, or None.
    """
    chosen: Path | None = None
    for candidate in _candidate_env_files():
        if candidate.is_file():
            chosen = candidate
            break

    if chosen is None:
        logger.warning(
            "env_bootstrap: no .env file found (checked: %s)",
            ", ".join(str(p) for p in _candidate_env_files()),
        )
        return None

    loaded = load_dotenv(dotenv_path=chosen, override=True)
    logger.info(
        "env_bootstrap: load_dotenv path=%s override=True result=%s",
        chosen,
        loaded,
    )
    _merge_ti_keys_from_file(chosen)
    return chosen


_ENV_FILE_USED = bootstrap_dotenv()
