"""Shared helpers for Trend Micro Vision One collectors."""

import json
import logging
import os
import socket
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

LOGGER = logging.getLogger("trend_micro_visionone")

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_STATE_FILE = SCRIPT_DIR / "state.json"
API_DT_FORMATS = (
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
)


def setup_logging() -> None:
    """Configure stdout logging once."""
    if LOGGER.handlers:
        return
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    )
    LOGGER.addHandler(handler)
    LOGGER.setLevel(logging.INFO)


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load collector config from JSON."""
    path = config_path or (SCRIPT_DIR / "config.json")
    with path.open("r", encoding="utf-8") as handle:
        config = json.load(handle)
    if not isinstance(config, dict):
        raise ValueError("config.json must be a JSON object")
    required = ("udp_host", "udp_port", "bearer_token", "minutes")
    missing = [key for key in required if key not in config]
    if missing:
        raise ValueError(f"config.json missing keys: {', '.join(missing)}")
    return config


def resolve_state_path(config: Dict[str, Any]) -> Path:
    """Resolve state file path from config or default."""
    raw = str(config.get("state_file") or "").strip()
    if not raw:
        return DEFAULT_STATE_FILE
    path = Path(raw)
    if not path.is_absolute():
        path = SCRIPT_DIR / path
    return path


def utc_now() -> datetime:
    """Return timezone-aware UTC now."""
    return datetime.now(timezone.utc)


def parse_api_datetime(value: str) -> datetime:
    """Parse Vision One API datetime strings into aware UTC datetime."""
    text = (value or "").strip()
    if not text:
        raise ValueError("empty datetime")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        parsed = None
        for fmt in API_DT_FORMATS:
            try:
                parsed = datetime.strptime(value, fmt)
                break
            except ValueError:
                continue
        if parsed is None:
            raise ValueError(f"unsupported datetime format: {value}") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def format_api_datetime(value: datetime) -> str:
    """Format datetime for Vision One query parameters (second precision, Zulu)."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    else:
        value = value.astimezone(timezone.utc)
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def load_state(state_path: Path) -> Dict[str, Any]:
    """Load checkpoint state; return empty structure when missing/invalid."""
    empty = {"alerts": {}, "detections": {}}
    if not state_path.exists():
        return empty
    try:
        raw = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.warning("Failed to read state file %s: %s", state_path, exc)
        return empty
    if not isinstance(raw, dict):
        return empty
    for key in ("alerts", "detections"):
        if not isinstance(raw.get(key), dict):
            raw[key] = {}
    return raw


def save_state(state_path: Path, state: Dict[str, Any]) -> None:
    """Atomically persist checkpoint state."""
    state_path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(state, ensure_ascii=False, indent=2, sort_keys=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{state_path.name}.",
        suffix=".tmp",
        dir=str(state_path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, state_path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def get_checkpoint(state: Dict[str, Any], stream: str) -> Optional[datetime]:
    """Return last successful datetime for a stream, if present."""
    entry = state.get(stream) or {}
    raw = entry.get("last_datetime")
    if not raw:
        return None
    try:
        return parse_api_datetime(str(raw))
    except ValueError:
        LOGGER.warning("Invalid checkpoint for %s: %s", stream, raw)
        return None


def set_checkpoint(
    state: Dict[str, Any],
    stream: str,
    last_dt: datetime,
    state_path: Path,
) -> None:
    """Update stream checkpoint and persist immediately."""
    state.setdefault(stream, {})
    state[stream]["last_datetime"] = format_api_datetime(last_dt)
    state[stream]["updated_at"] = format_api_datetime(utc_now())
    save_state(state_path, state)


def resolve_start_datetime(
    state: Dict[str, Any],
    stream: str,
    minutes: int,
) -> datetime:
    """
    Resolve query start time.

    Prefer last checkpoint + 1 second so the next run resumes after the last
    successfully sent event. Fall back to now - minutes on first run.
    """
    checkpoint = get_checkpoint(state, stream)
    if checkpoint is not None:
        return checkpoint + timedelta(seconds=1)
    lookback = max(int(minutes), 1)
    return utc_now() - timedelta(minutes=lookback)


def send_udp(host: str, port: int, data: Any) -> None:
    """Send a JSON payload over UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        payload = json.dumps(data, ensure_ascii=False).encode("utf-8")
        sock.sendto(payload, (host, int(port)))
    finally:
        sock.close()


def max_item_datetime(
    items: List[Dict[str, Any]],
    field_name: str,
) -> Optional[datetime]:
    """Return the newest datetime among items for the given field."""
    newest: Optional[datetime] = None
    for item in items:
        raw = item.get(field_name)
        if not raw:
            continue
        try:
            current = parse_api_datetime(str(raw))
        except ValueError:
            continue
        if newest is None or current > newest:
            newest = current
    return newest


def api_get(
    url: str,
    bearer_token: str,
    timeout: int = 60,
) -> Optional[Dict[str, Any]]:
    """GET JSON from Vision One API; return None on failure."""
    headers = {"Authorization": f"Bearer {bearer_token}"}
    try:
        response = requests.get(url, headers=headers, timeout=timeout)
    except requests.RequestException as exc:
        LOGGER.error("HTTP request failed: %s", exc)
        return None
    if response.status_code != 200:
        body = (response.text or "")[:500]
        LOGGER.error(
            "HTTP %s for %s: %s",
            response.status_code,
            url.split("?", 1)[0],
            body,
        )
        return None
    try:
        data = response.json()
    except ValueError as exc:
        LOGGER.error("Invalid JSON response: %s", exc)
        return None
    if not isinstance(data, dict):
        LOGGER.error("Unexpected JSON root type: %s", type(data).__name__)
        return None
    return data
