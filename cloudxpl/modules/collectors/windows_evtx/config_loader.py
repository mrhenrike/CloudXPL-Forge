"""
Carrega configuração a partir de YAML (estrutura NW: categories + hosts).
Produz CollectorConfig e lista de TargetHost com merge category → host.
"""
import os
from pathlib import Path
from typing import Any, Dict, List

from .config import (
    AuthMethod,
    CollectorConfig,
    EventSourceCategory,
    TargetHost,
    Transport,
)


def _bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in ("true", "1", "yes", "on")
    return bool(v)


def _int(v: Any, default: int = 0) -> int:
    if v is None:
        return default
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _str(v: Any) -> str:
    return str(v).strip() if v is not None else ""


def _expand_env(s: str) -> str:
    """Expande ${VAR} e $VAR a partir de os.environ. Mantém literal se não existir."""
    if not s or "$" not in s:
        return s
    out = []
    i = 0
    while i < len(s):
        if s[i] == "$" and i + 1 < len(s):
            if s[i + 1] == "{":
                end = s.find("}", i + 2)
                if end != -1:
                    key = s[i + 2 : end].strip()
                    out.append(os.environ.get(key, ""))
                    i = end + 1
                else:
                    out.append(s[i])
                    i += 1
            else:
                key_start = i + 1
                j = key_start
                while j < len(s) and (s[j].isalnum() or s[j] == "_"):
                    j += 1
                key = s[key_start:j]
                out.append(os.environ.get(key, f"${key}") if key else "$")
                i = j
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _load_env_file(path: str) -> None:
    """Carrega arquivo .env (KEY=VALUE) em os.environ. Ignora comentários e linhas vazias."""
    if not path or not os.path.isfile(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                eq = line.find("=")
                if eq <= 0:
                    continue
                key = line[:eq].strip()
                val = line[eq + 1 :].strip()
                if len(val) >= 2 and (val.startswith('"') and val.endswith('"') or val.startswith("'") and val.endswith("'")):
                    val = val[1:-1]
                if key:
                    os.environ[key] = val
    except Exception:
        pass


def load_target_from_dict(
    host_data: Dict[str, Any],
    category: EventSourceCategory,
    global_verify_ssl: bool = False,
) -> TargetHost:
    """Constrói um TargetHost a partir de dict (host) + category defaults."""
    raw_addr = host_data.get("event_source_address") or host_data.get("hostname") or host_data.get("host")
    address = _expand_env(_str(raw_addr))
    if not address:
        raise ValueError("Host deve ter event_source_address ou hostname ou host")
    port = host_data.get("port")
    if port is not None:
        port = _int(port)
    transport_raw = _str(host_data.get("transport_mode") or host_data.get("transport") or "http").lower()
    transport = Transport.HTTPS if transport_raw == "https" else Transport.HTTP
    auth_raw = _str(host_data.get("authorization_method") or category.authorization_method).lower()
    if auth_raw == "certificate":
        auth = AuthMethod.CERTIFICATE
    elif auth_raw == "basic":
        auth = AuthMethod.BASIC
    else:
        auth = AuthMethod.NEGOTIATE
    validate = host_data.get("validate_server")
    if validate is None:
        validate = global_verify_ssl
    else:
        validate = _bool(validate)
    host_ip = _expand_env(_str(host_data.get("ip"))) or None
    return TargetHost(
        hostname=address,
        domain=None,
        ip=host_ip,
        port=port if port else None,
        transport=transport,
        auth=auth,
        enabled=_bool(host_data.get("enabled", True)),
        event_filter=_str(host_data.get("event_filter")) or None,
        validate_server=validate,
        debug=_str(host_data.get("debug") or "off").lower() or "off",
        render_locale=_str(host_data.get("render_locale")) or None,
        windows_type=_str(host_data.get("windows_type")) or None,
        resolve_sids=_bool(host_data.get("resolve_sids", True)),
        sid_enumeration_interval=host_data.get("sid_enumeration_interval"),
        sid_enumeration_timeout=host_data.get("sid_enumeration_timeout"),
        override_channels=_str(host_data.get("override_channels")) or None,
        certificate_name=_str(host_data.get("certificate_name")) or None,
        ca_trust_path=_str(host_data.get("ca_trust_path")) or None,
        client_cert_pem=_str(host_data.get("client_cert_pem")) or None,
        client_cert_key_pem=_str(host_data.get("client_cert_key_pem")) or None,
        client_cert_key_password=_str(host_data.get("client_cert_key_password")) or None,
    )


def load_category_from_dict(cat: Dict[str, Any]) -> EventSourceCategory:
    """Constrói EventSourceCategory a partir de dict."""
    auth_raw = _str(cat.get("authorization_method") or "basic").lower()
    auth = AuthMethod.BASIC if auth_raw == "basic" else AuthMethod.NEGOTIATE
    return EventSourceCategory(
        alias=_str(cat.get("alias") or "default"),
        authorization_method=auth,
        channel=_str(cat.get("channel") or "Security,System,Application"),
        user_name=_str(cat.get("user_name") or cat.get("username") or ""),
        password=_str(cat.get("password") or ""),
        read_all_events=_bool(cat.get("read_all_events", True)),
        max_duration_poll=_int(cat.get("max_duration_poll"), 120),
        max_events_per_cycle=_int(cat.get("max_events_per_cycle"), 150000),
        polling_interval=_int(cat.get("polling_interval"), 60),
        render_events=_bool(cat.get("render_events", True)),
    )


def load_config_yaml(path: str) -> CollectorConfig:
    """
    Carrega arquivo YAML no formato NW (categories com hosts).
    Retorna um único CollectorConfig com todos os targets achatados.
    """
    try:
        import yaml
    except ImportError:
        raise RuntimeError("PyYAML necessário para --config. Instale: pip install pyyaml")
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    env_file = _str(data.get("env_file")) or os.environ.get("HARPIA_ENV_PATH", "")
    if env_file:
        config_dir = os.path.abspath(os.path.dirname(os.path.abspath(path)) or os.getcwd())
        env_path = os.path.normpath(os.path.join(config_dir, env_file)) if not os.path.isabs(env_file) else env_file
        _load_env_file(env_path)
        if not os.path.isfile(env_path) and os.environ.get("HARPIA_ENV_PATH"):
            _load_env_file(os.environ.get("HARPIA_ENV_PATH", ""))
    global_verify = _bool(data.get("verify_ssl", False))
    _raw_output_dir = _str(data.get("output_dir") or "").strip()
    output_dir = _expand_env(_raw_output_dir) if _raw_output_dir else os.path.join(os.getcwd(), "logs")
    output_filename_pattern = _str(data.get("output_filename_pattern") or "{hostname}_{channel}_{YYYY}-{MM}-{DD}-{HHMMSS}Z")
    output_extension = _str(data.get("output_extension") or ".log")
    app_name = _str(data.get("app_name") or "harpiawincollector")
    output_format = _str(data.get("output_format") or "raw")  # raw | ietf | jsonl | cef
    targets: List[TargetHost] = []
    username = _expand_env(_str(data.get("username") or data.get("user_name") or ""))
    password = _expand_env(_str(data.get("password") or ""))
    log_names = ["Security", "System", "Application"]
    max_events_per_log = _int(data.get("max_events_per_log") or data.get("max_events_per_cycle"), 1000)
    max_duration_poll = 120
    polling_interval = _int(data.get("polling_interval"), 60)
    read_all_events = True
    render_events = True
    collect_all_logs = _bool(data.get("collect_all_logs", False))
    rotation_interval_sec = _int(data.get("rotation_interval_sec"), 60)
    rotation_max_lines = _int(data.get("rotation_max_lines"), 10000)
    disk_threshold_percent = float(data.get("disk_threshold_percent") or 98.0)
    disk_target_percent = float(data.get("disk_target_percent") or 80.0)
    raw_tiers = data.get("retention_tiers_sec")
    retention_days = _int(
        os.environ.get("WINCOLLECT_RETENTION_DAYS") or data.get("retention_days"), 15
    )
    backfill_days = _int(
        os.environ.get("WINCOLLECT_BACKFILL_DAYS") or data.get("backfill_days"), 30
    )
    if retention_days > 0:
        retention_tiers_sec = (retention_days * 86400, 0)
    elif raw_tiers:
        retention_tiers_sec = tuple(int(x) for x in raw_tiers) if isinstance(raw_tiers, (list, tuple)) else (86400, 10800, 3600, 1800, 0)
    else:
        retention_tiers_sec = (86400, 10800, 3600, 1800, 0)
    bookmark_path = _str(data.get("bookmark_path")) or None
    if not bookmark_path and output_dir:
        bookmark_path = os.path.join(output_dir.rstrip("/"), ".wincollect_bookmarks.json")
    ca_trust_path = _str(data.get("ca_trust_path")) or None
    client_cert_pem = _str(data.get("client_cert_pem")) or None
    client_cert_key_pem = _str(data.get("client_cert_key_pem")) or None
    client_cert_key_password = _str(data.get("client_cert_key_password")) or None

    for cat_data in data.get("categories") or []:
        cat = load_category_from_dict(cat_data)
        if cat.user_name:
            username = _expand_env(cat.user_name)
        if cat.password:
            password = _expand_env(cat.password)
        log_names = [x.strip() for x in cat.channel.split(",") if x.strip()]
        max_events_per_log = _int(cat.max_events_per_cycle or max_events_per_log, 1000)
        max_duration_poll = cat.max_duration_poll
        polling_interval = cat.polling_interval
        read_all_events = cat.read_all_events
        render_events = cat.render_events
        for host_data in cat_data.get("hosts") or []:
            t = load_target_from_dict(host_data, cat, global_verify)
            if t.enabled:
                targets.append(t)
    username = username or os.environ.get("WINCOLLECT_USER", "")
    password = password or os.environ.get("WINCOLLECT_PASSWORD", "")
    return CollectorConfig(
        username=username,
        password=password,
        targets=targets,
        log_names=log_names,
        max_events_per_log=max_events_per_log,
        output_dir=output_dir,
        output_filename_pattern=output_filename_pattern,
        output_extension=output_extension,
        app_name=app_name,
        output_format=output_format,
        verify_ssl=global_verify,
        collect_all_logs=collect_all_logs,
        ca_trust_path=ca_trust_path,
        client_cert_pem=client_cert_pem,
        client_cert_key_pem=client_cert_key_pem,
        client_cert_key_password=client_cert_key_password,
        max_duration_poll=max_duration_poll,
        polling_interval=polling_interval,
        read_all_events=read_all_events,
        render_events=render_events,
        rotation_interval_sec=rotation_interval_sec,
        rotation_max_lines=rotation_max_lines,
        disk_threshold_percent=disk_threshold_percent,
        disk_target_percent=disk_target_percent,
        retention_tiers_sec=retention_tiers_sec,
        retention_days=retention_days,
        backfill_days=backfill_days,
        bookmark_path=bookmark_path,
    )
