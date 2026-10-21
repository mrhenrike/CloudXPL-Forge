"""
Saída dos eventos. Formatos:
- raw: XML/evtx em uma linha (sem conversão).
- ietf: RFC 5424 com MSG = JSON do evento parseado (sem raw_xml).
- jsonl: uma linha JSON por evento, campos parseados (sem raw_xml).
- cef: Common Event Format, evento parseado (sem raw_xml).
Path e nome configuráveis; extensão .log; rotação e rolled-out por disco.
"""
import json
import os
import re
import time
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .config import CollectorConfig
from .winevent_parser import parse_event_xml

IETF_PRI = 134
OUTPUT_EXTENSION_DEFAULT = ".log"


def _to_single_line_raw(xml: str) -> str:
    """UTF-8 limpo (sem mojibake) e uma única linha (\\n/\\r → espaço)."""
    s = xml.encode("utf-8", errors="replace").decode("utf-8")
    return s.replace("\r\n", " ").replace("\n", " ").replace("\r", " ").strip()


def _safe_filename(s: str) -> str:
    """Substitui caracteres não seguros para nome de arquivo."""
    return re.sub(r"[^\w\-.]", "_", s)


def _format_filename(config: CollectorConfig, hostname: str, log_name: str, suffix: str) -> str:
    """
    Gera o nome do arquivo a partir do padrão (placeholders: hostname, channel, YYYY, MM, DD, HHMMSS).
    suffix = "YYYY-MM-DD", "YYYY-MM-DD-HHMMSS" (rotação), ou "all". Extensão sempre .log.
    Default: hostname_channel_yyyy-mm-dd-HHMMSSZ.log
    """
    safe_host = _safe_filename(hostname)
    safe_channel = _safe_filename(log_name)
    now = datetime.utcnow()
    if suffix == "all":
        yyyy, mm, dd = now.strftime("%Y-%m-%d").split("-")
        hhmmss = now.strftime("%H%M%S")
    else:
        parts = suffix.split("-")
        yyyy = parts[0] if len(parts) >= 1 else ""
        mm = parts[1] if len(parts) >= 2 else ""
        dd = parts[2] if len(parts) >= 3 else ""
        hhmmss = parts[3] if len(parts) >= 4 and len(parts[3]) >= 6 else now.strftime("%H%M%S")
    pattern = getattr(config, "output_filename_pattern", None) or "{hostname}_{channel}_{YYYY}-{MM}-{DD}-{HHMMSS}Z"
    ext = getattr(config, "output_extension", None) or OUTPUT_EXTENSION_DEFAULT
    name = (
        pattern.replace("{hostname}", safe_host)
        .replace("{channel}", safe_channel)
        .replace("{YYYY}", yyyy)
        .replace("{MM}", mm)
        .replace("{DD}", dd)
        .replace("{HHMMSS}", hhmmss)
    )
    return name + ext if not name.endswith(ext) else name


def _output_file_path(config: CollectorConfig, hostname: str, log_name: str, suffix: str) -> str:
    """Diretório base/hostname/ e arquivo com nome formatado. Garante extensão .log."""
    base = (config.output_dir or "").strip() or os.path.join(os.getcwd(), "logs")
    safe_host = _safe_filename(hostname)
    dir_path = os.path.join(base, safe_host)
    filename = _format_filename(config, hostname, log_name, suffix)
    return os.path.join(dir_path, filename)


def _rotation_suffix(config: CollectorConfig) -> str:
    """Suffix com data+hora para rotação por tempo/linhas; sem hora para só por dia."""
    now = datetime.utcnow()
    interval = getattr(config, "rotation_interval_sec", 0) or 0
    max_lines = getattr(config, "rotation_max_lines", 0) or 0
    if interval > 0 or max_lines > 0:
        return now.strftime("%Y-%m-%d-%H%M%S")
    return now.strftime("%Y-%m-%d")


def _should_rotate(
    config: CollectorConfig,
    opened_at: float,
    line_count: int,
) -> bool:
    """True se deve rotacionar: janela de tempo ou limite de linhas atingido."""
    interval = getattr(config, "rotation_interval_sec", 0) or 0
    max_lines = getattr(config, "rotation_max_lines", 0) or 0
    if interval > 0 and (time.time() - opened_at) >= interval:
        return True
    if max_lines > 0 and line_count >= max_lines:
        return True
    return False


def ensure_output_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def rotate_old_files(directory: str, retention_days: int, patterns: list[str] | None = None) -> int:
    """
    Remove arquivos no diretório mais antigos que retention_days dias.
    patterns: lista de globs (ex: ['*.jsonl', '*.log']). Default: ['*.jsonl', '*.log'].
    Retorna quantidade de arquivos removidos.
    """
    if retention_days <= 0:
        return 0
    import glob as _glob
    cutoff = time.time() - (retention_days * 86400)
    removed = 0
    for pattern in (patterns or ["*.jsonl", "*.log"]):
        for filepath in _glob.glob(os.path.join(directory, "**", pattern), recursive=True):
            try:
                if os.path.isfile(filepath) and os.path.getmtime(filepath) < cutoff:
                    os.remove(filepath)
                    print(f"[rotate] Removido (>{retention_days}d): {os.path.basename(filepath)}", flush=True)
                    removed += 1
            except OSError as exc:
                print(f"[rotate] Erro ao remover {filepath}: {exc}", flush=True)
    return removed


def _parse_event(raw_xml: str) -> Optional[Dict[str, Any]]:
    """Parse XML para dict; retorna None se falhar."""
    try:
        return parse_event_xml(raw_xml, keep_rendered=True)
    except Exception:
        return None


def _parsed_record(hostname: str, log_name: str, parsed: Dict[str, Any]) -> Dict[str, Any]:
    """Registro para IETF/JSONL: @timestamp, host, channel, system, data, rendered (sem raw_xml)."""
    return {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "host": hostname,
        "channel": log_name,
        "system": parsed.get("system") or {},
        "data": parsed.get("data") or {},
        "rendered": parsed.get("rendered") or {},
    }


def _cef_escape(val: str) -> str:
    """Escapa valor para extensão CEF: \\ | \\n."""
    if val is None:
        return ""
    s = str(val).replace("\\", "\\\\").replace("|", "\\|").replace("\n", "\\n").replace("\r", "\\r")
    return s


def _parsed_to_cef(hostname: str, parsed: Dict[str, Any], channel: str = "") -> str:
    """Uma linha CEF completa: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|ext (rt, deviceExternalId, msg, cn1, cs1, etc.)."""
    sys_ = parsed.get("system") or {}
    rend = parsed.get("rendered") or {}
    data_ = parsed.get("data") or {}
    event_id = sys_.get("EventID") or "0"
    provider = (sys_.get("Provider") or "").strip() or "Windows"
    msg_rendered = (rend.get("Message") or "").strip()
    name = msg_rendered or provider or f"WinEvent {event_id}"
    level = sys_.get("Level") or "4"
    sev_map = {"0": "10", "1": "8", "2": "6", "3": "4", "4": "3", "5": "1"}
    severity = sev_map.get(level, "5")
    computer = (sys_.get("Computer") or hostname).strip() or hostname
    time_created = (sys_.get("TimeCreated") or "").strip()
    if not time_created:
        time_created = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
    chan = (channel or sys_.get("Channel") or "").strip() or "Application"
    record_id = (sys_.get("EventRecordID") or "").strip()
    ext_parts = [
        f"rt={_cef_escape(time_created)}",
        f"deviceExternalId={_cef_escape(computer)}",
        f"msg={_cef_escape(name[:1023])}",
        f"cn1={_cef_escape(str(event_id))}",
        f"cs1={_cef_escape(chan)}",
        f"cs2={_cef_escape(provider)}",
    ]
    if record_id:
        ext_parts.append(f"externalId={_cef_escape(record_id)}")
    for k, v in data_.items():
        if v is not None and str(v).strip():
            key_cef = str(k).replace(" ", "_")
            ext_parts.append(f"{_cef_escape(key_cef)}={_cef_escape(str(v)[:1023])}")
    ext = " ".join(ext_parts)
    return f"CEF:0|Microsoft|Windows|WinEvent|{_cef_escape(str(event_id))}|{_cef_escape(name[:255])}|{severity}|{ext}"


def event_to_logstash_record(hostname: str, log_name: str, event: Dict[str, Any]) -> Dict[str, Any]:
    """Um registro por evento, com campos padrão para Logstash (@timestamp, host, log)."""
    rec = {
        "@timestamp": datetime.utcnow().isoformat() + "Z",
        "host": hostname,
        "log": log_name,
        "event": event,
    }
    if event.get("system", {}).get("TimeCreated"):
        rec["event_created"] = event["system"]["TimeCreated"]
    return rec


def write_jsonl(
    output_dir: str,
    hostname: str,
    log_name: str,
    event: Dict[str, Any],
    rotate_by_day: bool = True,
) -> str:
    """
    Grava um evento em arquivo JSONL. Retorna o path do arquivo.
    Se rotate_by_day, usa sufixo YYYY-MM-DD no nome.
    """
    ensure_output_dir(output_dir)
    suffix = datetime.utcnow().strftime("%Y-%m-%d") if rotate_by_day else "all"
    safe_host = hostname.replace(".", "_").replace(":", "_")
    safe_log = log_name.replace(" ", "_")
    filename = f"winevent_{safe_host}_{safe_log}_{suffix}.jsonl"
    path = os.path.join(output_dir, filename)
    rec = event_to_logstash_record(hostname, log_name, event)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return path


def write_events_from_collector(
    config: CollectorConfig,
    events: Iterator[Tuple[str, str, Dict[str, Any]]],
    rotate_by_day: bool = True,
) -> int:
    """
    Consome o iterável (hostname, log_name, event_dict) e grava em JSONL.
    Retorna quantidade de eventos escritos.
    """
    count = 0
    for hostname, log_name, event in events:
        write_jsonl(
            config.output_dir,
            hostname,
            log_name,
            event,
            rotate_by_day=rotate_by_day,
        )
        count += 1
    return count


def _ietf_escape_sd_value(val: str) -> str:
    """Escapa valor para RFC 5424 structured data: \\ e ] e \"."""
    if not val:
        return ""
    return val.replace("\\", "\\\\").replace('"', '\\"').replace("]", "\\]")


def _ietf_syslog_line(
    timestamp: str,
    hostname: str,
    log_name: str,
    msg_raw: str,
    app_name: str = "harpiawincollector",
) -> str:
    """Uma linha IETF RFC 5424: <PRI>1 TIMESTAMP HOSTNAME APP-NAME - - [event@0 ...] MSG (raw, uma linha)."""
    channel_esc = _ietf_escape_sd_value(log_name)
    host_esc = _ietf_escape_sd_value(hostname)
    sd = f'[event@0 channel="{channel_esc}" source_host="{host_esc}"]'
    return f"<{IETF_PRI}>1 {timestamp} {hostname} {app_name} - - {sd} {msg_raw}"


def write_ietf_events_to_log(
    config: CollectorConfig,
    events: Iterator[Tuple[str, str, str]],
    rotate_by_day: bool = True,
) -> int:
    """
    IETF RFC 5424: uma linha por evento. MSG = JSON do evento parseado (sem raw_xml).
    """
    count = 0
    state: Dict[Tuple[str, str], Dict[str, Any]] = {}
    app_name = getattr(config, "app_name", None) or "harpiawincollector"
    use_rotation = (getattr(config, "rotation_interval_sec", 0) or 0) > 0 or (getattr(config, "rotation_max_lines", 0) or 0) > 0

    def open_new(key: Tuple[str, str], hostname: str, log_name: str):
        suffix = _rotation_suffix(config) if use_rotation else (datetime.utcnow().strftime("%Y-%m-%d") if rotate_by_day else "all")
        path = _output_file_path(config, hostname, log_name, suffix)
        ensure_output_dir(os.path.dirname(path))
        return {"f": open(path, "a", encoding="utf-8"), "opened_at": time.time(), "lines": 0, "suffix": suffix}

    try:
        for hostname, log_name, raw_xml in events:
            parsed = _parse_event(raw_xml)
            if not parsed:
                continue
            rec = _parsed_record(hostname, log_name, parsed)
            msg_json = json.dumps(rec, ensure_ascii=False)
            timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")
            line = _ietf_syslog_line(timestamp, hostname, log_name, msg_json, app_name=app_name)
            key = (_safe_filename(hostname), _safe_filename(log_name))
            if key not in state:
                state[key] = open_new(key, hostname, log_name)
            st = state[key]
            if _should_rotate(config, st["opened_at"], st["lines"]):
                st["f"].close()
                state[key] = open_new(key, hostname, log_name)
                st = state[key]
            if st["lines"] > 0:
                st["f"].write("\n")
            st["f"].write(line)
            st["f"].flush()
            st["lines"] += 1
            count += 1
    finally:
        for st in state.values():
            st["f"].close()
    return count


def write_raw_events_to_log(
    config: CollectorConfig,
    events: Iterator[Tuple[str, str, str]],
    rotate_by_day: bool = True,
) -> int:
    """
    Raw XML: uma linha por evento. Rotação por janela de tempo e/ou linhas.
    """
    count = 0
    state: Dict[Tuple[str, str], Dict[str, Any]] = {}
    use_rotation = (getattr(config, "rotation_interval_sec", 0) or 0) > 0 or (getattr(config, "rotation_max_lines", 0) or 0) > 0

    def open_new(key: Tuple[str, str], hostname: str, log_name: str):
        suffix = _rotation_suffix(config) if use_rotation else (datetime.utcnow().strftime("%Y-%m-%d") if rotate_by_day else "all")
        path = _output_file_path(config, hostname, log_name, suffix)
        ensure_output_dir(os.path.dirname(path))
        return {"f": open(path, "a", encoding="utf-8"), "opened_at": time.time(), "lines": 0, "suffix": suffix}

    try:
        for hostname, log_name, raw_xml in events:
            line_xml = _to_single_line_raw(raw_xml)
            key = (_safe_filename(hostname), _safe_filename(log_name))
            if key not in state:
                state[key] = open_new(key, hostname, log_name)
            st = state[key]
            if _should_rotate(config, st["opened_at"], st["lines"]):
                st["f"].close()
                state[key] = open_new(key, hostname, log_name)
                st = state[key]
            if st["lines"] > 0:
                st["f"].write("\n")
            st["f"].write(line_xml)
            st["f"].flush()
            st["lines"] += 1
            count += 1
    finally:
        for st in state.values():
            st["f"].close()
    return count


def write_jsonl_events(
    config: CollectorConfig,
    events: Iterator[Tuple[str, str, str]],
    rotate_by_day: bool = True,
) -> int:
    """
    JSONL: uma linha JSON por evento, campos parseados (system, data, rendered). Sem raw_xml.
    """
    count = 0
    state: Dict[Tuple[str, str], Dict[str, Any]] = {}
    use_rotation = (getattr(config, "rotation_interval_sec", 0) or 0) > 0 or (getattr(config, "rotation_max_lines", 0) or 0) > 0

    def open_new(key: Tuple[str, str], hostname: str, log_name: str):
        suffix = _rotation_suffix(config) if use_rotation else (datetime.utcnow().strftime("%Y-%m-%d") if rotate_by_day else "all")
        path = _output_file_path(config, hostname, log_name, suffix)
        ensure_output_dir(os.path.dirname(path))
        return {"f": open(path, "a", encoding="utf-8"), "opened_at": time.time(), "lines": 0, "suffix": suffix}

    try:
        for hostname, log_name, raw_xml in events:
            parsed = _parse_event(raw_xml)
            if not parsed:
                continue
            rec = _parsed_record(hostname, log_name, parsed)
            one_line = json.dumps(rec, ensure_ascii=False) + "\n"
            key = (_safe_filename(hostname), _safe_filename(log_name))
            if key not in state:
                state[key] = open_new(key, hostname, log_name)
            st = state[key]
            if _should_rotate(config, st["opened_at"], st["lines"]):
                st["f"].close()
                state[key] = open_new(key, hostname, log_name)
                st = state[key]
            st["f"].write(one_line)
            st["f"].flush()
            st["lines"] += 1
            count += 1
    finally:
        for st in state.values():
            st["f"].close()
    return count


def write_cef_events_to_log(
    config: CollectorConfig,
    events: Iterator[Tuple[str, str, str]],
    rotate_by_day: bool = True,
) -> int:
    """
    CEF (Common Event Format): uma linha por evento, parseado (sem raw_xml).
    """
    count = 0
    state: Dict[Tuple[str, str], Dict[str, Any]] = {}
    use_rotation = (getattr(config, "rotation_interval_sec", 0) or 0) > 0 or (getattr(config, "rotation_max_lines", 0) or 0) > 0

    def open_new(key: Tuple[str, str], hostname: str, log_name: str):
        suffix = _rotation_suffix(config) if use_rotation else (datetime.utcnow().strftime("%Y-%m-%d") if rotate_by_day else "all")
        path = _output_file_path(config, hostname, log_name, suffix)
        ensure_output_dir(os.path.dirname(path))
        return {"f": open(path, "a", encoding="utf-8"), "opened_at": time.time(), "lines": 0, "suffix": suffix}

    try:
        for hostname, log_name, raw_xml in events:
            parsed = _parse_event(raw_xml)
            if not parsed:
                continue
            line_cef = _parsed_to_cef(hostname, parsed, log_name)
            key = (_safe_filename(hostname), _safe_filename(log_name))
            if key not in state:
                state[key] = open_new(key, hostname, log_name)
            st = state[key]
            if _should_rotate(config, st["opened_at"], st["lines"]):
                st["f"].close()
                state[key] = open_new(key, hostname, log_name)
                st = state[key]
            if st["lines"] > 0:
                st["f"].write("\n")
            st["f"].write(line_cef)
            st["f"].flush()
            st["lines"] += 1
            count += 1
    finally:
        for st in state.values():
            st["f"].close()
    return count


def run_rolled_out(config: CollectorConfig) -> int:
    """
    Rolled-out: quando uso do disco >= threshold, exclui logs mais antigos (apenas em output_dir)
    em etapas (24h, 3h, 1h, 30min, tudo) até uso cair para target ou não haver mais arquivos.
    Retorna quantidade de arquivos removidos.
    """
    import shutil
    base = (config.output_dir or "").strip() or os.path.join(os.getcwd(), "logs")
    if not os.path.isdir(base):
        return 0
    try:
        usage = shutil.disk_usage(base)
    except OSError:
        return 0
    total, used = usage.total, usage.used
    if total == 0:
        return 0
    percent_used = 100.0 * used / total
    threshold = getattr(config, "disk_threshold_percent", 98.0) or 98.0
    target = getattr(config, "disk_target_percent", 80.0) or 80.0
    if percent_used < threshold:
        return 0
    tiers: List[int] = list(getattr(config, "retention_tiers_sec", (86400, 10800, 3600, 1800, 0)))
    if not tiers:
        tiers = [86400, 10800, 3600, 1800, 0]
    now = time.time()
    files_with_mtime: List[Tuple[str, float]] = []
    for root, _dirs, files in os.walk(base, topdown=False):
        for name in files:
            path = os.path.join(root, name)
            try:
                mtime = os.path.getmtime(path)
                files_with_mtime.append((path, mtime))
            except OSError:
                pass
    files_with_mtime.sort(key=lambda x: x[1])
    removed = 0
    for max_age_sec in tiers:
        if percent_used < target:
            break
        cutoff = now - max_age_sec
        for path, mtime in files_with_mtime:
            if mtime >= cutoff:
                continue
            try:
                if os.path.isfile(path):
                    os.unlink(path)
                    removed += 1
            except OSError:
                pass
        try:
            usage = shutil.disk_usage(base)
            percent_used = 100.0 * usage.used / usage.total if usage.total else 0
        except OSError:
            break
    return removed
