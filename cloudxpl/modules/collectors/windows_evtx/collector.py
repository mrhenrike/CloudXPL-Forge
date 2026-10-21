"""
Coletor WinRM: conecta ao host Windows, executa Get-WinEvent (PowerShell) e retorna eventos em XML.
Suporta certificados (CA, client cert+key, senha opcional da key), event_filter, override_channels,
max_duration_poll, coleta de todos os logs do Event Viewer e bookmark para coleta incremental.
"""
import json
import os
from dataclasses import replace
from typing import Any, Dict, Generator, List, Optional, Tuple
import winrm

from .config import TargetHost, AuthMethod, CollectorConfig, Transport
from .winevent_parser import parse_event_xml, get_time_created_from_raw_xml
from .channel_parser import channels_from_config
from .cert_utils import resolve_client_key_path
from .etc_hosts import ensure_etc_hosts_entry

# Delimitador para separar eventos XML no stdout (sem newline para evitar `n no PowerShell)
EVENT_DELIM = "###WINEVENT###"


def _decode_winrm_stdout(data: bytes) -> str:
    """
    Decode do stdout do PowerShell (WinRM). Windows pode enviar UTF-16 LE (com BOM)
    ou UTF-8 (sem BOM). Sem BOM, tentar UTF-8 primeiro: UTF-16 LE decodifica quase
    qualquer par de bytes sem erro, o que gera mojibake quando o host envia UTF-8.
    """
    if not data:
        return ""
    # BOM UTF-16 LE (ff fe) ou UTF-16 BE (fe ff)
    if data[:2] == b"\xff\xfe":
        return data.decode("utf-16-le", errors="replace")
    if data[:2] == b"\xfe\xff":
        return data.decode("utf-16-be", errors="replace")
    # Sem BOM: UTF-8 primeiro (mais restritivo); depois UTF-16
    for enc in ("utf-8", "utf-16-le", "utf-16"):
        try:
            return data.decode(enc, errors="strict")
        except (UnicodeDecodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace")

# PowerShell: lista todos os logs do Event Viewer (para collect_all_logs)
PS_LIST_ALL_LOGS = """
$ErrorActionPreference = 'Stop'
(Get-WinEvent -ListLog *).LogName
""".strip()


def _load_bookmarks(bookmark_path: Optional[str]) -> Dict[str, str]:
    """Carrega bookmarks (hostname|channel -> last TimeCreated SystemTime). Retorna dict vazio se falhar."""
    if not bookmark_path or not os.path.isfile(bookmark_path):
        return {}
    try:
        with open(bookmark_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return dict(data) if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_bookmarks(bookmark_path: Optional[str], bookmarks: Dict[str, str]) -> None:
    """Persiste bookmarks. Cria diretório do path se necessário."""
    if not bookmark_path:
        return
    try:
        base = os.path.dirname(bookmark_path)
        if base:
            os.makedirs(base, exist_ok=True)
        with open(bookmark_path, "w", encoding="utf-8") as f:
            json.dump(bookmarks, f, indent=0)
    except Exception:
        pass


def _run_ps(session, script: str):
    """
    Executa PS via pwsh.exe (PS7) com caminho absoluto.
    Bypassa wrapper powershell.exe que injeta %%* literal no WinRM (bug cmd batch).
    Fallback para PS5 e depois run_ps se ambos falharem.
    """
    from base64 import b64encode
    enc = b64encode(script.encode("utf_16_le")).decode("ascii")
    PS_PATHS = [
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Program Files\PowerShell\6\pwsh.exe",
    ]
    for ps_path in PS_PATHS:
        try:
            r = session.run_cmd(
                "cmd.exe",
                ["/D", "/c", f'"{ps_path}" -NonInteractive -NoProfile -EncodedCommand {enc}'],
            )
            # Sucesso se status_code==0 ou se stderr não tem o erro de %*
            if r.status_code == 0:
                return r
            err_str = (r.std_err or b"").decode("utf-8", errors="replace")
            if "%" not in err_str:
                return r  # retorna mesmo com erro (erro do PS, não do wrapper)
        except Exception:
            continue
    # Fallback: tenta run_ps padrão
    return session.run_ps(script)



def _build_ps_collect(
    log_name: str,
    max_events: int,
    event_ids: Optional[List[int]] = None,
    filter_xpath: Optional[str] = None,
    time_created_after: Optional[str] = None,
) -> str:
    """
    Gera script PowerShell: Get-WinEvent -LogName X -MaxEvents N [-Id ...] [-FilterXPath ...].
    filter_xpath: opcional, ex: "*[System[(EventID=4624)]]"
    time_created_after: opcional, SystemTime (ex: 2026-03-09T12:00:00.000Z); gera FilterXPath para eventos após essa data.
    """
    delim = EVENT_DELIM
    id_part = ""
    if event_ids:
        id_list = ",".join(str(i) for i in event_ids)
        id_part = f" -Id {id_list}"
    xpath_part = ""
    if filter_xpath and filter_xpath.strip():
        xpath_esc = filter_xpath.replace("'", "''")
        xpath_part = f" -FilterXPath '{xpath_esc}'"
    elif time_created_after and time_created_after.strip():
        # Coleta incremental: apenas eventos com TimeCreated > time_created_after
        xpath_esc = f"*[System[TimeCreated[@SystemTime>'{time_created_after.strip()}']]]".replace("'", "''")
        xpath_part = f" -FilterXPath '{xpath_esc}'"
    # -LogName e -MaxEvents sempre; -Id e -FilterXPath opcionais
    cmd = f"Get-WinEvent -LogName '{log_name}' -MaxEvents {max_events}{id_part}{xpath_part}"
    return f"""
$ErrorActionPreference = 'Stop'
try {{
  {cmd} | ForEach-Object {{ $_.ToXml() }} | ForEach-Object -Begin {{ $first = $true }} -Process {{
    if (-not $first) {{ Write-Output '{delim}' }}
    $first = $false
    Write-Output $_
  }}
}} catch {{
  if ($_.Exception.Message -notmatch 'No events were found') {{ throw $_ }}
}}
""".strip()


def _session_for_target(
    target: TargetHost,
    username: str,
    password: str,
    verify_ssl: bool = False,
    operation_timeout_sec: int = 120,
    read_timeout_sec: int = 120,
    ca_trust_path: Optional[str] = None,
    client_cert_pem: Optional[str] = None,
    client_cert_key_pem: Optional[str] = None,
    client_cert_key_password: Optional[str] = None,
) -> Tuple[winrm.Session, Optional[str]]:
    """
    Cria sessão WinRM. Retorna (session, path_temp_key) onde path_temp_key deve ser
    removido pelo caller após o uso (quando a chave foi descriptografada com senha).
    """
    endpoint = target.endpoint()
    auth_val = target.auth.value if isinstance(target.auth, AuthMethod) else target.auth
    cert_pem = client_cert_pem or target.client_cert_pem
    cert_key = client_cert_key_pem or target.client_cert_key_pem
    key_pass = client_cert_key_password or target.client_cert_key_password
    ca_path = ca_trust_path or target.ca_trust_path
    temp_key_path: Optional[str] = None

    if auth_val == "certificate":
        transport = "certificate"
        if not cert_pem or not cert_key:
            raise ValueError("Auth certificate exige client_cert_pem e client_cert_key_pem")
        key_to_use, temp_key_path = resolve_client_key_path(cert_key, key_pass)
        auth_tuple = (username or "", password or "")
        read_sec = max(read_timeout_sec, operation_timeout_sec + 10)
        kwargs = dict(
            target=endpoint,
            auth=auth_tuple,
            transport=transport,
            cert_pem=cert_pem,
            cert_key_pem=key_to_use,
            server_cert_validation="validate" if verify_ssl else "ignore",
            operation_timeout_sec=operation_timeout_sec,
            read_timeout_sec=read_sec,
        )
        if verify_ssl and ca_path:
            kwargs["ca_trust_path"] = ca_path
        return (winrm.Session(**kwargs), temp_key_path)
    transport = "ntlm" if auth_val == "negotiate" else auth_val
    read_sec = max(read_timeout_sec, operation_timeout_sec + 10)
    kwargs = dict(
        target=endpoint,
        auth=(username, password),
        transport=transport,
        server_cert_validation="validate" if verify_ssl else "ignore",
        operation_timeout_sec=operation_timeout_sec,
        read_timeout_sec=read_sec,
    )
    if verify_ssl and ca_path:
        kwargs["ca_trust_path"] = ca_path
    return (winrm.Session(**kwargs), None)


def _get_all_log_names_from_host(session: winrm.Session, hostname: str) -> List[str]:
    """Executa Get-WinEvent -ListLog * no host e retorna lista de nomes de log."""
    r = _run_ps(session, PS_LIST_ALL_LOGS)
    if r.status_code != 0:
        raise RuntimeError((r.std_err or b"").decode("utf-8", errors="replace") or "Falha ao listar logs")
    out = (r.std_out or b"").decode("utf-16-le", errors="replace")
    return [s.strip() for s in out.splitlines() if s.strip()]


def collect_from_host(
    target: TargetHost,
    username: str,
    password: str,
    log_names: List[str],
    max_events_per_log: int,
    verify_ssl: bool = False,
    max_duration_poll: int = 120,
    override_channels: Optional[str] = None,
    event_filter: Optional[str] = None,
    collect_all_logs: bool = False,
    ca_trust_path: Optional[str] = None,
    client_cert_pem: Optional[str] = None,
    client_cert_key_pem: Optional[str] = None,
    client_cert_key_password: Optional[str] = None,
    raw_output: bool = False,
    bookmark_path: Optional[str] = None,
    backfill_since: Optional[str] = None,
) -> Generator[Tuple[str, str, Any], None, None]:
    """
    Conecta ao host, coleta eventos e produz (hostname, log_name, event_dict ou raw_xml).
    Se raw_output=True, o terceiro elemento é o XML bruto (str); senão é o dict parseado.
    Para hosts fora do domínio (target.ip definido), garante entrada em /etc/hosts antes de conectar.
    Se bookmark_path estiver definido, usa coleta incremental (apenas eventos após último TimeCreated).
    """
    bookmarks: Dict[str, str] = _load_bookmarks(bookmark_path)
    max_time_by_key: Dict[str, str] = {}
    if target.ip:
        ok, msg = ensure_etc_hosts_entry(target.ip, target.hostname)
        if not ok:
            # Fallback: conectar pelo IP (sem escrever /etc/hosts)
            target = replace(target, hostname=target.ip)
    verify = target.validate_server if target.validate_server is not None else verify_ssl
    session, temp_key_path = _session_for_target(
        target, username, password, verify,
        operation_timeout_sec=max_duration_poll,
        read_timeout_sec=max_duration_poll + 30,
        ca_trust_path=ca_trust_path,
        client_cert_pem=client_cert_pem,
        client_cert_key_pem=client_cert_key_pem,
        client_cert_key_password=client_cert_key_password,
    )
    try:
        if collect_all_logs:
            log_names = _get_all_log_names_from_host(session, target.hostname)
        channels = channels_from_config(override_channels or target.override_channels, log_names)
        for log_name, event_ids in channels:
            bookmark_key = f"{target.hostname}|{log_name}"
            last_time = bookmarks.get(bookmark_key)
            # Se não há bookmark (primeiro run) e backfill_since foi definido,
            # usa como ponto de partida para não coletar histórico ilimitado.
            if last_time is None and backfill_since:
                last_time = backfill_since
            ps = _build_ps_collect(
                log_name,
                max_events_per_log,
                event_ids=event_ids,
                filter_xpath=event_filter or target.event_filter,
                time_created_after=last_time,
            )
            try:
                r = _run_ps(session, ps)
                stderr_raw = (r.std_err or b"").decode("utf-8", errors="replace")
                # CLIXML é output de progresso do PowerShell — não é erro real
                is_clixml = stderr_raw.strip().startswith("#< CLIXML")
                if r.status_code != 0 and not is_clixml:
                    if "No events were found" not in stderr_raw and stderr_raw.strip():
                        raise RuntimeError(f"PowerShell error: {stderr_raw}")
                    continue
                stdout = _decode_winrm_stdout(r.std_out or b"")
            except Exception as e:
                raise RuntimeError(f"WinRM host {target.hostname} log {log_name}: {e}") from e

            # Aceitar tanto delimitador novo (###WINEVENT###) quanto antigo (newline ou `n)
            for part in stdout.replace("`n---WINEVENT---`n", EVENT_DELIM).replace("\n---WINEVENT---\n", EVENT_DELIM).split(EVENT_DELIM):
                raw_xml = part.strip()
                if not raw_xml:
                    continue
                # Normalizar para UTF-8 limpo (evita mojibake)
                raw_xml = raw_xml.encode("utf-8", errors="replace").decode("utf-8")
                tc = get_time_created_from_raw_xml(raw_xml)
                if tc:
                    cur = max_time_by_key.get(bookmark_key, "")
                    if tc > cur:
                        max_time_by_key[bookmark_key] = tc
                if raw_output:
                    yield target.hostname, log_name, raw_xml
                else:
                    try:
                        ev = parse_event_xml(raw_xml)
                        yield target.hostname, log_name, ev
                    except Exception:
                        yield target.hostname, log_name, {"_raw_xml": raw_xml, "_parse_error": True}
            # Atualizar bookmark ao final de cada canal
            if bookmark_path and bookmark_key in max_time_by_key:
                bookmarks[bookmark_key] = max_time_by_key[bookmark_key]
                _save_bookmarks(bookmark_path, bookmarks)
    finally:
        if temp_key_path and os.path.isfile(temp_key_path):
            try:
                os.unlink(temp_key_path)
            except Exception:
                pass


def collect_all(
    config: CollectorConfig,
    raw_output: bool = False,
) -> Generator[Tuple[str, str, Any], None, None]:
    """Itera sobre todos os targets e produz (hostname, log_name, event_dict ou raw_xml)."""
    from datetime import datetime, timedelta, timezone as _tz
    backfill_days = getattr(config, "backfill_days", 30)
    if backfill_days > 0:
        _since = (datetime.now(_tz.utc) - timedelta(days=backfill_days)).strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    else:
        _since = None  # sem limite

    for target in config.targets:
        if not target.enabled:
            continue
        yield from collect_from_host(
            target,
            config.username,
            config.password,
            config.log_names,
            config.max_events_per_log,
            config.verify_ssl,
            config.max_duration_poll,
            event_filter=None,
            override_channels=None,
            collect_all_logs=config.collect_all_logs,
            ca_trust_path=config.ca_trust_path,
            client_cert_pem=config.client_cert_pem,
            client_cert_key_pem=config.client_cert_key_pem,
            client_cert_key_password=config.client_cert_key_password,
            raw_output=raw_output,
            bookmark_path=getattr(config, "bookmark_path", None),
            backfill_since=_since,
        )
