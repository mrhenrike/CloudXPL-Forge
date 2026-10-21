import glob as _glob
import hashlib
import json
import os
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests


# ─── Versão lida do arquivo VERSION (sem hardcode) ────────────────────────────
def _read_version() -> str:
    try:
        return (Path(__file__).resolve().parent / "VERSION").read_text(encoding="utf-8").strip()
    except Exception:
        return "unknown"

__version__ = _read_version()


def env(name: str, default: str = "") -> str:
    return (os.getenv(name, default) or "").strip()


# ─── Configuração ─────────────────────────────────────────────────────────────
BASE_URL     = env("S1_BASE_URL", "https://usea1-014.sentinelone.net/")
if not BASE_URL.endswith("/"):
    BASE_URL += "/"

API_VERSION  = env("S1_API_VERSION", "2.1")
TOKEN        = env("S1_API_TOKEN")

# Identificação do scope de coleta
SITE_NAME    = env("S1_SITE_NAME", "")           # label para logging
ACCOUNT_NAME = env("S1_ACCOUNT_NAME", "")         # label para logging
SITE_IDS     = [x.strip() for x in env("S1_SITE_IDS", "").split(",") if x.strip()]
GROUP_NAME   = env("S1_GROUP_NAME", "Default Group")
# GROUP_IDS: se preenchido usa direto; se vazio, resolve pelo nome via API no startup
GROUP_IDS    = [x.strip() for x in env("S1_GROUP_IDS", "").split(",") if x.strip()]

# Tipos de log a coletar: threats, activities, alerts (default: threats,activities)
_raw_log_types = env("S1_LOG_TYPES", "threats,activities")
LOG_TYPES = [x.strip().lower() for x in _raw_log_types.split(",") if x.strip()]

# Quantos dias anteriores buscar no primeiro run (0 = sem limite)
BACKFILL_DAYS = int(env("S1_BACKFILL_DAYS", "30"))

POLL_SECONDS    = int(env("S1_POLL_SECONDS", "60"))
RETENTION_DAYS  = int(env("S1_RETENTION_DAYS", "15"))
VERIFY_SSL      = env("S1_VERIFY_SSL", "true").lower() not in ("0", "false", "no")
STATE_FILE      = Path(env("S1_STATE_FILE", "/opt/safelabs/sentinelone/state.json"))
ENABLE_UDP      = env("S1_ENABLE_UDP", "false").lower() in ("1", "true", "yes", "on")
UDP_HOST        = env("S1_UDP_HOST", "127.0.0.1")
UDP_PORT        = int(env("S1_UDP_PORT", "1514"))
MAX_PAGES       = 50

_LOGSTASH_BASE_GLOB = "/Harpia/hin/docker-volumes/logstash-config-*"
_LOGSTASH_SUBDIR    = "logsource/sentinelone/api"
_FALLBACK_DIR       = "/Harpia/logsource/sentinelone/api"

# Mapa de endpoints por tipo de log
_LOG_TYPE_ENDPOINTS = {
    "threats":    f"web/api/v{API_VERSION}/threats",
    "activities": f"web/api/v{API_VERSION}/activities",
    "alerts":     f"web/api/v{API_VERSION}/cloud-detection/alerts",
}

# ─── Diretório de saída ────────────────────────────────────────────────────────
def _resolve_out_dir() -> Path:
    raw = env("S1_OUTPUT_DIR")
    if raw and "*" not in raw:
        p = Path(raw)
        p.mkdir(parents=True, exist_ok=True)
        return p
    base_pattern = _LOGSTASH_BASE_GLOB if not raw else raw
    bases = sorted(_glob.glob(base_pattern))
    if bases:
        resolved = Path(bases[0]) / _LOGSTASH_SUBDIR
        resolved.mkdir(parents=True, exist_ok=True)
        print(f"[config] S1_OUTPUT_DIR resolvido: {resolved}", flush=True)
        return resolved
    fallback = Path(_FALLBACK_DIR)
    fallback.mkdir(parents=True, exist_ok=True)
    print(f"[config] Usando fallback: {fallback}", flush=True)
    return fallback


OUT_DIR = _resolve_out_dir()


# ─── Rotação de arquivos ───────────────────────────────────────────────────────
def rotate_old_files(directory: Path, retention_days: int, patterns: list | None = None) -> int:
    if retention_days <= 0:
        return 0
    cutoff = time.time() - (retention_days * 86400)
    removed = 0
    for pattern in (patterns or ["*.jsonl"]):
        for f in directory.glob(pattern):
            try:
                if f.stat().st_mtime < cutoff:
                    f.unlink()
                    print(f"[rotate] Removido (>{retention_days}d): {f.name}", flush=True)
                    removed += 1
            except OSError as exc:
                print(f"[rotate] Erro ao remover {f}: {exc}", flush=True)
    return removed


# ─── Helpers ──────────────────────────────────────────────────────────────────
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_state() -> dict:
    if not STATE_FILE.exists():
        return {"sent_ids": []}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {"sent_ids": []}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")


def stable_id(event_type: str, item: dict) -> str:
    raw_id = str(item.get("id") or item.get("threatInfo", {}).get("threatId") or "").strip()
    if raw_id:
        return f"{event_type}:{raw_id}"
    payload = json.dumps(item, ensure_ascii=False, sort_keys=True)
    return f"{event_type}:sha1:{hashlib.sha1(payload.encode('utf-8')).hexdigest()}"


def append_jsonl(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")


def send_udp(payload: dict) -> None:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(data, (UDP_HOST, UDP_PORT))
    finally:
        sock.close()


# ─── API ──────────────────────────────────────────────────────────────────────
def s1_get(path: str, params: dict) -> tuple:
    headers = {"Authorization": f"ApiToken {TOKEN}", "Content-Type": "application/json"}
    r = requests.get(
        f"{BASE_URL}{path.lstrip('/')}",
        headers=headers,
        params=params,
        timeout=40,
        verify=VERIFY_SSL,
    )
    try:
        body = r.json()
    except Exception:
        body = {"raw": (r.text or "")[:1000]}
    return r.status_code, body


def resolve_group_ids() -> list:
    """
    Resolve os GROUP_IDS a partir do GROUP_NAME via API.
    Se GROUP_IDS já estiver configurado, usa diretamente.
    """
    if GROUP_IDS:
        print(f"[config] Usando GROUP_IDS configurados: {GROUP_IDS}", flush=True)
        return GROUP_IDS
    if not GROUP_NAME:
        return []
    params = {"limit": 50}
    if SITE_IDS:
        params["siteIds"] = ",".join(SITE_IDS)
    status, body = s1_get(f"web/api/v{API_VERSION}/groups", params)
    if status != 200:
        print(f"[config] AVISO: falha ao listar grupos (HTTP {status}). Sem filtro de grupo.", flush=True)
        return []
    groups = body.get("data", [])
    matched = [g["id"] for g in groups if g.get("name", "").lower() == GROUP_NAME.lower()]
    if matched:
        print(f"[config] Grupo '{GROUP_NAME}' resolvido → IDs: {matched}", flush=True)
    else:
        available = [g.get("name") for g in groups]
        print(f"[config] AVISO: Grupo '{GROUP_NAME}' não encontrado. Disponíveis: {available}", flush=True)
        print(f"[config] Configure S1_GROUP_IDS manualmente ou ajuste S1_GROUP_NAME.", flush=True)
    return matched


def validate_config(resolved_group_ids: list) -> None:
    """Valida token, URL, site e permissões antes de iniciar a coleta."""
    if not TOKEN:
        raise SystemExit("[FATAL] S1_API_TOKEN não definido.")
    if not BASE_URL.startswith(("http://", "https://")):
        raise SystemExit("[FATAL] S1_BASE_URL inválida.")
    if not SITE_IDS:
        raise SystemExit("[FATAL] S1_SITE_IDS não definido. Configure pelo menos um Site ID.")

    # Verificar se os sites existem e o token tem acesso
    status, body = s1_get(f"web/api/v{API_VERSION}/sites", {
        "siteIds": ",".join(SITE_IDS),
        "limit": 10,
        "state": "active",
    })
    if status != 200:
        raise SystemExit(f"[FATAL] Falha ao validar sites (HTTP {status}): {body}")

    sites = body.get("data", {}).get("sites", [])
    if not sites:
        raise SystemExit(
            f"[FATAL] Site(s) {SITE_IDS} não encontrado(s) ou sem permissão. "
            f"Verifique S1_SITE_IDS e o escopo do API token."
        )

    for s in sites:
        print(
            f"[validate] ✓ Site: '{s.get('name')}' "
            f"(id={s.get('id')}, account='{s.get('accountName')}', state={s.get('state')})",
            flush=True,
        )

    if GROUP_NAME and not resolved_group_ids:
        print(f"[validate] ⚠ Grupo '{GROUP_NAME}' não resolvido — coletando sem filtro de grupo.", flush=True)

    invalid = [lt for lt in LOG_TYPES if lt not in _LOG_TYPE_ENDPOINTS]
    if invalid:
        raise SystemExit(f"[FATAL] LOG_TYPES inválidos: {invalid}. Válidos: {list(_LOG_TYPE_ENDPOINTS.keys())}")

    print(f"[validate] Log types: {LOG_TYPES}", flush=True)
    print(f"[validate] Backfill: últimos {BACKFILL_DAYS} dias (0=sem limite)", flush=True)


# ─── Coleta ───────────────────────────────────────────────────────────────────
def get_backfill_since() -> str | None:
    """Retorna timestamp ISO8601 para limitar o backfill inicial. None = sem limite."""
    if BACKFILL_DAYS <= 0:
        return None
    dt = datetime.now(timezone.utc) - timedelta(days=BACKFILL_DAYS)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def fetch_all_pages(api_path: str, base_params: dict, group_ids: list, since: str | None) -> list:
    """Busca todos os eventos paginando com cursor. Aplica filtros de site, grupo e data."""
    all_items = []
    params = dict(base_params)
    if SITE_IDS:
        params["siteIds"] = ",".join(SITE_IDS)
    if group_ids:
        params["groupIds"] = ",".join(group_ids)
    if since:
        params["createdAt__gt"] = since

    for _ in range(MAX_PAGES):
        status, body = s1_get(api_path, params)
        if status != 200:
            print(f"[fetch] HTTP {status} em {api_path}: {str(body)[:200]}", flush=True)
            break
        items = body.get("data", [])
        if not isinstance(items, list):
            break
        all_items.extend(items)
        cursor = body.get("pagination", {}).get("nextCursor")
        if not cursor:
            break
        params["cursor"] = cursor

    return all_items


def collect_once(state: dict, group_ids: list) -> dict:
    sent_ids    = set(state.get("sent_ids", []))
    is_backfill = not state.get("backfill_done", False)
    since       = get_backfill_since() if is_backfill else None
    new_count   = 0

    base_sort = {"limit": 200, "sortBy": "createdAt", "sortOrder": "desc"}

    for log_type in LOG_TYPES:
        api_path = _LOG_TYPE_ENDPOINTS[log_type]

        if is_backfill:
            items = fetch_all_pages(api_path, dict(base_sort), group_ids, since)
        else:
            # Polling incremental: apenas uma página com filtros de site/grupo
            params = dict(base_sort)
            if SITE_IDS:
                params["siteIds"] = ",".join(SITE_IDS)
            if group_ids:
                params["groupIds"] = ",".join(group_ids)
            status, body = s1_get(api_path, params)
            if status != 200:
                append_jsonl(OUT_DIR / "errors.jsonl", {
                    "@timestamp": now_iso(), "source": "sentinelone_api",
                    "log_type": log_type, "status": status, "error": body,
                })
                continue
            items = body.get("data", [])
            if not isinstance(items, list):
                continue

        for item in reversed(items):
            ev_id = stable_id(log_type, item)
            if ev_id in sent_ids:
                continue

            wrapper = {
                "@timestamp":   now_iso(),
                "source":       "sentinelone_api",
                "event_type":   log_type,
                "site_name":    SITE_NAME,
                "site_ids":     SITE_IDS,
                "account_name": ACCOUNT_NAME,
                "group_name":   GROUP_NAME,
                "group_ids":    group_ids,
                "event_id":     ev_id,
                "payload":      item,
            }
            if ENABLE_UDP:
                send_udp(wrapper)
            append_jsonl(OUT_DIR / f"{log_type}.jsonl", wrapper)
            sent_ids.add(ev_id)
            new_count += 1

    # Limitar cache de IDs para evitar crescimento ilimitado
    if len(sent_ids) > 10000:
        sent_ids = set(list(sent_ids)[-10000:])

    new_state = {
        "sent_ids":         list(sent_ids),
        "last_run":         now_iso(),
        "last_new_events":  new_count,
        "backfill_done":    True,
    }
    save_state(new_state)
    return new_state


# ─── Entrypoint ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    resolved_group_ids = resolve_group_ids()
    validate_config(resolved_group_ids)

    scope = f"site={SITE_NAME or SITE_IDS} | group={GROUP_NAME or 'all'} | types={LOG_TYPES}"
    print(
        f"[s1-collector] v{__version__} | {scope} | "
        f"backfill={BACKFILL_DAYS}d | poll={POLL_SECONDS}s | out={OUT_DIR} | pid={os.getpid()}",
        flush=True,
    )

    state = load_state()
    while True:
        try:
            rotated = rotate_old_files(OUT_DIR, RETENTION_DAYS, patterns=["*.jsonl"])
            if rotated:
                print(f"[rotate] {rotated} arquivo(s) removido(s) (retenção={RETENTION_DAYS}d)", flush=True)
            state = collect_once(state, resolved_group_ids)
            print(
                f"[{state['last_run']}] done | new={state['last_new_events']} "
                f"| tracked={len(state['sent_ids'])}",
                flush=True,
            )
        except Exception as exc:
            append_jsonl(
                OUT_DIR / "errors.jsonl",
                {"@timestamp": now_iso(), "source": "sentinelone_api", "error": str(exc)},
            )
            print(f"[{now_iso()}] ERROR: {exc}", flush=True)
        time.sleep(POLL_SECONDS)
