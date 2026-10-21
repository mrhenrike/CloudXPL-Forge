#!/usr/bin/env python3
"""
Mantis Collector — coleta RISCOS e EVENTOS de forma independente via API Mantis 3.

Fluxo riscos:
  GET /customer/risks (paginado por page/page_size)
  → dedupe por ID → append mantis-risks.jsonl → estado local

Fluxo eventos:
  GET /customer/events (cursor-based, Elasticsearch search_after)
  → dedupe por ID → append mantis-events.jsonl → estado local
  Os dois coletores são completamente independentes entre si.

Uso:
  python3 mantis_collect_risks.py

Instalação:
  sudo bash install.sh
"""
from __future__ import annotations

import glob as _glob
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path


def _read_version() -> str:
    try:
        return (Path(__file__).resolve().parent / "VERSION").read_text(encoding="utf-8").strip()
    except Exception:
        return "unknown"


__version__ = _read_version()


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

def rotate_old_files(directory: Path, retention_days: int, patterns: list[str] | None = None) -> int:
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


def load_dotenv(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.is_file():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def load_config(install_dir: Path | None = None) -> dict[str, str]:
    root = install_dir or Path(__file__).resolve().parent
    cfg = load_dotenv(root / ".env")
    for key in (
        "MANTIS_GATEWAY_BASE_URL",
        "MANTIS_BEARER_TOKEN",
        "MANTIS_COLLECTOR_OUT_DIR",
        "MANTIS_JSONL_BASENAME",
        "MANTIS_EVENTS_JSONL_BASENAME",
        "MANTIS_STATE_PATH",
        "MANTIS_RISKS_PAGE_SIZE",
        "MANTIS_POLL_SECONDS",
        "MANTIS_RUN_ONCE",
        "MANTIS_USER_EMAIL",
        # coleta
        "MANTIS_COLLECT_RISKS",
        "MANTIS_COLLECT_EVENTS",
        # categorias de riscos (server-side filter)
        "MANTIS_RISK_CATEGORIES",
        "MANTIS_EVENT_CATEGORIES",      # alias legado → MANTIS_RISK_CATEGORIES
        # categorias de eventos (client-side filter)
        "MANTIS_EVENT_FILTER_CATEGORIES",
        # modo e threads
        "MANTIS_SAVE_MODE",
        "MANTIS_DETAIL_THREADS",
        "MANTIS_CREDENTIAL_KEYWORDS",
        "MANTIS_PHISHING_KEYWORDS",
        # retenção e eventos
        "MANTIS_RETENTION_DAYS",
        "MANTIS_EVENTS_MAX_PAGES",
        "MANTIS_EVENTS_FETCH_DETAIL",
        "MANTIS_BACKFILL_DAYS",
    ):
        v = os.environ.get(key)
        if v and v.strip():
            cfg[key] = v.strip()

    # Backward compat: MANTIS_EVENT_CATEGORIES é alias de MANTIS_RISK_CATEGORIES
    if "MANTIS_RISK_CATEGORIES" not in cfg and "MANTIS_EVENT_CATEGORIES" in cfg:
        cfg["MANTIS_RISK_CATEGORIES"] = cfg["MANTIS_EVENT_CATEGORIES"]

    return cfg


# ---------------------------------------------------------------------------
# Path dinâmico do volume Logstash
# ---------------------------------------------------------------------------

_LOGSTASH_BASE_GLOB = "/Harpia/hin/docker-volumes/logstash-config-*"
_LOGSTASH_SUBDIR    = "logsource/mantis"
_FALLBACK_DIR       = "/Harpia/logsource/mantis"


def _resolve_out_dir(raw: str | None) -> Path:
    """
    Resolve e CRIA o diretório de saída.
    - raw sem glob  → usa o caminho literalmente e cria se não existir.
    - raw com glob  → expande e usa o primeiro match + cria.
    - raw vazio/None → descobre automaticamente o volume logstash-config-*
                       e acrescenta _LOGSTASH_SUBDIR; cria tudo se não existir.
    """
    if raw and "*" not in raw:
        p = Path(raw)
        p.mkdir(parents=True, exist_ok=True)
        return p

    # Glob sobre a base (logstash-config-*) para não falhar quando
    # o subdiretório ainda não existe dentro do volume.
    base_pattern = _LOGSTASH_BASE_GLOB if not raw else raw
    bases = sorted(_glob.glob(base_pattern))
    if bases:
        resolved = Path(bases[0]) / _LOGSTASH_SUBDIR
        resolved.mkdir(parents=True, exist_ok=True)
        print(f"[config] out_dir resolvido e criado: {resolved}", flush=True)
        return resolved

    fallback = Path(_FALLBACK_DIR)
    fallback.mkdir(parents=True, exist_ok=True)
    print(f"[config] Nenhum volume logstash-config-* encontrado; usando fallback: {fallback}", flush=True)
    return fallback


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_bearer(token: str) -> str:
    t = (token or "").strip()
    return t[7:].strip() if t.lower().startswith("bearer ") else t


def stable_id(item: dict) -> str:
    for k in ("id", "risk_id", "event_id"):
        v = item.get(k)
        if v is not None and str(v).strip():
            return str(v)
    return hashlib.sha256(
        json.dumps(item, sort_keys=True, default=str, ensure_ascii=False).encode()
    ).hexdigest()[:24]


DOMAIN_STYLE_PATTERNS = (
    re.compile(r"^[^\\/\s]+\\[^\\/\s]+$"),
    re.compile(r"^[^@\s]+@[^@\s]+$"),
)

CREDENTIAL_DEFAULT_KEYWORDS = (
    "credential", "credentials", "dataleak", "stealer", "infostealer", "malware",
    "azure", "microsoft", "microsoftonline", "activedirectory", "active directory",
    "okta", "iam", "pam", "sso", "adfs", "entra", "hudsonrock",
    "password", "senha", "login",
)

PHISHING_DEFAULT_KEYWORDS = (
    "phishing", "phish", "spoof", "impersonation", "brand abuse",
    "fake login", "credential harvesting",
)


def _load_keywords(cfg_value: str | None, defaults: tuple[str, ...]) -> tuple[str, ...]:
    if not cfg_value or not cfg_value.strip():
        return defaults
    vals = [x.strip().lower() for x in cfg_value.split(",") if x.strip()]
    return tuple(vals) if vals else defaults


def _match_domain_style(value: str) -> bool:
    v = (value or "").strip()
    return any(p.match(v) for p in DOMAIN_STYLE_PATTERNS) if v else False


def _extract_credential_identifiers(detail: dict | None) -> list[str]:
    if not isinstance(detail, dict):
        return []
    src = detail.get("event_details", {}).get("_source", {}).get("details", {})
    out: list[str] = []
    for c in (src.get("credentials") or []):
        if isinstance(c, dict):
            u = str(c.get("username") or "").strip()
            if _match_domain_style(u):
                out.append(u)
    ce = src.get("credential_enrichment") or {}
    if isinstance(ce, dict):
        u = str(ce.get("username") or "").strip()
        if _match_domain_style(u):
            out.append(u)
    seen: set[str] = set()
    return [x for x in out if not (x.lower() in seen or seen.add(x.lower()))]  # type: ignore[func-returns-value]


def _extract_any_usernames(detail: dict | None) -> list[str]:
    if not isinstance(detail, dict):
        return []
    src = detail.get("event_details", {}).get("_source", {}).get("details", {})
    out: list[str] = []
    for c in (src.get("credentials") or []):
        if isinstance(c, dict):
            u = str(c.get("username") or "").strip()
            if u:
                out.append(u)
    ce = src.get("credential_enrichment") or {}
    if isinstance(ce, dict):
        u = str(ce.get("username") or "").strip()
        if u:
            out.append(u)
    seen: set[str] = set()
    return [x for x in out if not (x.lower() in seen or seen.add(x.lower()))]  # type: ignore[func-returns-value]


def _extract_url_sources(detail: dict | None) -> list[str]:
    if not isinstance(detail, dict):
        return []
    src = detail.get("event_details", {}).get("_source", {}).get("details", {})
    out: list[str] = []
    for c in (src.get("credentials") or []):
        if isinstance(c, dict):
            u = str(c.get("url_source") or "").strip()
            if u:
                out.append(u)
    ce = src.get("credential_enrichment") or {}
    if isinstance(ce, dict):
        u = str(ce.get("url_source") or "").strip()
        if u:
            out.append(u)
    seen: set[str] = set()
    return [x for x in out if not (x.lower() in seen or seen.add(x.lower()))]  # type: ignore[func-returns-value]


def _risk_text_blob(risk: dict, detail: dict | None) -> str:
    chunks: list[str] = []
    if isinstance(risk, dict):
        chunks.append(json.dumps(risk, ensure_ascii=False, sort_keys=True))
    if isinstance(detail, dict):
        chunks.append(json.dumps(detail, ensure_ascii=False, sort_keys=True))
    return " ".join(chunks).lower()


def _keyword_hits(text: str, keywords: tuple[str, ...]) -> list[str]:
    return [k for k in keywords if k in text]


def _detect_risk_signals(risk, detail, credential_keywords, phishing_keywords) -> dict:
    category = str(risk.get("event_category") or "").strip().lower()
    identifiers    = _extract_credential_identifiers(detail)
    usernames_any  = _extract_any_usernames(detail)
    url_sources    = _extract_url_sources(detail)
    text_blob      = _risk_text_blob(risk, detail)
    credential_hits = _keyword_hits(text_blob, credential_keywords)
    phishing_hits   = _keyword_hits(text_blob, phishing_keywords)
    is_phishing = (category == "phishing") or bool(phishing_hits)
    idp_hits = [h for h in credential_hits if h in {
        "azure", "microsoft", "microsoftonline", "okta", "iam", "pam",
        "active directory", "activedirectory", "sso", "adfs", "entra",
    }]
    stealer_hits = [h for h in credential_hits if h in {"stealer", "infostealer", "malware", "hudsonrock"}]
    corporate_likely = bool(usernames_any) and (bool(idp_hits) or bool(stealer_hits))
    if not corporate_likely:
        for u in url_sources:
            if any(x in u.lower() for x in ("login.microsoftonline.com", "okta", "adfs", "sso", "azure")) and usernames_any:
                corporate_likely = True
                break
    is_credential = bool(identifiers) or ("dataleak" in category) or bool(credential_hits) or corporate_likely
    reason = ("phishing_signal" if is_phishing
              else "corporate_likely_credentials" if corporate_likely
              else "credential_signal" if is_credential else None)
    return {
        "is_phishing": is_phishing,
        "is_credential": is_credential,
        "reason": reason,
        "matched_identifiers": identifiers,
        "matched_usernames": usernames_any[:20],
        "url_sources": url_sources[:20],
        "corporate_likely": corporate_likely,
        "credential_keywords": credential_hits[:20],
        "phishing_keywords": phishing_hits[:20],
    }


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

def load_state(path: Path) -> tuple[set[str], list[str]]:
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            ids = [str(x) for x in data.get("seen_ids", [])]
            return set(ids), ids
        except (json.JSONDecodeError, OSError):
            pass
    return set(), []


def save_state(path: Path, seen_order: list[str], cap: int = 200_000) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({
            "seen_ids":  seen_order[-cap:],
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }, ensure_ascii=False),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# API — Riscos
# ---------------------------------------------------------------------------

def fetch_risks_page(base, token, page, page_size, categories, since_date: str | None = None, timeout=120) -> dict:
    params: list[tuple[str, str]] = [("page", str(page)), ("page_size", str(page_size))]
    for c in categories:
        if c := c.strip():
            params.append(("event_category", c))
    if since_date:
        params.append(("created_at__gte", since_date))
    url = f"{base}/customer/risks?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def fetch_risk_detail(base, token, risk_id, timeout=90) -> dict:
    url = f"{base}/customer/risks/{risk_id}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


# ---------------------------------------------------------------------------
# API — Eventos
# ---------------------------------------------------------------------------

def fetch_events_page(base, token, cursor=None, timeout=30) -> dict:
    """
    GET /customer/events — cursor-based (Elasticsearch search_after).
    cursor: valor de next_cursor da página anterior, ou None para primeira página.
    Retorna dict com 'events' (list) e 'next_cursor' (list ou None).
    """
    params = ""
    if cursor is not None:
        params = "?cursor=" + urllib.parse.quote(json.dumps(cursor), safe="")
    url = f"{base}/customer/events{params}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


def fetch_event_detail(base, token, event_id, timeout=30) -> dict:
    """GET /customer/events/{event_id} — detalhe enriquecido de um evento."""
    url = f"{base}/customer/events/{event_id}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))


# ---------------------------------------------------------------------------
# Builders de eventos JSONL
# ---------------------------------------------------------------------------

def build_risk_record(risk, user_email, risk_detail=None, filter_reason=None,
                      matched_identifiers=None, signals=None) -> dict:
    rec = {
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "collector":  "mantis_risks",
        "datasource": "mantis",
        "event":      {"dataset": "mantis.risks", "module": "mantis", "kind": "event"},
        "mantis":     {"user_email": user_email or None, "risk": risk},
    }
    if isinstance(risk_detail, dict):
        rec["mantis"]["risk_detail"] = risk_detail
    if filter_reason:
        rec["mantis"]["filter_reason"] = filter_reason
    if matched_identifiers:
        rec["mantis"]["matched_identifiers"] = matched_identifiers
    if isinstance(signals, dict):
        rec["mantis"]["signals"] = signals
    return rec


def build_event_record(ev: dict, user_email: str, detail: dict | None = None) -> dict:
    """
    Constrói registro de evento coletado via GET /customer/events.
    ev: item da lista retornada pela API (id, category, asset_type, processed_at, content, link_evidence).
    detail: opcional, resultado de GET /customer/events/{id} para enriquecimento.
    """
    return {
        "@timestamp": (ev.get("processed_at") or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
        "collector":  "mantis_events",
        "datasource": "mantis",
        "event":      {"dataset": "mantis.events", "module": "mantis", "kind": "event"},
        "mantis": {
            "user_email": user_email or None,
            "event": {
                "id":            ev.get("id"),
                "category":      ev.get("category"),
                "asset_type":    ev.get("asset_type"),
                "processed_at":  ev.get("processed_at"),
                "content":       ev.get("content"),
                "link_evidence": ev.get("link_evidence"),
                **({"detail": detail} if isinstance(detail, dict) else {}),
            },
        },
    }


# ---------------------------------------------------------------------------
# Coleta de Riscos (independente)
# ---------------------------------------------------------------------------

def collect_risks(
    base: str, token: str, out_dir: Path, user_email: str,
    page_size: int, categories: list[str], save_mode: str,
    detail_threads: int, credential_keywords: tuple, phishing_keywords: tuple,
    state_path: Path, jsonl_name: str,
    since_date: str | None = None,
) -> int:
    """Coleta riscos via /customer/risks e salva em JSONL. Retorna quantidade de novos."""
    jsonl_path = out_dir / jsonl_name
    seen_set, seen_order = load_state(state_path)
    is_first_run = len(seen_set) == 0
    # Aplica filtro de data apenas no primeiro run (backfill)
    effective_since = since_date if is_first_run else None
    if effective_since:
        print(f"[risks] Backfill: coletando riscos a partir de {effective_since}", flush=True)
    new_count = 0

    page = 1
    while True:
        data = fetch_risks_page(base, token, page, page_size, categories, since_date=effective_since)
        if not isinstance(data, dict):
            break
        total_pages = int(data.get("total_pages") or 0)
        content = data.get("content") or []
        to_fetch_detail: list[tuple[str, dict]] = []

        with jsonl_path.open("a", encoding="utf-8") as fh:
            for risk in content:
                if not isinstance(risk, dict):
                    continue
                rid = stable_id(risk)
                if rid in seen_set:
                    continue

                category = str(risk.get("event_category") or "").strip().lower()

                if save_mode == "all":
                    fh.write(json.dumps(build_risk_record(risk, user_email), ensure_ascii=False) + "\n")
                    new_count += 1
                    seen_set.add(rid); seen_order.append(rid)
                    continue

                # phishing_and_domain_leaks: fast path phishing
                if category == "phishing":
                    fh.write(json.dumps(build_risk_record(risk, user_email,
                        filter_reason="phishing_category_fastpath"), ensure_ascii=False) + "\n")
                    new_count += 1
                    seen_set.add(rid); seen_order.append(rid)
                    continue

                to_fetch_detail.append((rid, risk))

        if to_fetch_detail:
            with ThreadPoolExecutor(max_workers=detail_threads) as executor:
                future_map = {
                    executor.submit(fetch_risk_detail, base, token, rid): (rid, risk)
                    for rid, risk in to_fetch_detail
                }
                for fut in as_completed(future_map):
                    rid, risk = future_map[fut]
                    try:
                        detail = fut.result()
                    except Exception:
                        seen_set.add(rid); seen_order.append(rid)
                        continue
                    signals = _detect_risk_signals(risk, detail, credential_keywords, phishing_keywords)
                    if signals["is_phishing"] or signals["is_credential"]:
                        with jsonl_path.open("a", encoding="utf-8") as fh:
                            fh.write(json.dumps(build_risk_record(
                                risk, user_email, risk_detail=detail,
                                filter_reason=str(signals.get("reason") or "signal"),
                                matched_identifiers=list(signals.get("matched_identifiers") or []),
                                signals=signals,
                            ), ensure_ascii=False) + "\n")
                        new_count += 1
                    seen_set.add(rid); seen_order.append(rid)

        if total_pages <= 0 or page >= total_pages:
            break
        page += 1

    save_state(state_path, seen_order)
    return new_count


# ---------------------------------------------------------------------------
# Coleta de Eventos (independente)
# ---------------------------------------------------------------------------

def collect_events(
    base: str, token: str, out_dir: Path, user_email: str,
    state_path: Path, jsonl_name: str,
    max_pages: int, fetch_detail: bool,
    filter_categories: set[str] | None = None,
    since_date: str | None = None,
) -> int:
    """
    Coleta eventos via GET /customer/events (cursor-based, Elasticsearch search_after).
    Independente de riscos — eventos não precisam ter um risco associado.
    filter_categories: conjunto de categorias a salvar; None/vazio = todas.
    since_date: data ISO8601; eventos com processed_at < since_date são ignorados no primeiro run.
    Para quando 2 páginas consecutivas têm todos os eventos já vistos.
    Retorna quantidade de novos eventos salvos.
    """
    jsonl_path = out_dir / jsonl_name
    seen_set, seen_order = load_state(state_path)
    is_first_run = len(seen_set) == 0
    # Aplica filtro de data apenas no primeiro run (backfill)
    effective_since = since_date if is_first_run else None
    if effective_since:
        print(f"[events] Backfill: coletando eventos a partir de {effective_since}", flush=True)
    new_count = 0
    all_seen_streak = 0
    cursor = None  # começa sempre do mais recente

    for _page_num in range(max_pages):
        try:
            data = fetch_events_page(base, token, cursor)
        except Exception as exc:
            print(f"[events] Erro na página {_page_num + 1}: {exc}", file=sys.stderr)
            break

        events      = data.get("events") or []
        next_cursor = data.get("next_cursor")
        new_in_page = 0

        for ev in events:
            if not isinstance(ev, dict):
                continue
            ev_id = str(ev.get("id") or "").strip()
            if not ev_id or ev_id in seen_set:
                continue

            # Filtro client-side por data (backfill apenas no primeiro run)
            if effective_since:
                processed_at = str(ev.get("processed_at") or "").strip()
                if processed_at and processed_at < effective_since:
                    seen_set.add(ev_id)
                    seen_order.append(ev_id)
                    continue

            # Filtro client-side por categoria (vazio/None = todas)
            if filter_categories:
                ev_cat = str(ev.get("category") or "").strip()
                if ev_cat not in filter_categories:
                    # Marca como visto para não reprocessar, mas não salva
                    seen_set.add(ev_id)
                    seen_order.append(ev_id)
                    continue

            # Opcional: detalhe enriquecido via GET /customer/events/{id}
            detail: dict | None = None
            if fetch_detail:
                try:
                    detail = fetch_event_detail(base, token, ev_id)
                except Exception:
                    detail = None

            with jsonl_path.open("a", encoding="utf-8") as ef:
                ef.write(json.dumps(build_event_record(ev, user_email, detail), ensure_ascii=False) + "\n")
            seen_set.add(ev_id)
            seen_order.append(ev_id)
            new_in_page += 1

        new_count += new_in_page

        if new_in_page == 0:
            all_seen_streak += 1
            if all_seen_streak >= 2:
                break
        else:
            all_seen_streak = 0

        if not next_cursor:
            break
        cursor = next_cursor

    save_state(state_path, seen_order)
    return new_count


# ---------------------------------------------------------------------------
# Coleta combinada (uma passada)
# ---------------------------------------------------------------------------

def run_once(cfg: dict[str, str]) -> int:
    base  = (cfg.get("MANTIS_GATEWAY_BASE_URL") or "").rstrip("/")
    token = normalize_bearer(cfg.get("MANTIS_BEARER_TOKEN", ""))

    if not base:
        print("ERRO: MANTIS_GATEWAY_BASE_URL não definida no .env", file=sys.stderr)
        return 2
    if not token:
        print("ERRO: MANTIS_BEARER_TOKEN não definida no .env", file=sys.stderr)
        return 2

    out_dir           = _resolve_out_dir(cfg.get("MANTIS_COLLECTOR_OUT_DIR"))
    risks_jsonl_name  = cfg.get("MANTIS_JSONL_BASENAME")        or "mantis-risks.jsonl"
    events_jsonl_name = cfg.get("MANTIS_EVENTS_JSONL_BASENAME") or "mantis-events.jsonl"
    risks_state_path  = Path(cfg.get("MANTIS_STATE_PATH") or str(out_dir / ".state-risks.json"))
    events_state_path = out_dir / ".state-events.json"

    page_size      = max(1, int(cfg.get("MANTIS_RISKS_PAGE_SIZE") or "100"))
    user_email     = cfg.get("MANTIS_USER_EMAIL", "").strip()
    save_mode      = (cfg.get("MANTIS_SAVE_MODE") or "all").strip().lower()
    detail_threads = max(1, int(cfg.get("MANTIS_DETAIL_THREADS") or "16"))
    retention_days = int(cfg.get("MANTIS_RETENTION_DAYS") or "15")

    # ── Flags de coleta ──────────────────────────────────────────────────────
    collect_risks_flag = (cfg.get("MANTIS_COLLECT_RISKS") or "true").strip().lower() not in ("0", "false", "no")
    collect_ev         = (cfg.get("MANTIS_COLLECT_EVENTS") or "true").strip().lower() not in ("0", "false", "no")

    # ── Categorias de riscos (server-side filter; vazio = todas as categorias) ──
    risk_cats_raw = cfg.get("MANTIS_RISK_CATEGORIES", "").strip()
    risk_categories = [x.strip() for x in risk_cats_raw.split(",") if x.strip()] if risk_cats_raw else []

    # ── Categorias de eventos (client-side filter; vazio = todas) ────────────
    ev_cats_raw = cfg.get("MANTIS_EVENT_FILTER_CATEGORIES", "").strip()
    event_filter_categories: set[str] = {x.strip() for x in ev_cats_raw.split(",") if x.strip()} if ev_cats_raw else set()

    events_max_pages = max(1, int(cfg.get("MANTIS_EVENTS_MAX_PAGES") or "20"))
    events_fetch_det = (cfg.get("MANTIS_EVENTS_FETCH_DETAIL") or "false").strip().lower() in ("1", "true", "yes")
    credential_keywords = _load_keywords(cfg.get("MANTIS_CREDENTIAL_KEYWORDS"), CREDENTIAL_DEFAULT_KEYWORDS)
    phishing_keywords   = _load_keywords(cfg.get("MANTIS_PHISHING_KEYWORDS"),   PHISHING_DEFAULT_KEYWORDS)

    # ── Backfill: período mínimo de dados no primeiro run ─────────────────────
    backfill_days = int(cfg.get("MANTIS_BACKFILL_DAYS") or "30")
    if backfill_days > 0:
        since_dt   = datetime.now(timezone.utc) - timedelta(days=backfill_days)
        since_date: str | None = since_dt.strftime("%Y-%m-%dT%H:%M:%S.000000Z")
    else:
        since_date = None  # sem limite: coleta tudo disponível

    rotated = rotate_old_files(out_dir, retention_days, patterns=["*.jsonl", ".state*.json"])
    if rotated:
        print(f"[rotate] {rotated} arquivo(s) removido(s) (retenção={retention_days}d)", flush=True)

    risk_filter_info  = f"categorias={risk_categories or 'todas'}"
    event_filter_info = f"categorias={sorted(event_filter_categories) or 'todas'}"
    print(
        f"[config] collect_risks={collect_risks_flag} ({risk_filter_info}) | "
        f"collect_events={collect_ev} ({event_filter_info}) | "
        f"save_mode={save_mode}",
        flush=True,
    )

    # ── Riscos ──────────────────────────────────────────────────────────────
    new_risks: int = 0
    if collect_risks_flag:
        print("[risks] Iniciando coleta de riscos...", flush=True)
        try:
            new_risks = collect_risks(
                base=base, token=token, out_dir=out_dir, user_email=user_email,
                page_size=page_size, categories=risk_categories, save_mode=save_mode,
                detail_threads=detail_threads,
                credential_keywords=credential_keywords,
                phishing_keywords=phishing_keywords,
                state_path=risks_state_path,
                jsonl_name=risks_jsonl_name,
                since_date=since_date,
            )
            print(f"[risks] Novos riscos: {new_risks}", flush=True)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")[:800]
            print(f"[risks] HTTP {e.code}: {body}", file=sys.stderr)
            new_risks = -1
        except Exception as e:
            print(f"[risks] Erro: {e}", file=sys.stderr)
            new_risks = -1
    else:
        print("[risks] Coleta desativada (MANTIS_COLLECT_RISKS=false)", flush=True)

    # ── Eventos ─────────────────────────────────────────────────────────────
    new_events: int = 0
    if collect_ev:
        print(f"[events] Iniciando coleta de eventos (max_pages={events_max_pages})...", flush=True)
        try:
            new_events = collect_events(
                base=base, token=token, out_dir=out_dir, user_email=user_email,
                state_path=events_state_path,
                jsonl_name=events_jsonl_name,
                max_pages=events_max_pages,
                fetch_detail=events_fetch_det,
                filter_categories=event_filter_categories,
                since_date=since_date,
            )
            print(f"[events] Novos eventos: {new_events}", flush=True)
        except Exception as e:
            print(f"[events] Erro: {e}", file=sys.stderr)
            new_events = -1
    else:
        print("[events] Coleta desativada (MANTIS_COLLECT_EVENTS=false)", flush=True)

    print(json.dumps({
        "ok":                   (new_risks >= 0 if collect_risks_flag else True),
        "collect_risks":        collect_risks_flag,
        "collect_events":       collect_ev,
        "new_risks":            new_risks,
        "new_events":           new_events,
        "risk_categories":      risk_categories or "all",
        "event_categories":     sorted(event_filter_categories) or "all",
        "jsonl_risks":          str(out_dir / risks_jsonl_name) if collect_risks_flag else None,
        "jsonl_events":         str(out_dir / events_jsonl_name) if collect_ev else None,
        "save_mode":            save_mode,
        "events_max_pages":     events_max_pages,
    }, ensure_ascii=False))
    return 0 if (new_risks >= 0 or not collect_risks_flag) else 1


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    cfg = load_config()
    poll_seconds  = max(1, int(cfg.get("MANTIS_POLL_SECONDS") or "60"))
    run_once_only = (cfg.get("MANTIS_RUN_ONCE") or "").strip().lower() in ("1", "true", "yes", "on")

    print(f"[mantis-collector] v{__version__} | poll={poll_seconds}s | pid={os.getpid()}", flush=True)

    if run_once_only:
        return run_once(cfg)

    while True:
        rc = run_once(cfg)
        if rc != 0:
            print(f"Coleta com erro (rc={rc}); nova tentativa em {poll_seconds}s", file=sys.stderr)
        time.sleep(poll_seconds)


if __name__ == "__main__":
    raise SystemExit(main())
