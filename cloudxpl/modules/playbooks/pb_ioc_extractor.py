#!/usr/bin/env python3
"""
IOC Extractor — Ponte entre Pipelines HIN e Playbooks N2
=========================================================
Lê eventos de qualquer pipeline (SentinelOne, Windows, Fortinet, Linux, Mantis)
e extrai IOCs estruturados prontos para alimentar os playbooks de contenção.

Pipelines suportados (baseados nos logs reais coletados na HIN):
  - sentinelone_threats  → hashes, IPs de agentes infectados, filePaths
  - sentinelone_activities → agentId, activityType, agentComputerName
  - windows_events       → EventID, SubjectUserName, IpAddress, ProcessName, Hashes
  - fortinet_syslog      → srcip, dstip, hostname, domain, url, app
  - linux_auditd         → uid, exe, pid, hostname, addr (syslog RFC3164 + auditd)
  - mantis               → risk_id, asset, score, indicators

Uso standalone:
  python3 pb_ioc_extractor.py --source sentinelone --input threats.jsonl
  python3 pb_ioc_extractor.py --source windows     --input events.jsonl --event-ids 4625,4768
  python3 pb_ioc_extractor.py --source fortinet     --input fortigate.log
  python3 pb_ioc_extractor.py --source all          --output iocs_combined.json

Uso como módulo:
  from pb_ioc_extractor import extract_from_file, IOCBundle
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Modelo de IOC estruturado
# ---------------------------------------------------------------------------

@dataclass
class IOCBundle:
    """
    Conjunto de IOCs extraídos de um evento.
    Serve como input padronizado para todos os playbooks N2.
    """
    source:          str = ""          # pipeline de origem: sentinelone, windows, fortinet, linux
    source_event_id: str = ""          # ID do evento na origem
    timestamp:       str = ""

    # Hashes (EDR, Windows Sysmon)
    sha256: str = ""
    sha1:   str = ""
    md5:    str = ""

    # Rede
    src_ip:    str = ""
    dst_ip:    str = ""
    src_port:  int = 0
    dst_port:  int = 0
    domain:    str = ""
    url:       str = ""
    protocol:  str = ""

    # Identidade (AD, Windows)
    username:    str = ""              # sAMAccountName
    upn:         str = ""              # user@domain.lab
    domain_name: str = ""
    workstation: str = ""

    # Host
    hostname:   str = ""
    agent_id:   str = ""
    agent_os:   str = ""
    agent_ip:   str = ""

    # Arquivo / processo
    file_path:    str = ""
    process_name: str = ""
    cmdline:      str = ""
    parent_proc:  str = ""

    # Classificação / severidade
    threat_name:  str = ""
    classification: str = ""
    severity:     str = ""
    action:       str = ""            # allow, block, deny, isolate, detect

    # Flags para qual playbook acionar
    trigger_fw:   bool = False        # → pb_fw_fortigate.py
    trigger_dns:  bool = False        # → pb_dns_block.py
    trigger_ad:   bool = False        # → pb_ad_containment.py
    trigger_edr:  bool = False        # → pb_edr_sentinelone.py

    # Evidências brutas para auditoria
    raw: dict = field(default_factory=dict)

    def has_iocs(self) -> bool:
        return any([
            self.sha256, self.sha1, self.md5,
            self.src_ip, self.dst_ip, self.domain, self.url,
            self.username, self.hostname,
        ])

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("raw", None)
        return {k: v for k, v in d.items() if v and v != 0 and v is not False}

    def playbooks_needed(self) -> list[str]:
        pbs = []
        if self.trigger_fw:  pbs.append("pb_fw_fortigate.py")
        if self.trigger_dns: pbs.append("pb_dns_block.py")
        if self.trigger_ad:  pbs.append("pb_ad_containment.py")
        if self.trigger_edr: pbs.append("pb_edr_sentinelone.py")
        return pbs


# ---------------------------------------------------------------------------
# Extratores por pipeline
# ---------------------------------------------------------------------------

def extract_sentinelone_threat(event: dict) -> IOCBundle:
    """
    Extrai IOC de threat SentinelOne.
    Campos: payload.threatInfo, agentDetectionInfo, agentRealtimeInfo, indicators.
    """
    p   = event.get("payload", {})
    ti  = p.get("threatInfo", {})
    ai  = p.get("agentDetectionInfo", {})
    ari = p.get("agentRealtimeInfo", {})

    # IPs do agente
    agent_ips = [ip.strip() for ip in (ai.get("agentIpV4") or "").split(",") if ip.strip()]
    for iface in ari.get("networkInterfaces", []):
        agent_ips.extend(iface.get("inet", []))
    primary_ip = agent_ips[0] if agent_ips else ""

    mitigation = ti.get("mitigationStatus", "")
    is_active  = mitigation not in ("mitigated", "not_applicable")
    is_alert   = ti.get("confidenceLevel") in ("malicious", "suspicious")

    b = IOCBundle(
        source          = "sentinelone",
        source_event_id = ti.get("threatId", event.get("event_id", "")),
        timestamp       = ti.get("identifiedAt", event.get("@timestamp", "")),
        sha256          = ti.get("sha256", ""),
        sha1            = ti.get("sha1", ""),
        md5             = ti.get("md5", ""),
        file_path       = ti.get("filePath", ""),
        threat_name     = ti.get("threatName", ""),
        classification  = ti.get("classification", ""),
        severity        = ti.get("confidenceLevel", ""),
        action          = "detect" if is_active else "mitigated",
        hostname        = ari.get("agentComputerName", ai.get("agentComputerName", "")),
        agent_id        = ari.get("agentId", ""),
        agent_os        = ai.get("agentOsName", ari.get("agentOsName", "")),
        agent_ip        = primary_ip,
        domain_name     = ai.get("agentDomain", ""),
        trigger_edr     = is_active and is_alert,
        trigger_fw      = is_active and bool(primary_ip),
        raw             = {"threatInfo": ti, "agentDetectionInfo": ai},
    )
    return b


def extract_sentinelone_activity(event: dict) -> IOCBundle:
    """
    Extrai IOC de activity SentinelOne.
    Campos: payload.{primaryDescription, activityType, agentComputerName, siteId, agentId}
    """
    p = event.get("payload", {})
    return IOCBundle(
        source          = "sentinelone_activity",
        source_event_id = str(p.get("id", event.get("event_id", ""))),
        timestamp       = p.get("createdAt", event.get("@timestamp", "")),
        hostname        = p.get("agentComputerName", ""),
        agent_id        = str(p.get("agentId", "")),
        threat_name     = p.get("primaryDescription", "")[:100],
        action          = "alert",
        raw             = p,
    )


# Windows Event ID → IOC mapping baseado nos eventos reais coletados (WinEvent bastion/DC)
_WIN_EVENT_IOC_MAP: dict[int, dict] = {
    # Logon events
    4624: {"action": "logon_success",   "trigger_ad": False},
    4625: {"action": "logon_failure",   "trigger_ad": True,  "severity": "medium"},
    4648: {"action": "explicit_logon",  "trigger_ad": True,  "severity": "medium"},
    4672: {"action": "special_logon",   "trigger_ad": True,  "severity": "low"},
    # Account management
    4720: {"action": "user_created",    "trigger_ad": True,  "severity": "high"},
    4726: {"action": "user_deleted",    "trigger_ad": True,  "severity": "high"},
    4732: {"action": "group_member_add","trigger_ad": True,  "severity": "medium"},
    4740: {"action": "account_locked",  "trigger_ad": True,  "severity": "medium"},
    4767: {"action": "account_unlocked","trigger_ad": True,  "severity": "low"},
    # Kerberos
    4768: {"action": "kerberos_tgt",    "trigger_ad": False},
    4769: {"action": "kerberos_st",     "trigger_ad": False},
    4771: {"action": "kerberos_fail",   "trigger_ad": True,  "severity": "medium"},
    # Process
    4688: {"action": "process_created", "trigger_edr": True, "severity": "low"},
    4689: {"action": "process_exit",    "trigger_edr": False},
    # Network
    5156: {"action": "network_allow",   "trigger_fw": False},
    5157: {"action": "network_block",   "trigger_fw": True,  "severity": "medium"},
    # Log clearing
    1102: {"action": "log_cleared",     "trigger_ad": True,  "severity": "high"},
    4698: {"action": "schtask_created", "trigger_edr": True, "severity": "medium"},
    4702: {"action": "schtask_modified","trigger_edr": True, "severity": "medium"},
    # Sysmon
    1:    {"action": "process_created", "trigger_edr": True, "severity": "low"},
    3:    {"action": "network_conn",    "trigger_fw": True,  "severity": "low"},
    11:   {"action": "file_created",    "trigger_edr": True, "severity": "low"},
    13:   {"action": "reg_set",         "trigger_edr": True, "severity": "low"},
}


def extract_windows_event(event: dict) -> IOCBundle:
    """
    Extrai IOC de evento Windows (Security/Sysmon/System via WinEvent pipeline).
    Suporta formato JSONL do WinCollector (raw XML → parsed) e formato Harpia SIEM.
    """
    ev_id   = int(event.get("EventID", event.get("event_id", 0)) or 0)
    user    = event.get("SubjectUserName", event.get("TargetUserName", event.get("user", "")))
    domain  = event.get("SubjectDomainName", event.get("TargetDomainName", ""))
    src_ip  = event.get("IpAddress", event.get("src_ip", event.get("Workstation", "")))
    proc    = event.get("ProcessName", event.get("Image", event.get("process_name", "")))
    cmdline = event.get("CommandLine", event.get("cmdline", ""))
    parent  = event.get("ParentProcessName", event.get("ParentImage", ""))
    hashes  = event.get("Hashes", "")
    hostname= event.get("Computer", event.get("hostname", event.get("workstation", "")))
    ts      = event.get("TimeCreated", event.get("@timestamp", ""))

    # Parse hashes string "SHA256=abc,SHA1=def,MD5=ghi"
    sha256 = sha1 = md5 = ""
    for part in str(hashes).split(","):
        if "SHA256=" in part.upper():
            sha256 = part.split("=", 1)[-1].strip()
        elif "SHA1=" in part.upper():
            sha1 = part.split("=", 1)[-1].strip()
        elif "MD5=" in part.upper():
            md5 = part.split("=", 1)[-1].strip()

    meta = _WIN_EVENT_IOC_MAP.get(ev_id, {})
    upn  = f"{user}@{domain}".lower() if user and domain and domain != "-" else ""

    # Heurísticas de trigger
    trigger_ad  = meta.get("trigger_ad", False)
    trigger_edr = meta.get("trigger_edr", False)
    trigger_fw  = meta.get("trigger_fw", False)

    # Logons com falha repetida → mais relevante para AD
    if ev_id in (4625, 4771) and src_ip and src_ip not in ("-", "::1", "127.0.0.1"):
        trigger_fw = True  # src externo → bloquear no FW

    return IOCBundle(
        source          = "windows",
        source_event_id = str(ev_id),
        timestamp       = ts,
        sha256          = sha256,
        sha1            = sha1,
        md5             = md5,
        src_ip          = src_ip if src_ip and src_ip not in ("-", "::1") else "",
        username        = user.lower() if user and user not in ("-", "SYSTEM") else "",
        upn             = upn,
        domain_name     = domain,
        workstation     = hostname,
        hostname        = hostname,
        file_path       = proc,
        process_name    = Path(proc).name if proc else "",
        cmdline         = cmdline[:200] if cmdline else "",
        parent_proc     = parent,
        action          = meta.get("action", ""),
        severity        = meta.get("severity", "info"),
        trigger_ad      = trigger_ad,
        trigger_edr     = trigger_edr,
        trigger_fw      = trigger_fw,
        raw             = event,
    )


def extract_fortinet_syslog(event: dict) -> IOCBundle:
    """
    Extrai IOC de log FortiGate (syslog UDP 514 → pipeline fortinet).
    Campos comuns FortiOS: srcip, dstip, srcport, dstport, hostname, proto,
      action, policyname, app, url, user, srccountry, dstcountry.
    """
    src_ip  = event.get("srcip", event.get("src_ip", ""))
    dst_ip  = event.get("dstip", event.get("dst_ip", ""))
    action  = event.get("action", event.get("action", "")).lower()
    url     = event.get("url", event.get("referralurl", ""))
    domain  = event.get("hostname", event.get("domain", ""))
    app     = event.get("app", event.get("appcat", ""))
    user    = event.get("user", event.get("srcuser", ""))
    severity= event.get("severity", event.get("level", ""))
    subtype = event.get("subtype", "")

    # Bloquear no FW se: ação deny/block, ou país de alto risco, ou C2 detectado
    trigger_fw  = action in ("deny", "block", "drop") and bool(src_ip)
    trigger_dns = bool(domain) and action in ("deny", "block")

    return IOCBundle(
        source          = "fortinet",
        source_event_id = event.get("logid", event.get("log_id", "")),
        timestamp       = event.get("eventtime", event.get("@timestamp", "")),
        src_ip          = src_ip,
        dst_ip          = dst_ip,
        src_port        = int(event.get("srcport", 0) or 0),
        dst_port        = int(event.get("dstport", 0) or 0),
        domain          = domain,
        url             = url,
        protocol        = event.get("proto", event.get("protocol", "")),
        username        = user,
        hostname        = event.get("srcname", event.get("devname", "")),
        action          = action,
        threat_name     = app,
        severity        = severity,
        trigger_fw      = trigger_fw,
        trigger_dns     = trigger_dns,
        raw             = event,
    )


def extract_linux_auditd(event: dict) -> IOCBundle:
    """
    Extrai IOC de evento auditd Linux (syslog UDP 5514 → pipeline linux).
    Formato: RFC3164 com campos auditd: type=SYSCALL, USER_LOGIN, EXECVE, etc.
    """
    msg     = event.get("message", event.get("msg", ""))
    uid     = event.get("uid", event.get("auid", ""))
    exe     = event.get("exe", event.get("comm", ""))
    addr    = event.get("addr", event.get("src_addr", ""))
    hostname= event.get("hostname", event.get("host", ""))
    ts      = event.get("@timestamp", "")
    ev_type = event.get("type", "")

    # USER_AUTH / USER_LOGIN falhos → trigger AD se user de domínio
    is_auth_fail = ev_type in ("USER_AUTH", "USER_LOGIN") and "res=failed" in msg
    user = event.get("acct", event.get("user", "")).strip("'\"")

    return IOCBundle(
        source          = "linux",
        source_event_id = event.get("serial", event.get("audit_serial", "")),
        timestamp       = ts,
        src_ip          = addr if addr and addr not in ("?", "") else "",
        username        = user,
        hostname        = hostname,
        file_path       = exe,
        process_name    = Path(exe).name if exe else "",
        action          = "auth_fail" if is_auth_fail else ev_type.lower(),
        severity        = "medium" if is_auth_fail else "info",
        trigger_ad      = is_auth_fail and "@" in user,  # UPN de domínio
        trigger_fw      = is_auth_fail and bool(addr) and addr not in ("?",),
        raw             = event,
    )


def extract_mantis(event: dict) -> IOCBundle:
    """
    Extrai IOC de risco Mantis.
    Campos: asset, score, risk_type, indicators, affected_ips, affected_domains.
    """
    score    = float(event.get("score", event.get("risk_score", 0)) or 0)
    asset    = event.get("asset", event.get("device", ""))
    severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 5 else "low"

    return IOCBundle(
        source          = "mantis",
        source_event_id = str(event.get("id", event.get("risk_id", ""))),
        timestamp       = event.get("created_at", event.get("@timestamp", "")),
        hostname        = asset,
        src_ip          = event.get("ip", event.get("affected_ip", "")),
        threat_name     = event.get("risk_type", event.get("risk_name", "")),
        severity        = severity,
        action          = "alert",
        trigger_fw      = score >= 8,
        trigger_edr     = score >= 9,
        raw             = event,
    )


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

_EXTRACTORS = {
    "sentinelone":          extract_sentinelone_threat,
    "sentinelone_activity": extract_sentinelone_activity,
    "windows":              extract_windows_event,
    "fortinet":             extract_fortinet_syslog,
    "linux":                extract_linux_auditd,
    "mantis":               extract_mantis,
}


def auto_detect_source(event: dict) -> str:
    """Detecta o pipeline de origem pelo conteúdo do evento."""
    src  = event.get("source", "")
    tags = event.get("tags", [])
    mod  = event.get("event", {}).get("module", "")

    if "sentinelone" in src or "sentinelone" in tags or "sentinelone" in mod:
        et = event.get("event_type", "")
        return "sentinelone_activity" if et == "activities" else "sentinelone"
    if "fortinet" in src or "fortinet" in tags or "fortinet" in mod:
        return "fortinet"
    if "windows" in src or "windows" in tags or "windows" in mod:
        return "windows"
    if "linux" in src or "linux" in tags or "auditd" in src:
        return "linux"
    if "mantis" in src or "mantis" in tags or "mantis" in mod:
        return "mantis"

    # Heurísticas por campos presentes
    if event.get("threatInfo") or event.get("agentDetectionInfo"):
        return "sentinelone"
    if event.get("EventID") or event.get("SubjectUserName"):
        return "windows"
    if event.get("srcip") or event.get("dstip"):
        return "fortinet"
    if event.get("exe") or event.get("auid") is not None:
        return "linux"

    return "unknown"


def extract_from_event(event: dict, source: str | None = None) -> IOCBundle | None:
    """Extrai IOC de um único evento."""
    src = source or auto_detect_source(event)
    fn  = _EXTRACTORS.get(src)
    if not fn:
        return None
    try:
        b = fn(event)
        b.source = b.source or src
        return b if b.has_iocs() else None
    except Exception as e:
        return None


def extract_from_file(path: Path, source: str | None = None,
                      max_events: int = 10000) -> list[IOCBundle]:
    """Extrai IOCs de arquivo JSONL."""
    bundles = []
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= max_events:
                break
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            b = extract_from_event(event, source)
            if b:
                bundles.append(b)
    return bundles


def summarize(bundles: list[IOCBundle]) -> dict:
    """Resumo de IOCs para exibição e decisão de playbooks."""
    triggers: dict[str, int] = {"fw": 0, "dns": 0, "ad": 0, "edr": 0}
    for b in bundles:
        if b.trigger_fw:  triggers["fw"]  += 1
        if b.trigger_dns: triggers["dns"] += 1
        if b.trigger_ad:  triggers["ad"]  += 1
        if b.trigger_edr: triggers["edr"] += 1

    unique_ips   = {b.src_ip  for b in bundles if b.src_ip}
    unique_users = {b.username for b in bundles if b.username}
    unique_hosts = {b.hostname for b in bundles if b.hostname}
    unique_sha   = {b.sha256  for b in bundles if b.sha256} | {b.sha1 for b in bundles if b.sha1}

    return {
        "total_events":    len(bundles),
        "triggers":        triggers,
        "unique_ips":      sorted(unique_ips),
        "unique_users":    sorted(unique_users),
        "unique_hosts":    sorted(unique_hosts),
        "unique_hashes":   len(unique_sha),
        "top_threats":     list({b.threat_name for b in bundles if b.threat_name})[:10],
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="IOC Extractor — Ponte Pipelines HIN → Playbooks N2",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # Extrai IOCs de threats SentinelOne
  python3 pb_ioc_extractor.py --source sentinelone \\
      --input /Harpia/logsource/sentinelone/api/threats.jsonl

  # Extrai IOCs de eventos Windows e mostra quais playbooks acionar
  python3 pb_ioc_extractor.py --source windows --input winevent.jsonl --summary

  # Detecta automaticamente o tipo e exporta JSON
  python3 pb_ioc_extractor.py --input trend.log --output iocs.json

  # Lista eventos com trigger_ad (credenciais comprometidas → pb_ad_containment)
  python3 pb_ioc_extractor.py --source windows --input events.jsonl --filter-trigger ad
""")
    p.add_argument("--source",  choices=list(_EXTRACTORS) + ["auto"], default="auto")
    p.add_argument("--input",   required=True, help="Arquivo JSONL de entrada")
    p.add_argument("--output",  default=None,   help="Arquivo JSON de saída")
    p.add_argument("--summary", action="store_true", help="Exibe resumo")
    p.add_argument("--filter-trigger", choices=["fw", "dns", "ad", "edr"],
                   help="Mostra apenas IOCs com este trigger ativo")
    p.add_argument("--max",     type=int, default=10000, help="Máx eventos a processar")
    return p


def main() -> int:
    args = build_parser().parse_args()
    src  = None if args.source == "auto" else args.source
    path = Path(args.input)
    if not path.is_file():
        print(f"ERRO: arquivo não encontrado: {path}", file=sys.stderr)
        return 2

    bundles = extract_from_file(path, source=src, max_events=args.max)
    print(f"[OK] {len(bundles)} IOCs extraídos de {path.name}")

    if args.filter_trigger:
        attr = f"trigger_{args.filter_trigger}"
        bundles = [b for b in bundles if getattr(b, attr, False)]
        print(f"     Filtrado: {len(bundles)} com trigger_{args.filter_trigger}")

    if args.summary:
        s = summarize(bundles)
        print(f"\n  Total eventos : {s['total_events']}")
        print(f"  Triggers      : FW={s['triggers']['fw']} DNS={s['triggers']['dns']} "
              f"AD={s['triggers']['ad']} EDR={s['triggers']['edr']}")
        print(f"  IPs únicos    : {len(s['unique_ips'])} — {s['unique_ips'][:5]}")
        print(f"  Usuários      : {len(s['unique_users'])} — {s['unique_users'][:5]}")
        print(f"  Hashes        : {s['unique_hashes']}")
        print(f"  Threats top   : {s['top_threats'][:5]}")

    if args.output:
        data = [b.to_dict() for b in bundles]
        Path(args.output).write_text(
            json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"[OK] Salvo: {args.output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
