#!/usr/bin/env python3
"""
MCP Server — EDR/XDR Containment
==================================
Expõe ferramentas de contenção de endpoint via MCP.
Suporte: SentinelOne (via API REST). Extensível para outros EDR/XDR/EPP.

Inicie com:
  python server_edr.py
  mcp dev server_edr.py
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    requests = None  # type: ignore

# ---------------------------------------------------------------------------
# Configuração
# ---------------------------------------------------------------------------

_ENV_PATHS = [
    Path(__file__).parent / ".env",
    Path(__file__).parent.parent / ".env",
    Path(__file__).parent.parent.parent / "laboratory" / "poc-harpia" / ".env",
]


def _load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for p in _ENV_PATHS:
        if p.is_file():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                env.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    for k in list(env):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


ENV = _load_env()

S1_BASE     = ENV.get("S1_BASE_URL",   "https://usea1-014.sentinelone.net").rstrip("/")
S1_TOKEN    = ENV.get("S1_API_TOKEN",  "")
S1_SITES    = [s.strip() for s in ENV.get("S1_SITE_IDS", "").split(",") if s.strip()]
S1_VERIFY   = ENV.get("S1_VERIFY_SSL","true").lower() not in ("0","false","no")

IOC_LISTS_DIR = Path(__file__).parent / "ioc_lists"


# ---------------------------------------------------------------------------
# SentinelOne API helpers
# ---------------------------------------------------------------------------

def _s1_get(path: str, params: dict | None = None) -> dict:
    if not requests:
        raise RuntimeError("pip install requests")
    headers = {"Authorization": f"ApiToken {S1_TOKEN}", "Content-Type": "application/json"}
    p = dict(params or {})
    if S1_SITES:
        p.setdefault("siteIds", ",".join(S1_SITES))
    r = requests.get(
        f"{S1_BASE}/web/api/v2.1/{path.lstrip('/')}",
        headers=headers, params=p, verify=S1_VERIFY, timeout=30,
    )
    r.raise_for_status()
    return r.json()


def _s1_post(path: str, data: dict) -> dict:
    if not requests:
        raise RuntimeError("pip install requests")
    headers = {"Authorization": f"ApiToken {S1_TOKEN}", "Content-Type": "application/json"}
    r = requests.post(
        f"{S1_BASE}/web/api/v2.1/{path.lstrip('/')}",
        headers=headers, json=data, verify=S1_VERIFY, timeout=30,
    )
    r.raise_for_status()
    return r.json()


def _extract_threat_iocs(threat: dict) -> dict:
    ti  = threat.get("threatInfo", {})
    ai  = threat.get("agentDetectionInfo", {})
    ari = threat.get("agentRealtimeInfo", {})
    agent_ips = [ip.strip() for ip in (ai.get("agentIpV4") or "").split(",") if ip.strip()]
    for iface in ari.get("networkInterfaces", []):
        agent_ips.extend(iface.get("inet", []))
    return {
        "threat_id":       threat.get("id", ""),
        "threat_name":     ti.get("threatName", ""),
        "classification":  ti.get("classification", ""),
        "confidence":      ti.get("confidenceLevel", ""),
        "mitigation":      ti.get("mitigationStatus", ""),
        "file_path":       ti.get("filePath", ""),
        "sha256":          ti.get("sha256", ""),
        "sha1":            ti.get("sha1", ""),
        "md5":             ti.get("md5", ""),
        "agent_id":        ari.get("agentId", ""),
        "agent_name":      ari.get("agentComputerName", ai.get("agentComputerName", "")),
        "agent_domain":    ai.get("agentDomain", ""),
        "agent_ips":       list(set(agent_ips)),
        "network_status":  ari.get("agentNetworkStatus", ""),
        "infected":        ari.get("agentInfected", False),
        "active_threats":  ari.get("activeThreats", 0),
        "identified_at":   ti.get("identifiedAt", ""),
        "engines":         [e.get("title","") for e in ti.get("detectionEngines",[])],
        "behaviors":       [i.get("description","") for i in threat.get("indicators",[])],
    }


def _read_list(path: Path) -> list[str]:
    values = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.split("#")[0].strip()
        if line:
            values.append(line)
    return values


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "safelabs-edr",
    instructions=(
        "EDR/XDR containment tools for SafeLabs SOC. "
        "Supports SentinelOne via REST API. "
        "Use isolate_agent to network-quarantine a compromised endpoint. "
        "Use collect_threat_iocs to extract IOCs for cross-playbook enrichment. "
        "Never deisolate without analyst confirmation."
    ),
)


@mcp.tool()
def edr_status() -> str:
    """Verifica conectividade com o SentinelOne e retorna info dos sites configurados."""
    try:
        r = _s1_get("agents", {"limit": 1})
        total = r.get("pagination", {}).get("totalItems", len(r.get("data", [])))
        return json.dumps({
            "platform":     "SentinelOne",
            "base_url":     S1_BASE,
            "site_ids":     S1_SITES,
            "status":       "connected",
            "agents_found": total,
            "ok":           True,
        }, indent=2)
    except Exception as e:
        return json.dumps({"ok": False, "error": str(e)})


@mcp.tool()
def edr_list_agents(infected_only: bool = False) -> str:
    """
    Lista agentes SentinelOne. Mostra hostname, IP, status de rede e ameaças ativas.

    Args:
        infected_only: Se True, mostra apenas agentes com ameaças ativas
    """
    try:
        params: dict = {"limit": 200}
        if infected_only:
            params["isInfected"] = "true"
        r     = _s1_get("agents", params)
        agents = r.get("data", [])
        rows   = []
        for a in agents:
            ips = ", ".join(
                ip for iface in a.get("networkInterfaces", []) for ip in iface.get("inet", [])
            ) or a.get("externalIp", "?")
            rows.append({
                "id":            a.get("id"),
                "name":          a.get("computerName"),
                "os":            a.get("osName"),
                "network":       a.get("networkStatus"),
                "infected":      a.get("isInfected", False),
                "active_threats":a.get("activeThreats", 0),
                "ips":           ips,
                "version":       a.get("agentVersion"),
            })
        return json.dumps(rows, ensure_ascii=False, indent=2)
    except Exception as e:
        return f"[ERRO] {e}"


@mcp.tool()
def edr_isolate_agent(agent_id: str, reason: str = "SafeLabs MCP — incident response") -> str:
    """
    Isola um agente da rede via SentinelOne (Network Quarantine).
    O endpoint mantém comunicação apenas com o console S1.
    ⚠ IMPACTO: Host perde acesso à rede. Confirme o agent_id antes.

    Args:
        agent_id: ID do agente SentinelOne (obter via edr_list_agents)
        reason: Motivo do isolamento para auditoria
    """
    try:
        r = _s1_post("agents/actions/disconnect", {"filter": {"ids": agent_id}})
        affected = r.get("data", {}).get("affected", "?")
        return f"[OK] Agente {agent_id} ISOLADO. Afetados: {affected}\nMotivo: {reason}"
    except Exception as e:
        return f"[ERRO] isolate({agent_id}): {e}"


@mcp.tool()
def edr_deisolate_agent(agent_id: str) -> str:
    """
    Remove o isolamento de rede de um agente (restaura conectividade).
    Use apenas após confirmação de remediação.

    Args:
        agent_id: ID do agente SentinelOne
    """
    try:
        r = _s1_post("agents/actions/connect", {"filter": {"ids": agent_id}})
        affected = r.get("data", {}).get("affected", "?")
        return f"[OK] Agente {agent_id} RECONECTADO. Afetados: {affected}"
    except Exception as e:
        return f"[ERRO] deisolate({agent_id}): {e}"


@mcp.tool()
def edr_scan_agent(agent_id: str) -> str:
    """
    Aciona scan completo de um agente SentinelOne.

    Args:
        agent_id: ID do agente
    """
    try:
        r = _s1_post("agents/actions/initiate-scan", {"filter": {"ids": agent_id}})
        return f"[OK] Scan iniciado no agente {agent_id}: {r.get('data', {})}"
    except Exception as e:
        return f"[ERRO] scan({agent_id}): {e}"


@mcp.tool()
def edr_list_threats(unresolved_only: bool = True, agent_id: str = "") -> str:
    """
    Lista threats detectados no SentinelOne com IOCs extraídos.

    Args:
        unresolved_only: Se True (padrão), mostra apenas ameaças não resolvidas
        agent_id: Filtrar por agente específico (opcional)
    """
    try:
        params: dict = {"limit": 50, "sortBy": "createdAt", "sortOrder": "desc"}
        if unresolved_only:
            params["resolved"] = "false"
        if agent_id:
            params["agentIds"] = agent_id
        r       = _s1_get("threats", params)
        threats = r.get("data", [])
        if not threats:
            return json.dumps({
                "threats": [],
                "message": "Nenhuma threat não tratada no momento",
                "filter": {"unresolved_only": unresolved_only, "agent_id": agent_id or "all"},
            }, ensure_ascii=False, indent=2)
        iocs = [_extract_threat_iocs(t) for t in threats]
        return json.dumps({"threats": iocs, "count": len(iocs)}, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def edr_collect_iocs(unresolved_only: bool = True) -> str:
    """
    Coleta todos os IOCs de threats SentinelOne.
    Retorna lista estruturada com hashes, IPs, hostnames — pronta para
    alimentar fw_block_ip_list, dns_block_domain, ad_check_user, etc.

    Args:
        unresolved_only: Coletar apenas threats não resolvidos
    """
    try:
        params: dict = {"limit": 200, "sortBy": "createdAt", "sortOrder": "desc"}
        if unresolved_only:
            params["resolved"] = "false"
        r = _s1_get("threats", params)
        threats = r.get("data", [])

        all_iocs = [_extract_threat_iocs(t) for t in threats]

        # Resumo para decisão
        hashes_sha256  = {i["sha256"] for i in all_iocs if i["sha256"]}
        hashes_sha1    = {i["sha1"]   for i in all_iocs if i["sha1"]}
        infected_ips   = {ip for i in all_iocs for ip in i["agent_ips"]
                          if i["infected"] or i["active_threats"] > 0}
        infected_names = {i["agent_name"] for i in all_iocs
                          if i["infected"] or i["active_threats"] > 0}

        summary = {
            "total_threats":       len(all_iocs),
            "unique_sha256":       len(hashes_sha256),
            "unique_sha1":         len(hashes_sha1),
            "infected_host_ips":   sorted(infected_ips),
            "infected_host_names": sorted(infected_names),
            "top_threats":         [i["threat_name"] for i in all_iocs[:10]],
            "iocs":                all_iocs,
        }
        return json.dumps(summary, ensure_ascii=False, indent=2)
    except Exception as e:
        return f"[ERRO] {e}"


def _detect_hash_type(h: str) -> str | None:
    """Detecta tipo de hash pelo tamanho: 32=MD5, 40=SHA1, 64=SHA256."""
    import re as _re
    h = h.strip()
    if _re.fullmatch(r'[0-9a-fA-F]{32}', h):
        return "md5"
    if _re.fullmatch(r'[0-9a-fA-F]{40}', h):
        return "sha1"
    if _re.fullmatch(r'[0-9a-fA-F]{64}', h):
        return "sha256"
    return None


@mcp.tool()
def edr_blacklist_hash(hash_value: str, description: str = "SafeLabs SOC — IOC block") -> str:
    """
    Adiciona hash à blacklist do SentinelOne (bloqueia execução futura).
    Aceita SHA1 (40 hex), SHA256 (64 hex) ou MD5 (32 hex — aviso: suporte limitado no S1).

    Args:
        hash_value: Hash do arquivo malicioso (SHA1, SHA256 ou MD5)
        description: Descrição/motivo
    """
    h = hash_value.strip().lower()
    htype = _detect_hash_type(h)
    if not htype:
        return f"[ERRO] Hash inválido: '{hash_value}'. Deve ser MD5 (32), SHA1 (40) ou SHA256 (64) hex chars."
    if htype == "md5":
        return (f"[AVISO] MD5 ({h}) não é suportado nativamente pelo SentinelOne para blacklist. "
                f"Use o hash SHA1 ou SHA256 do mesmo arquivo.")
    try:
        payload: dict[str, Any] = {
            "type":        "black_hash",
            "value":       h,
            "description": description,
            "osType":      "windows",
            "source":      "user",
        }
        r = _s1_post("restrictions", {
            "filter": {"siteIds": S1_SITES},
            "data":   payload,
        })
        return json.dumps({
            "ok": True,
            "hash": h,
            "type": htype,
            "result": r.get("data", {}),
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "hash": h, "type": htype})


@mcp.tool()


def edr_get_blacklist_hashes() -> str:
    """Retorna a lista de hashes na blacklist do SentinelOne (restrictions type=black_hash).

    Returns:
        JSON com lista de hashes e metadados.
    """
    try:
        params = {"limit": 1000, "type": "black_hash"}
        if S1_SITES:
            params["siteIds"] = ",".join(S1_SITES)
        data = _s1_get("restrictions", params)
        items = data.get("data", [])
        hashes = []
        for it in items:
            hashes.append({
                "value": it.get("value", ""),
                "type": it.get("type", ""),
                "description": it.get("description", ""),
                "os_type": it.get("osType", ""),
                "created_at": str(it.get("createdAt", ""))[:19],
                "user_name": it.get("userName", ""),
            })
        return json.dumps({"ok": True, "count": len(hashes), "hashes": hashes}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"ok": False, "error": str(e)})



def edr_blacklist_hash_list(list_name: str) -> str:
    """
    Adiciona hashes de uma lista à blacklist SentinelOne.
    Detecta automaticamente SHA1 (40 hex) e SHA256 (64 hex). MD5 é ignorado com aviso.

    Args:
        list_name: Nome da lista em ioc_lists/ (ex: 'apt44_hashes')
    """
    import re
    list_path = IOC_LISTS_DIR / f"{list_name}.txt"
    if not list_path.is_file():
        available = [f.stem for f in IOC_LISTS_DIR.glob("*.txt")]
        return f"[ERRO] Lista '{list_name}' não encontrada. Disponíveis: {available}"

    raw_lines = _read_list(list_path)
    sha1_re   = re.compile(r'\b[0-9a-fA-F]{40}\b')
    sha256_re = re.compile(r'\b[0-9a-fA-F]{64}\b')
    hashes: list[tuple[str, str]] = []
    for line in raw_lines:
        m256 = sha256_re.search(line)
        m1   = sha1_re.search(line)
        if m256:
            hashes.append((m256.group(0).lower(), "sha256"))
        elif m1:
            hashes.append((m1.group(0).lower(), "sha1"))

    if not hashes:
        return f"[AVISO] Nenhum hash SHA1/SHA256 encontrado em '{list_name}'."

    results = []
    for h, htype in hashes:
        try:
            _s1_post("restrictions", {
                "filter": {"siteIds": S1_SITES},
                "data": {
                    "type":        "black_hash",
                    "value":       h,
                    "description": f"SafeLabs MCP — {list_name}",
                    "osType":      "windows",
                    "source":      "user",
                },
            })
            results.append(f"[OK] {h} ({htype})")
        except Exception as e:
            results.append(f"[ERRO] {h} ({htype}): {e}")

    ok   = sum(1 for r in results if r.startswith("[OK]"))
    fail = len(results) - ok
    return f"Blacklist '{list_name}': {ok} hashes adicionados | {fail} erros\n" + "\n".join(results)


@mcp.tool()
def edr_containment_chain(agent_id: str) -> str:
    """
    Executa contenção automática completa em um agente:
    1. Isola o agente da rede
    2. Aciona scan completo
    3. Coleta IOCs de todos os threats desse agente
    4. Retorna IOCs para ação nos outros playbooks (FW, DNS, AD)

    Args:
        agent_id: ID do agente comprometido
    """
    steps = []

    # 1. Info do agente
    try:
        r = _s1_get("agents", {"ids": agent_id})
        agents = r.get("data", [])
        if not agents:
            return f"[ERRO] Agente {agent_id} não encontrado"
        agent = agents[0]
        steps.append(f"[1/3] Agente: {agent.get('computerName')} | OS: {agent.get('osName')} | Net: {agent.get('networkStatus')}")
    except Exception as e:
        return f"[ERRO] lookup agent: {e}"

    # 2. Isolar
    try:
        r = _s1_post("agents/actions/disconnect", {"filter": {"ids": agent_id}})
        steps.append(f"[2/3] ISOLADO — afetados: {r.get('data',{}).get('affected','?')}")
    except Exception as e:
        steps.append(f"[2/3] ERRO ao isolar: {e}")

    # 3. Scan
    try:
        _s1_post("agents/actions/initiate-scan", {"filter": {"ids": agent_id}})
        steps.append("[3/3] Scan iniciado")
    except Exception as e:
        steps.append(f"[3/3] AVISO scan: {e}")

    # 4. Collect IOCs desse agente
    try:
        params = {"limit": 100, "resolved": "false", "agentIds": agent_id}
        r = _s1_get("threats", params)
        threats = r.get("data", [])
        iocs = [_extract_threat_iocs(t) for t in threats]
        steps.append(f"\n[IOCs] {len(iocs)} threats coletados para agente {agent_id}")
        steps.append("\nUse os IOCs abaixo com:")
        steps.append("  fw_block_ip(ip)    — para cada agent_ip dos hosts infectados")
        steps.append("  edr_blacklist_hash(sha1)  — para cada hash")
        steps.append("\n" + json.dumps(iocs[:5], ensure_ascii=False, indent=2))
    except Exception as e:
        steps.append(f"[IOCs] ERRO: {e}")

    return "\n".join(steps)


@mcp.tool()
def edr_list_available_lists() -> str:
    """Lista todos os arquivos de IOCs disponíveis na pasta ioc_lists/."""
    lists = []
    for f in sorted(IOC_LISTS_DIR.glob("*.txt")):
        from pathlib import Path as _P
        lines = [l.split("#")[0].strip() for l in f.read_text(encoding="utf-8-sig").splitlines()
                 if l.split("#")[0].strip()]
        lists.append(f"  {f.stem} ({len(lines)} entradas)")
    return "Listas disponíveis:\n" + "\n".join(lists) if lists else "Nenhuma lista encontrada"


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

@mcp.resource("ioc://apt44/hashes")
def apt44_hashes_resource() -> str:
    """Hashes maliciosos do APT44 (Sandworm)."""
    p = IOC_LISTS_DIR / "apt44_hashes.txt"
    return p.read_text(encoding="utf-8") if p.is_file() else "Arquivo não encontrado"


@mcp.resource("ioc://apt44/c2_onion")
def apt44_onion_resource() -> str:
    """Endereços Tor C2 do APT44."""
    p = IOC_LISTS_DIR / "apt44_c2_onion.txt"
    return p.read_text(encoding="utf-8") if p.is_file() else "Arquivo não encontrado"


if __name__ == "__main__":
    import sys
    transport = "stdio"
    port = 8091
    for arg in sys.argv[1:]:
        if arg == "--sse":
            transport = "sse"
        elif arg.startswith("--port="):
            port = int(arg.split("=")[1])
    if transport == "sse":
        mcp.run(transport="sse", host="0.0.0.0", port=port)
    else:
        mcp.run()
