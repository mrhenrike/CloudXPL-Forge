#!/usr/bin/env python3
"""
Playbook N2 — SentinelOne EDR/XDR Containment
===============================================
Aciona contenção em agentes SentinelOne via API REST:
  - Isola host da rede (Network Quarantine)
  - Remove isolamento
  - Coleta IOCs de threats (hash, filePath, IP, domain) e enriquece threat intelligence
  - Atualiza exclusões / blacklist via API
  - Aciona scan sob demanda
  - Lista threats com IOCs extraídos (prontos para uso em pb_fw_fortigate e pb_dns_block)

Inputs reconhecidos pelos pipelines HIN:
  - SentinelOne threats.jsonl: payload.threatInfo.{sha256, sha1, filePath, threatName,
      classification, mitigationStatus, detectionEngines}
  - payload.agentDetectionInfo.{agentComputerName, agentIpV4, agentIpV6, agentOsName, agentDomain}
  - payload.agentRealtimeInfo.{agentComputerName, agentNetworkStatus, agentInfected, activeThreats}

Uso:
  python3 pb_edr_sentinelone.py --action isolate     --agent-id <ID>
  python3 pb_edr_sentinelone.py --action deisolate   --agent-id <ID>
  python3 pb_edr_sentinelone.py --action scan        --agent-id <ID>
  python3 pb_edr_sentinelone.py --action collect-ioc               # coleta IOCs de threats ativos
  python3 pb_edr_sentinelone.py --action collect-ioc --output iocs.json
  python3 pb_edr_sentinelone.py --action export-fw                 # exporta CSV para pb_fw_fortigate
  python3 pb_edr_sentinelone.py --action export-dns                # exporta lista para pb_dns_block
  python3 pb_edr_sentinelone.py --action list-threats
  python3 pb_edr_sentinelone.py --action list-agents
  python3 pb_edr_sentinelone.py --action status      --agent-id <ID>
  python3 pb_edr_sentinelone.py --action blacklist   --hash <SHA1>
  python3 pb_edr_sentinelone.py --action chain       --agent-id <ID>   # isolate + collect-ioc + export
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("ERRO: requests não instalado. Execute: pip install requests", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
API_VERSION    = "v2.1"
SAFELABS_NOTE  = "SafeLabs N2 Playbook — automated containment"


# ---------------------------------------------------------------------------
# Env
# ---------------------------------------------------------------------------

def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for p in [path,
              Path(__file__).parent / ".env",
              Path(__file__).parent.parent.parent / "laboratory" / "poc-harpia" / ".env"]:
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


# ---------------------------------------------------------------------------
# SentinelOne API Client
# ---------------------------------------------------------------------------

class S1Client:
    """Cliente REST para SentinelOne Management API."""

    def __init__(self, base_url: str, api_token: str, site_ids: list[str],
                 verify_ssl: bool = True, timeout: int = 30):
        self.base    = base_url.rstrip("/")
        self.headers = {"Authorization": f"ApiToken {api_token}", "Content-Type": "application/json"}
        self.site_ids = site_ids
        self.verify  = verify_ssl
        self.timeout = timeout

    def _url(self, path: str) -> str:
        return f"{self.base}/web/api/{API_VERSION}/{path.lstrip('/')}"

    def get(self, path: str, params: dict | None = None) -> dict:
        if self.site_ids and params is not None:
            params.setdefault("siteIds", ",".join(self.site_ids))
        r = requests.get(self._url(path), headers=self.headers, params=params or {},
                         verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def post(self, path: str, data: dict) -> dict:
        r = requests.post(self._url(path), headers=self.headers, json=data,
                          verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def put(self, path: str, data: dict) -> dict:
        r = requests.put(self._url(path), headers=self.headers, json=data,
                         verify=self.verify, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # Agentes
    # ------------------------------------------------------------------

    def get_agent(self, agent_id: str) -> dict | None:
        r = self.get("agents", {"ids": agent_id})
        data = r.get("data", [])
        return data[0] if data else None

    def list_agents(self, infected: bool | None = None) -> list[dict]:
        params: dict = {"limit": 200}
        if self.site_ids:
            params["siteIds"] = ",".join(self.site_ids)
        if infected is not None:
            params["isInfected"] = str(infected).lower()
        items = []
        while True:
            r = self.get("agents", params)
            items.extend(r.get("data", []))
            cursor = r.get("pagination", {}).get("nextCursor")
            if not cursor:
                break
            params["cursor"] = cursor
        return items

    def isolate_agent(self, agent_id: str) -> dict:
        return self.post("agents/actions/disconnect", {"filter": {"ids": agent_id}})

    def deisolate_agent(self, agent_id: str) -> dict:
        return self.post("agents/actions/connect", {"filter": {"ids": agent_id}})

    def initiate_scan(self, agent_id: str) -> dict:
        return self.post("agents/actions/initiate-scan", {"filter": {"ids": agent_id}})

    # ------------------------------------------------------------------
    # Threats
    # ------------------------------------------------------------------

    def list_threats(self, resolved: bool | None = None,
                     agent_id: str | None = None) -> list[dict]:
        params: dict = {"limit": 200, "sortBy": "createdAt", "sortOrder": "desc"}
        if self.site_ids:
            params["siteIds"] = ",".join(self.site_ids)
        if resolved is not None:
            params["resolved"] = str(resolved).lower()
        if agent_id:
            params["agentIds"] = agent_id
        items = []
        for _ in range(50):  # max 50 pages
            r = self.get("threats", params)
            items.extend(r.get("data", []))
            cursor = r.get("pagination", {}).get("nextCursor")
            if not cursor:
                break
            params["cursor"] = cursor
        return items

    def resolve_threat(self, threat_id: str, verdict: str = "true_positive") -> dict:
        return self.post("threats/actions/resolve", {
            "filter": {"ids": threat_id},
            "data": {"analystVerdict": verdict},
        })

    # ------------------------------------------------------------------
    # Blacklist (hash IOC)
    # ------------------------------------------------------------------

    def add_to_blacklist(self, sha1: str, description: str = "", os_type: str = "windows") -> dict:
        """Adiciona hash SHA1 à blacklist global do site."""
        return self.post("restrictions", {
            "filter": {"siteIds": self.site_ids},
            "data": {
                "type":        "black_hash",
                "value":       sha1,
                "description": description or SAFELABS_NOTE,
                "osType":      os_type,
                "source":      "user",
            },
        })

    def list_blacklist(self) -> list[dict]:
        params: dict = {"type": "black_hash", "limit": 200}
        if self.site_ids:
            params["siteIds"] = ",".join(self.site_ids)
        r = self.get("restrictions", params)
        return r.get("data", [])

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def site_status(self) -> dict:
        params: dict = {"limit": 5}
        if self.site_ids:
            params["ids"] = ",".join(self.site_ids)
        r = self.get("sites", params)
        return {
            "sites": [
                {"name": s.get("name"), "id": s.get("id"), "state": s.get("state")}
                for s in r.get("data", {}).get("sites", [])
            ]
        }


# ---------------------------------------------------------------------------
# IOC extraction from threats payload
# ---------------------------------------------------------------------------

def extract_iocs_from_threat(threat: dict) -> dict:
    """
    Extrai IOCs úteis de um threat item da API SentinelOne.
    Campos baseados nos eventos reais coletados no pipeline threats.jsonl da HIN:
      - threatInfo: {sha256, sha1, md5, filePath, threatName, classification, mitigationStatus}
      - agentDetectionInfo: {agentComputerName, agentIpV4, agentIpV6, agentDomain, agentOsName}
      - agentRealtimeInfo: {agentNetworkStatus, agentInfected, activeThreats, networkInterfaces}
      - indicators: lista de indicadores comportamentais
    """
    ti  = threat.get("threatInfo", {})
    ai  = threat.get("agentDetectionInfo", {})
    ari = threat.get("agentRealtimeInfo", {})

    hashes: dict[str, str] = {}
    if ti.get("sha256"):
        hashes["sha256"] = ti["sha256"]
    if ti.get("sha1"):
        hashes["sha1"] = ti["sha1"]
    if ti.get("md5"):
        hashes["md5"] = ti["md5"]

    # IPs do agente (origem interna)
    agent_ips: list[str] = []
    if ai.get("agentIpV4"):
        agent_ips.extend([ip.strip() for ip in ai["agentIpV4"].split(",") if ip.strip()])
    # Network interfaces (mais detalhado)
    for iface in ari.get("networkInterfaces", []):
        agent_ips.extend(iface.get("inet", []))

    # Indicadores comportamentais (úteis para enriquecer regras)
    behavioral: list[str] = []
    for ind in threat.get("indicators", []):
        desc = ind.get("description", "")
        if desc:
            behavioral.append(desc)

    return {
        "threat_id":         threat.get("id", ""),
        "threat_name":       ti.get("threatName", ""),
        "classification":    ti.get("classification", ""),
        "confidence":        ti.get("confidenceLevel", ""),
        "mitigation_status": ti.get("mitigationStatus", ""),
        "detection_engines": [e.get("title", "") for e in ti.get("detectionEngines", [])],
        "file_path":         ti.get("filePath", ""),
        "file_extension":    ti.get("fileExtension", ""),
        "file_size":         ti.get("fileSize", 0),
        "hashes":            hashes,
        "agent_id":          threat.get("agentRealtimeInfo", {}).get("agentId", ""),
        "agent_name":        ari.get("agentComputerName", ai.get("agentComputerName", "")),
        "agent_domain":      ai.get("agentDomain", ""),
        "agent_os":          ai.get("agentOsName", ari.get("agentOsName", "")),
        "agent_ips":         list(set(agent_ips)),
        "agent_network":     ari.get("agentNetworkStatus", ""),
        "agent_infected":    ari.get("agentInfected", False),
        "active_threats":    ari.get("activeThreats", 0),
        "identified_at":     ti.get("identifiedAt", ""),
        "created_at":        ti.get("createdAt", ""),
        "behavioral":        behavioral,
        "indicators_count":  len(threat.get("indicators", [])),
        "collection_id":     ti.get("collectionId", ""),
    }


def collect_all_iocs(client: S1Client, unresolved_only: bool = True) -> list[dict]:
    """Coleta todos os threats e extrai IOCs estruturados."""
    resolved_filter = False if unresolved_only else None
    threats = client.list_threats(resolved=resolved_filter)
    iocs = []
    for t in threats:
        ioc = extract_iocs_from_threat(t)
        if ioc["threat_name"] or ioc["hashes"]:
            iocs.append(ioc)
    return iocs


# ---------------------------------------------------------------------------
# Export helpers — integração com outros playbooks
# ---------------------------------------------------------------------------

def export_to_fw_csv(iocs: list[dict], out_path: Path) -> int:
    """
    Exporta IPs de agentes infectados como CSV para pb_fw_fortigate.py.
    Formato: action,type,ioc
    Só exporta agentes com network=connected e infected=True ou active_threats > 0.
    """
    rows = []
    for ioc in iocs:
        if not (ioc.get("agent_infected") or ioc.get("active_threats", 0) > 0):
            continue
        for ip in ioc.get("agent_ips", []):
            if ip and not ip.startswith("127.") and not ip.startswith("172.") and not ip.startswith("::"):
                rows.append({
                    "action": "isolate",
                    "type":   "host",
                    "ioc":    ip,
                    "#comment": f"S1 threat: {ioc['threat_name']} | agent: {ioc['agent_name']}",
                })

    if not rows:
        print("[AVISO] Nenhum agente infectado com IP para exportar ao FW")
        return 0

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["action", "type", "ioc", "#comment"])
        w.writeheader()
        w.writerows(rows)

    print(f"[OK] FW CSV exportado: {out_path} ({len(rows)} linhas)")
    return len(rows)


def export_to_dns_list(iocs: list[dict], out_path: Path) -> int:
    """
    Exporta domínios suspeitos para lista do pb_dns_block.py.
    Extrai domínios dos indicadores comportamentais (ex: referências a DNS C2).
    """
    domains: set[str] = set()

    for ioc in iocs:
        # Extrai domínios de indicadores textuais
        for desc in ioc.get("behavioral", []):
            desc_lower = desc.lower()
            if "dns" in desc_lower or "domain" in desc_lower or "c2" in desc_lower:
                # Marcadores de C2 DNS — úteis como nota para bloqueio manual
                pass
        # Domínio do agente (não bloquear — é interno)
        # Futuro: integrar com feeds de inteligência de C2 por hash

    if not domains:
        # Gera template comentado com IOCs de hash para consulta manual em VirusTotal etc.
        lines = [
            "# pb_dns_block.py — Lista gerada por pb_edr_sentinelone.py",
            "# Domínios C2 identificados a partir de threats SentinelOne",
            "# Consulte hashes abaixo em VirusTotal/ANY.RUN para identificar C2 domains",
            "#",
        ]
        for ioc in iocs[:20]:
            if ioc["hashes"].get("sha256"):
                lines.append(f"# {ioc['threat_name']} | SHA256: {ioc['hashes']['sha256']}")
        lines.append("# Adicione domínios C2 confirmados abaixo:")
        lines.append("# malicious-c2.example.com")
        out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"[AVISO] Nenhum domínio C2 extraído automaticamente. Template criado: {out_path}")
        return 0

    out_path.write_text("\n".join(sorted(domains)) + "\n", encoding="utf-8")
    print(f"[OK] DNS list exportado: {out_path} ({len(domains)} domínios)")
    return len(domains)


def export_hash_blacklist(iocs: list[dict], out_path: Path) -> int:
    """Exporta hashes SHA1 únicos para blacklist SentinelOne."""
    hashes: set[str] = set()
    for ioc in iocs:
        if ioc["hashes"].get("sha1"):
            hashes.add(ioc["hashes"]["sha1"])

    if not hashes:
        print("[AVISO] Nenhum hash SHA1 para exportar")
        return 0

    rows = [{"sha1": h, "source": "sentinelone_threat", "note": SAFELABS_NOTE}
            for h in sorted(hashes)]
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["sha1", "source", "note"])
        w.writeheader()
        w.writerows(rows)

    print(f"[OK] Hash blacklist exportado: {out_path} ({len(hashes)} hashes)")
    return len(hashes)


# ---------------------------------------------------------------------------
# Formatação de saída
# ---------------------------------------------------------------------------

def print_agent(agent: dict) -> None:
    info  = agent.get("computerName", "?")
    nstat = agent.get("networkStatus", "?")
    infec = agent.get("isInfected", False)
    thrs  = agent.get("activeThreats", 0)
    os_   = agent.get("osName", "?")
    ver   = agent.get("agentVersion", "?")
    ips   = ", ".join(
        ip for iface in agent.get("networkInterfaces", []) for ip in iface.get("inet", [])
    ) or agent.get("externalIp", "?")
    uid   = agent.get("id", "?")

    print(f"  {info:<20} | {os_:<22} | net={nstat:<11} | infected={'YES' if infec else 'no'} "
          f"| threats={thrs} | ips={ips} | ver={ver} | id={uid}")


def print_ioc(ioc: dict) -> None:
    h = ioc["hashes"]
    print(f"\n  [{ioc['classification']}] {ioc['threat_name']} | {ioc['confidence']}")
    print(f"    Agent    : {ioc['agent_name']} ({ioc['agent_os']}) | net={ioc['agent_network']}")
    print(f"    IPs      : {', '.join(ioc['agent_ips']) or 'N/A'}")
    print(f"    File     : {ioc['file_path']}")
    print(f"    SHA256   : {h.get('sha256','N/A')}")
    print(f"    SHA1     : {h.get('sha1','N/A')}")
    print(f"    MD5      : {h.get('md5','N/A')}")
    print(f"    Mitigation: {ioc['mitigation_status']}")
    print(f"    Engines  : {', '.join(ioc['detection_engines'])}")
    print(f"    Created  : {ioc['created_at']}")
    if ioc["behavioral"]:
        print(f"    Behaviors: {'; '.join(ioc['behavioral'][:3])}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="N2 Playbook — SentinelOne EDR/XDR Containment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  # Isolar agente infectado
  python3 pb_edr_sentinelone.py --action isolate --agent-id 2442300432464470030

  # Remover isolamento após remediar
  python3 pb_edr_sentinelone.py --action deisolate --agent-id 2442300432464470030

  # Acionar scan completo
  python3 pb_edr_sentinelone.py --action scan --agent-id 2442300432464470030

  # Coletar todos os IOCs de threats não resolvidos
  python3 pb_edr_sentinelone.py --action collect-ioc
  python3 pb_edr_sentinelone.py --action collect-ioc --output /tmp/s1_iocs.json --all

  # Exportar IPs de hosts infectados para bloqueio no FortiGate
  python3 pb_edr_sentinelone.py --action export-fw

  # Exportar lista de domínios suspeitos para bloqueio DNS
  python3 pb_edr_sentinelone.py --action export-dns

  # Adicionar hash à blacklist do site
  python3 pb_edr_sentinelone.py --action blacklist --hash 2f6ec65cc3fb2d394df710727786d4614d8ba6c6

  # Listar todos os threats com IOCs
  python3 pb_edr_sentinelone.py --action list-threats

  # Listar agentes (mostra infectados primeiro)
  python3 pb_edr_sentinelone.py --action list-agents

  # Cadeia completa: isolar + coletar IOCs + exportar para FW e DNS
  python3 pb_edr_sentinelone.py --action chain --agent-id 2442300432464470030

  # Status de um agente específico
  python3 pb_edr_sentinelone.py --action status --agent-id 2442300432464470030
""")
    p.add_argument("--action", required=True, choices=[
        "isolate", "deisolate", "scan", "status",
        "collect-ioc", "export-fw", "export-dns", "export-hashes",
        "blacklist", "list-threats", "list-agents", "chain",
    ])
    p.add_argument("--agent-id",  help="ID do agente SentinelOne (obrigatório para isolate/deisolate/scan/status/chain)")
    p.add_argument("--hash",      help="SHA1 hash para blacklist")
    p.add_argument("--output",    help="Arquivo de saída JSON (para collect-ioc)", default=None)
    p.add_argument("--all",       action="store_true", help="Incluir threats já resolvidos (collect-ioc)")
    p.add_argument("--env",       default=None, help="Caminho alternativo para .env")
    p.add_argument("--no-ssl",    action="store_true", help="Desabilitar verificação SSL")
    return p


def main() -> int:
    args  = build_parser().parse_args()
    env   = load_env(Path(args.env) if args.env else Path(".env"))

    base_url   = env.get("S1_BASE_URL", "https://usea1-014.sentinelone.net")
    api_token  = env.get("S1_API_TOKEN", "")
    site_ids   = [s.strip() for s in env.get("S1_SITE_IDS", "").split(",") if s.strip()]
    verify_ssl = env.get("S1_VERIFY_SSL", "true").lower() not in ("0", "false", "no") and not args.no_ssl

    if not api_token:
        print("ERRO: S1_API_TOKEN precisa estar no .env", file=sys.stderr)
        return 2

    client = S1Client(base_url, api_token, site_ids, verify_ssl=verify_ssl)
    out_dir = Path(__file__).parent / "lists" / "examples"
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        # --------------------------------------------------------
        # Isolate / Deisolate / Scan
        # --------------------------------------------------------
        if args.action in ("isolate", "deisolate", "scan"):
            if not args.agent_id:
                print(f"ERRO: --agent-id obrigatório para {args.action}", file=sys.stderr)
                return 2

            if args.action == "isolate":
                r = client.isolate_agent(args.agent_id)
                print(f"[OK] Agente {args.agent_id} ISOLADO da rede")
                print(f"     Resposta: {r.get('data', r)}")

            elif args.action == "deisolate":
                r = client.deisolate_agent(args.agent_id)
                print(f"[OK] Agente {args.agent_id} RECONECTADO à rede")
                print(f"     Resposta: {r.get('data', r)}")

            elif args.action == "scan":
                r = client.initiate_scan(args.agent_id)
                print(f"[OK] Scan iniciado no agente {args.agent_id}")
                print(f"     Resposta: {r.get('data', r)}")

        # --------------------------------------------------------
        # Status
        # --------------------------------------------------------
        elif args.action == "status":
            if not args.agent_id:
                # Status geral do site
                s = client.site_status()
                print("Sites:")
                for site in s["sites"]:
                    print(f"  {site['name']} | id={site['id']} | state={site['state']}")
                return 0

            agent = client.get_agent(args.agent_id)
            if not agent:
                print(f"ERRO: Agente '{args.agent_id}' não encontrado", file=sys.stderr)
                return 1
            print(f"\n  Agente: {agent.get('computerName')}")
            print_agent(agent)

        # --------------------------------------------------------
        # Collect IOCs
        # --------------------------------------------------------
        elif args.action == "collect-ioc":
            iocs = collect_all_iocs(client, unresolved_only=not args.all)
            print(f"\n[ IOCs SentinelOne — {len(iocs)} threats ]")
            for ioc in iocs[:20]:
                print_ioc(ioc)
            if len(iocs) > 20:
                print(f"\n  ... (+{len(iocs)-20} threats omitidos, use --output para dump completo)")

            if args.output:
                Path(args.output).write_text(
                    json.dumps(iocs, ensure_ascii=False, indent=2), encoding="utf-8"
                )
                print(f"\n[OK] IOCs salvos: {args.output}")

            # Resumo de IOCs únicos
            hashes_sha256 = {i["hashes"].get("sha256") for i in iocs if i["hashes"].get("sha256")}
            hashes_sha1   = {i["hashes"].get("sha1")   for i in iocs if i["hashes"].get("sha1")}
            infected_ips  = {ip for i in iocs for ip in i.get("agent_ips", [])
                             if i.get("agent_infected") or i.get("active_threats", 0) > 0}
            print(f"\n  Resumo: {len(hashes_sha256)} SHA256 | {len(hashes_sha1)} SHA1 | "
                  f"{len(infected_ips)} IPs de hosts infectados")

        # --------------------------------------------------------
        # Export FW CSV
        # --------------------------------------------------------
        elif args.action == "export-fw":
            iocs = collect_all_iocs(client, unresolved_only=True)
            out  = out_dir / "s1_fw_isolate.csv"
            n = export_to_fw_csv(iocs, out)
            if n:
                print(f"\n  Use: python3 pb_fw_fortigate.py --csv {out}")

        # --------------------------------------------------------
        # Export DNS list
        # --------------------------------------------------------
        elif args.action == "export-dns":
            iocs = collect_all_iocs(client, unresolved_only=True)
            out  = out_dir / "s1_dns_block.txt"
            n = export_to_dns_list(iocs, out)
            if n:
                print(f"\n  Use: python3 pb_dns_block.py --action block --type domain --list {out}")

        # --------------------------------------------------------
        # Export hash blacklist
        # --------------------------------------------------------
        elif args.action == "export-hashes":
            iocs = collect_all_iocs(client, unresolved_only=False)
            out  = out_dir / "s1_hashes.csv"
            export_hash_blacklist(iocs, out)

        # --------------------------------------------------------
        # Blacklist hash
        # --------------------------------------------------------
        elif args.action == "blacklist":
            if not args.hash:
                print("ERRO: --hash obrigatório para blacklist", file=sys.stderr)
                return 2
            r = client.add_to_blacklist(args.hash, SAFELABS_NOTE)
            print(f"[OK] Hash adicionado à blacklist: {args.hash}")
            print(f"     Resposta: {r.get('data', r)}")

        # --------------------------------------------------------
        # List threats
        # --------------------------------------------------------
        elif args.action == "list-threats":
            threats = client.list_threats(resolved=False)
            print(f"\n[ Threats não resolvidos: {len(threats)} ]\n")
            for t in threats[:30]:
                ioc = extract_iocs_from_threat(t)
                print(f"  [{ioc['classification']:<10}] {ioc['threat_name']:<40} | "
                      f"host={ioc['agent_name']:<15} | "
                      f"mitigation={ioc['mitigation_status']:<15} | "
                      f"sha1={ioc['hashes'].get('sha1','N/A')[:20]}")
            if len(threats) > 30:
                print(f"  ... (+{len(threats)-30} omitidos)")

        # --------------------------------------------------------
        # List agents
        # --------------------------------------------------------
        elif args.action == "list-agents":
            agents = client.list_agents()
            infected = [a for a in agents if a.get("isInfected") or a.get("activeThreats", 0) > 0]
            clean    = [a for a in agents if a not in infected]
            print(f"\n[ Agentes: {len(agents)} total | {len(infected)} infectados ]")
            print("\n  INFECTADOS:")
            for a in infected:
                print_agent(a)
            print("\n  LIMPOS:")
            for a in clean[:10]:
                print_agent(a)
            if len(clean) > 10:
                print(f"  ... (+{len(clean)-10} limpos omitidos)")

        # --------------------------------------------------------
        # Chain: Isolate + Collect IOC + Export FW + Export DNS
        # --------------------------------------------------------
        elif args.action == "chain":
            if not args.agent_id:
                print("ERRO: --agent-id obrigatório para chain", file=sys.stderr)
                return 2

            print(f"\n[CHAIN] Iniciando contenção automática para agente {args.agent_id}")

            # 1. Verificar status atual
            agent = client.get_agent(args.agent_id)
            if not agent:
                print(f"ERRO: Agente '{args.agent_id}' não encontrado", file=sys.stderr)
                return 1
            print(f"\n[1/4] Agente encontrado: {agent.get('computerName')}")
            print_agent(agent)

            # 2. Isolar
            print(f"\n[2/4] Isolando agente da rede...")
            r = client.isolate_agent(args.agent_id)
            isolated = r.get("data", {})
            print(f"      Resultado: {isolated.get('affected', '?')} agentes afetados")

            # 3. Coletar IOCs
            print(f"\n[3/4] Coletando IOCs de threats do agente...")
            iocs = collect_all_iocs(client, unresolved_only=True)
            agent_iocs = [i for i in iocs if i.get("agent_id") == args.agent_id
                          or i.get("agent_name") == agent.get("computerName")]
            print(f"      {len(agent_iocs)} threats com IOCs para este agente")
            for ioc in agent_iocs[:5]:
                print_ioc(ioc)

            # 4. Exportar para FW e DNS
            print(f"\n[4/4] Exportando IOCs para outros playbooks...")
            fw_out  = out_dir / f"s1_chain_{args.agent_id}_fw.csv"
            dns_out = out_dir / f"s1_chain_{args.agent_id}_dns.txt"
            hash_out = out_dir / f"s1_chain_{args.agent_id}_hashes.csv"

            export_to_fw_csv(agent_iocs or iocs[:5], fw_out)
            export_to_dns_list(iocs, dns_out)
            export_hash_blacklist(agent_iocs or iocs, hash_out)

            # Salvar IOCs completos
            ioc_out = out_dir / f"s1_chain_{args.agent_id}_iocs.json"
            ioc_out.write_text(
                json.dumps(agent_iocs or iocs[:10], ensure_ascii=False, indent=2),
                encoding="utf-8"
            )

            print(f"""
[CHAIN CONCLUÍDO]
  Agente isolado    : {agent.get('computerName')} (id={args.agent_id})
  IOCs exportados   :
    FW CSV          : {fw_out}
    DNS list        : {dns_out}
    Hash blacklist  : {hash_out}
    IOC JSON        : {ioc_out}

  Próximos passos:
    python3 pb_fw_fortigate.py --csv {fw_out}
    python3 pb_dns_block.py --action block --type domain --list {dns_out}
    python3 pb_ad_containment.py --action status --user <usuario_afetado>
""")

        return 0

    except requests.HTTPError as e:
        body = e.response.text[:300] if e.response else ""
        print(f"ERRO HTTP {e.response.status_code if e.response else '?'}: {body}", file=sys.stderr)
        return 1
    except requests.RequestException as e:
        print(f"ERRO de rede: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERRO: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
