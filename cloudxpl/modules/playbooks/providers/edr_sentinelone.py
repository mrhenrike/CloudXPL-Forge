"""
Provider — SentinelOne (REST API)
===================================
Implementação concreta de EDRProvider para SentinelOne.
Toda lógica de API extraída de server_edr.py — mesmo comportamento,
agora encapsulada em classe reutilizável.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""
from __future__ import annotations

from typing import Any

from .base import EDRProvider


class SentinelOneProvider(EDRProvider):
    """SentinelOne EDR/XDR via REST API v2.1."""

    def __init__(
        self,
        base_url: str,
        api_token: str,
        site_ids: list[str] | None = None,
        verify_ssl: bool = True,
        timeout: int = 30,
    ) -> None:
        """Inicializa provider com credenciais S1.

        Args:
            base_url: URL base do console (ex: https://usea1-014.sentinelone.net).
            api_token: Token de API do SentinelOne.
            site_ids: Lista de site IDs para escopo das queries.
            verify_ssl: Verificar certificado TLS.
            timeout: Timeout HTTP em segundos.
        """
        try:
            import requests
            requests.packages.urllib3.disable_warnings()
        except ImportError:
            raise RuntimeError("pip install requests")

        self._base_url = base_url.rstrip("/")
        self._token = api_token
        self._site_ids = site_ids or []
        self._verify = verify_ssl
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"ApiToken {self._token}",
            "Content-Type": "application/json",
        })
        self._session.verify = self._verify

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict | None = None) -> dict:
        """GET na API v2.1 do SentinelOne."""
        p = dict(params or {})
        if self._site_ids:
            p.setdefault("siteIds", ",".join(self._site_ids))
        r = self._session.get(
            f"{self._base_url}/web/api/v2.1/{path.lstrip('/')}",
            params=p,
            timeout=self._timeout,
        )
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, data: dict) -> dict:
        """POST na API v2.1 do SentinelOne."""
        r = self._session.post(
            f"{self._base_url}/web/api/v2.1/{path.lstrip('/')}",
            json=data,
            timeout=self._timeout,
        )
        r.raise_for_status()
        return r.json()

    # ------------------------------------------------------------------
    # EDRProvider — métodos públicos
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """Verifica conectividade e retorna info básica."""
        r = self._get("agents", {"limit": 1})
        agents = r.get("data", [])
        return {
            "platform": "SentinelOne",
            "base_url": self._base_url,
            "site_ids": self._site_ids,
            "status": "connected",
            "agents_found": len(agents),
        }

    def list_agents(self, infected_only: bool = False) -> list:
        """Lista agentes com hostname, IP, status de rede e ameaças ativas."""
        params: dict[str, Any] = {"limit": 200}
        if infected_only:
            params["isInfected"] = "true"
        r = self._get("agents", params)
        agents = r.get("data", [])
        rows: list[dict[str, Any]] = []
        for a in agents:
            ips = ", ".join(
                ip for iface in a.get("networkInterfaces", []) for ip in iface.get("inet", [])
            ) or a.get("externalIp", "?")
            rows.append({
                "id": a.get("id"),
                "name": a.get("computerName"),
                "os": a.get("osName"),
                "network": a.get("networkStatus"),
                "infected": a.get("isInfected", False),
                "active_threats": a.get("activeThreats", 0),
                "ips": ips,
                "version": a.get("agentVersion"),
            })
        return rows

    def isolate_agent(self, agent_id: str, reason: str = "SafeLabs MCP — incident response") -> dict:
        """Isola agente da rede (Network Quarantine)."""
        r = self._post("agents/actions/disconnect", {"filter": {"ids": agent_id}})
        return {
            "action": "isolated",
            "agent_id": agent_id,
            "affected": r.get("data", {}).get("affected", "?"),
            "reason": reason,
        }

    def deisolate_agent(self, agent_id: str) -> dict:
        """Remove isolamento de rede do agente."""
        r = self._post("agents/actions/connect", {"filter": {"ids": agent_id}})
        return {
            "action": "reconnected",
            "agent_id": agent_id,
            "affected": r.get("data", {}).get("affected", "?"),
        }

    def scan_agent(self, agent_id: str) -> dict:
        """Aciona scan completo no agente."""
        r = self._post("agents/actions/initiate-scan", {"filter": {"ids": agent_id}})
        return {
            "action": "scan_initiated",
            "agent_id": agent_id,
            "data": r.get("data", {}),
        }

    def list_threats(self, unresolved_only: bool = True) -> list:
        """Lista threats com IOCs extraídos."""
        params: dict[str, Any] = {"limit": 50, "sortBy": "createdAt", "sortOrder": "desc"}
        if unresolved_only:
            params["resolved"] = "false"
        r = self._get("threats", params)
        threats = r.get("data", [])
        return [self._extract_threat_iocs(t) for t in threats]

    def blacklist_hash(self, sha1: str, description: str = "SafeLabs MCP — IOC blacklist") -> dict:
        """Adiciona SHA1 à blacklist global do S1."""
        r = self._post("restrictions", {
            "filter": {"siteIds": self._site_ids},
            "data": {
                "type": "black_hash",
                "value": sha1,
                "description": description,
                "osType": "windows",
                "source": "user",
            },
        })
        return {"action": "blacklisted", "sha1": sha1, "data": r.get("data", {})}

    def collect_iocs(self) -> dict:
        """Coleta IOCs de todas as threats não resolvidas."""
        params: dict[str, Any] = {"limit": 200, "sortBy": "createdAt", "sortOrder": "desc", "resolved": "false"}
        r = self._get("threats", params)
        threats = r.get("data", [])

        all_iocs = [self._extract_threat_iocs(t) for t in threats]

        hashes_sha256 = {i["sha256"] for i in all_iocs if i["sha256"]}
        hashes_sha1 = {i["sha1"] for i in all_iocs if i["sha1"]}
        infected_ips = {
            ip for i in all_iocs for ip in i["agent_ips"]
            if i["infected"] or i["active_threats"] > 0
        }
        infected_names = {
            i["agent_name"] for i in all_iocs
            if i["infected"] or i["active_threats"] > 0
        }

        return {
            "total_threats": len(all_iocs),
            "unique_sha256": len(hashes_sha256),
            "unique_sha1": len(hashes_sha1),
            "infected_host_ips": sorted(infected_ips),
            "infected_host_names": sorted(infected_names),
            "top_threats": [i["threat_name"] for i in all_iocs[:10]],
            "iocs": all_iocs,
        }

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_threat_iocs(threat: dict) -> dict:
        """Extrai IOCs estruturados de um objeto threat do S1."""
        ti = threat.get("threatInfo", {})
        ai = threat.get("agentDetectionInfo", {})
        ari = threat.get("agentRealtimeInfo", {})
        agent_ips = [ip.strip() for ip in (ai.get("agentIpV4") or "").split(",") if ip.strip()]
        for iface in ari.get("networkInterfaces", []):
            agent_ips.extend(iface.get("inet", []))
        return {
            "threat_id": threat.get("id", ""),
            "threat_name": ti.get("threatName", ""),
            "classification": ti.get("classification", ""),
            "confidence": ti.get("confidenceLevel", ""),
            "mitigation": ti.get("mitigationStatus", ""),
            "file_path": ti.get("filePath", ""),
            "sha256": ti.get("sha256", ""),
            "sha1": ti.get("sha1", ""),
            "md5": ti.get("md5", ""),
            "agent_id": ari.get("agentId", ""),
            "agent_name": ari.get("agentComputerName", ai.get("agentComputerName", "")),
            "agent_domain": ai.get("agentDomain", ""),
            "agent_ips": list(set(agent_ips)),
            "network_status": ari.get("agentNetworkStatus", ""),
            "infected": ari.get("agentInfected", False),
            "active_threats": ari.get("activeThreats", 0),
            "identified_at": ti.get("identifiedAt", ""),
            "engines": [e.get("title", "") for e in ti.get("detectionEngines", [])],
            "behaviors": [i.get("description", "") for i in threat.get("indicators", [])],
        }
