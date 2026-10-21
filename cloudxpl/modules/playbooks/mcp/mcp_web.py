#!/usr/bin/env python3
"""
SafeLabs MCP Web — SOC Containment Dashboard v5
Tabs: Dashboard | Firewall | EDR/XDR | Active Directory | DNS | Threat Intel | Settings
Author: André Henrique (@mrhenrike) | União Geek
"""
import json, os, re, sys, threading, traceback, urllib.parse, time, uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import Path
try:
    import urllib.request as _ureq
    import ssl as _ssl
except ImportError:
    _ureq = None

MCP_DIR = Path(__file__).parent.parent / "mcp"
sys.path.insert(0, str(MCP_DIR))

_ENV: dict = {}
for _ep in [MCP_DIR / ".env", Path(__file__).parent / ".env"]:
    if _ep.is_file():
        for _l in _ep.read_text(encoding="utf-8").splitlines():
            _l = _l.strip()
            if _l and not _l.startswith("#") and "=" in _l:
                k, _, v = _l.partition("=")
                _ENV.setdefault(k.strip(), v.strip().strip('"').strip("'"))
for k, v in _ENV.items():
    os.environ.setdefault(k, v)

_fw = _edr = _ad = None
_load_errors: dict = {}
_ready = False

def _load(name):
    import importlib.util
    spec = importlib.util.spec_from_file_location(name, MCP_DIR / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def _init():
    global _fw, _edr, _ad, _ready
    for name, attr in [("server_fw","_fw"),("server_edr","_edr"),("server_ad_dns","_ad")]:
        try:
            globals()[attr] = _load(name)
        except Exception as e:
            _load_errors[name] = str(e)
    _ready = True

threading.Thread(target=_init, daemon=True).start()

def _san(val: str, maxlen: int = 512) -> str:
    return re.sub(r"[;&|`$<>{}\\]", "", str(val).strip())[:maxlen]

def _call(fn_path: str, *args) -> str:
    if not _ready:
        return json.dumps({"error": "Modules loading, try again in 5s"})
    try:
        mod_key, fn_name = fn_path.split(".", 1)
        mod = {"fw": _fw, "edr": _edr, "ad": _ad}.get(mod_key)
        if not mod:
            return json.dumps({"error": f"Module '{mod_key}' not loaded: {_load_errors.get('server_'+mod_key,'')}"})
        fn = getattr(mod, fn_name, None)
        if not fn:
            return json.dumps({"error": f"Function '{fn_name}' not found"})
        result = fn(*args)
        return result if isinstance(result, str) else json.dumps(result, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": str(e), "trace": traceback.format_exc()[-400:]})

# ─── CACHE ───────────────────────────────────────────────────────────────────
_cache: dict = {}
APT_CACHE_TTL   = int(_ENV.get("APT_CACHE_TTL", "86400"))
RULES_CACHE_TTL = int(_ENV.get("RULES_CACHE_TTL", "3600"))
OTX_API_KEY     = _ENV.get("OTX_API_KEY", "")

def _cached(key: str, ttl: int, fn):
    now = time.time()
    c = _cache.get(key)
    if c and (now - c["ts"]) < ttl:
        return c["data"]
    try:
        data = fn()
        _cache[key] = {"data": data, "ts": now}
        return data
    except Exception as e:
        if c: return c["data"]
        return {"error": str(e)}

# === APT CAMPAIGNS & THREAT INTEL ===
_APT_DB_PATH = Path(__file__).parent / "apt_campaigns.json"
_apt_lock = threading.Lock()

def _load_apt_campaigns() -> list:
    with _apt_lock:
        if _APT_DB_PATH.is_file():
            try:
                return json.loads(_APT_DB_PATH.read_text(encoding="utf-8"))
            except Exception:
                pass
        _APT_DB_PATH.write_text("[]", encoding="utf-8")
        return []

def _save_apt_campaigns(data: list) -> None:
    with _apt_lock:
        _APT_DB_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def _get_apt_campaigns(days: int = 90) -> list:
    return _load_apt_campaigns()

def _fetch_otx_pulses(days: int = 90) -> list:
    return _get_apt_campaigns(days)

def _get_containment_status() -> dict:
    def _fetch():
        status = {"fw_iocs": {}, "dns_blocked": [], "edr_agents": [], "edr_hashes": [], "dns_count": 0}
        try:
            r = _call("fw.fw_list_iocs")
            parsed = json.loads(r) if isinstance(r, str) else r
            status["fw_iocs"] = parsed if isinstance(parsed, dict) else {}
        except Exception:
            pass
        try:
            r = json.loads(_call("ad.dns_list_blocked"))
            status["dns_blocked"] = r.get("blocked_domains", [])
            status["dns_count"] = r.get("count", 0)
        except Exception:
            pass
        try:
            r = json.loads(_call("edr.edr_list_agents"))
            status["edr_agents"] = r if isinstance(r, list) else []
        except Exception:
            pass
        try:
            r = json.loads(_call("edr.edr_get_blacklist_hashes"))
            bl = r.get("hashes", []) if r.get("ok") else []
            status["edr_hashes"] = [h.get("value", "").lower() for h in bl]
        except Exception:
            pass
        return status
    return _cached("containment_status", RULES_CACHE_TTL, _fetch)

def _apt_containment_check(campaign_id: str) -> dict:
    campaigns = _load_apt_campaigns()
    camp = next((cp for cp in campaigns if cp.get("id") == campaign_id), None)
    if not camp:
        return {"error": "Campaign not found"}
    status = _get_containment_status()
    fw_raw = json.dumps(status.get("fw_iocs", {}))
    dns_blocked = {d.lower() for d in status.get("dns_blocked", [])}
    edr_hashes = {h.lower() for h in status.get("edr_hashes", [])}
    iocs = camp.get("iocs", {})
    ips = iocs.get("ips", [])
    domains = iocs.get("domains", [])
    hashes = iocs.get("hashes", [])
    urls = iocs.get("urls", [])
    ips_ok = [ip for ip in ips if ip.replace(".", "_") in fw_raw]
    doms_fw = [d for d in domains if d.replace(".", "_") in fw_raw]
    doms_dns = [d for d in domains if d.lower() in dns_blocked]
    doms_ok = list(set(doms_fw) | set(doms_dns))
    hash_ok = [h for h in hashes if h.lower() in edr_hashes]
    fw_urls = {u.lower() for u in status.get("fw_iocs", {}).get("blocked_urls", [])}
    # Simpler: check if url domain/path is in blocked_urls
    def _url_blocked(u, blocked):
        u_lower = u.lower().replace("http://","").replace("https://","")
        for bu in blocked:
            bu_clean = bu.lower().replace("http://","").replace("https://","").lstrip("*.")
            if bu_clean in u_lower or u_lower.startswith(bu_clean):
                return True
        return False
    urls_ok = [u for u in urls if _url_blocked(u, fw_urls)]
    total = len(ips) + len(domains) + len(hashes) + len(urls)
    blocked = len(ips_ok) + len(doms_ok) + len(hash_ok) + len(urls_ok)
    pct = round(100 * blocked / total) if total else 100
    return {
        "campaign_id": campaign_id,
        "campaign_name": camp.get("name", ""),
        "total_iocs": total, "total_blocked": blocked, "pct_contained": pct,
        "ips": {"total": len(ips), "blocked": len(ips_ok), "gaps": [ip for ip in ips if ip not in ips_ok]},
        "domains": {"total": len(domains), "blocked": len(doms_ok), "gaps": [d for d in domains if d not in doms_ok]},
        "hashes": {"total": len(hashes), "blocked": len(hash_ok), "gaps": [h for h in hashes if h.lower() not in edr_hashes]},
        "urls": {"total": len(urls), "blocked": len(urls_ok), "gaps": [u for u in urls if u not in urls_ok]},
        "last_check": datetime.now(timezone.utc).isoformat(),
    }


# ─── CONFIG ──────────────────────────────────────────────────────────────────
_SENSITIVE_KEYS = {"FORTIGATE_SSH_PASSWORD", "FORTIGATE_RESTFUL_API_KEY", "S1_API_TOKEN",
                   "DOMAIN_ADMIN_PASSWORD", "BASTION_PASS", "VM_DC01_DOMAIN_PASS",
                   "OTX_API_KEY", "VT_API_KEY"}
_CONFIG_GROUPS = {
    "firewall": ["FORTIGATE_WEB_IP", "FORTIGATE_WEB_PORT", "FORTIGATE_WEB_PROTOCOL",
                 "FORTIGATE_TRANSPORT", "FORTIGATE_SSH_USER", "FORTIGATE_SSH_PASSWORD",
                 "FORTIGATE_RESTFUL_API_KEY", "FORTIGATE_VDOM"],
    "edr": ["S1_BASE_URL", "S1_API_TOKEN", "S1_SITE_IDS", "S1_VERIFY_SSL"],
    "ad": ["VM_DC01_IP", "DOMAIN_NAME", "DOMAIN_ADMIN", "DOMAIN_ADMIN_PASSWORD",
           "LDAP_PORT", "LDAP_USE_SSL", "AD_TRANSPORT"],
    "dns": ["VM_DNS_IP", "DNS_USE_BASTION", "WINRM_PORT", "WINRM_TRANSPORT",
            "BASTION_IP", "BASTION_USER", "BASTION_PASS"],
    "threat_intel": ["OTX_API_KEY", "VT_API_KEY", "APT_CACHE_TTL", "RULES_CACHE_TTL"],
}

def _get_config_masked() -> dict:
    result = {}
    for group, keys in _CONFIG_GROUPS.items():
        g = {}
        for k in keys:
            v = _ENV.get(k, "")
            if k in _SENSITIVE_KEYS and v:
                g[k] = "****" + v[-4:] if len(v) > 4 else "****"
            else:
                g[k] = v
        result[group] = g
    return result

def _update_config(updates: dict) -> dict:
    env_path = MCP_DIR / ".env"
    if not env_path.is_file():
        return {"error": ".env not found"}
    lines = env_path.read_text(encoding="utf-8").splitlines()
    changed = 0
    for key, val in updates.items():
        if val == "****" or not val.strip():
            continue
        key = _san(key, 64)
        val = val.strip()
        found = False
        for i, line in enumerate(lines):
            if line.strip().startswith(f"{key}="):
                lines[i] = f"{key}={val}"
                _ENV[key] = val
                os.environ[key] = val
                found = True
                changed += 1
                break
        if not found:
            lines.append(f"{key}={val}")
            _ENV[key] = val
            os.environ[key] = val
            changed += 1
    if changed:
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"ok": True, "changed": changed}


# === INTEGRATIONS LAYER ===
_INTEGRATIONS_PATH = Path(__file__).parent / "integrations.json"
_intg_lock = threading.Lock()

_DEFAULT_INTEGRATIONS = [
    {"id": "fortigate-lab", "name": "FortiGate LAB",
     "class": "firewall", "vendor": "Fortinet", "product": "FortiGate",
     "integration_method": "api", "fallback_method": "ssh", "enabled": True,
     "capabilities": {"block_ip": True, "block_domain": True, "block_url": True,
                      "isolate_host": True, "list_iocs": True}},
    {"id": "sentinelone-lab", "name": "SentinelOne LAB",
     "class": "edr", "vendor": "SentinelOne", "product": "SentinelOne",
     "integration_method": "api", "enabled": True,
     "capabilities": {"blacklist_hash": True, "isolate_agent": True,
                      "deisolate_agent": True, "scan_agent": True,
                      "read_threats": True, "read_agents": True}},
    {"id": "microsoft-ad-lab", "name": "Active Directory LAB",
     "class": "identity", "vendor": "Microsoft", "product": "Active Directory",
     "integration_method": "ldap", "enabled": True,
     "capabilities": {"query_user": True, "disable_user": True, "enable_user": True,
                      "reset_password": True, "unlock_user": True, "list_users": True}},
    {"id": "microsoft-dns-lab", "name": "DNS Server LAB",
     "class": "dns", "vendor": "Microsoft", "product": "DNS Server",
     "integration_method": "bastion-ssh", "enabled": True,
     "capabilities": {"block_domain": True, "unblock_domain": True,
                      "flush_cache": True, "list_blocked": True}},
]

def _load_integrations() -> list:
    with _intg_lock:
        if _INTEGRATIONS_PATH.is_file():
            try:
                return json.loads(_INTEGRATIONS_PATH.read_text(encoding="utf-8"))
            except Exception:
                pass
        data = [dict(i) for i in _DEFAULT_INTEGRATIONS]
        _INTEGRATIONS_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return data

def _save_integrations(data: list) -> None:
    with _intg_lock:
        _INTEGRATIONS_PATH.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def _guard(cls: str, capability: str):
    integrations = _load_integrations()
    active = [i for i in integrations if i.get("class") == cls and i.get("enabled", False)]
    if not active:
        return {"error": f"Nenhuma integracao habilitada para classe {cls!r}", "code": 403}
    for intg in active:
        if intg.get("capabilities", {}).get(capability, False):
            return None
    return {"error": f"Capability {capability!r} desabilitada em {cls!r}", "code": 403}

_INTEGRATION_CATALOG = {
    "firewall": {"label": "Firewall / Network Security", "products": {"Fortinet": {"FortiGate": {
        "methods": ["api", "ssh"], "fallback": "ssh",
        "description": "FortiGate NGFW - bloqueio de IP, dominio, URL e isolamento de host",
        "capabilities": {"block_ip": "Bloqueio de IP", "block_domain": "Bloqueio de Dominio (DNS Filter)",
                         "block_url": "Bloqueio de URL (URL Filter)", "isolate_host": "Isolamento de Host/Sub-rede",
                         "list_iocs": "Listagem de Bloqueios Ativos"},
        "form_fields": [
            {"name": "host", "label": "IP/Host", "type": "text", "required": True, "env": "FORTIGATE_WEB_IP", "tooltip": "IP publico ou hostname do FortiGate"},
            {"name": "port", "label": "Porta", "type": "text", "required": True, "default": "80", "env": "FORTIGATE_WEB_PORT"},
            {"name": "protocol", "label": "Protocolo", "type": "select", "options": ["http", "https"], "env": "FORTIGATE_WEB_PROTOCOL"},
            {"name": "transport", "label": "Transport primario", "type": "select", "options": ["api", "ssh"], "env": "FORTIGATE_TRANSPORT", "tooltip": "api=REST API (primario); ssh=CLI SSH (primario)", "onchange": True},
            {"name": "api_key", "label": "API Key", "type": "password", "required": True, "env": "FORTIGATE_RESTFUL_API_KEY", "show_when_transport": ["api"]},
            {"name": "ssh_user", "label": "SSH User (fallback)", "type": "text", "required": False, "env": "FORTIGATE_SSH_USER", "show_when_transport": ["api"], "tooltip": "Opcional - usado como fallback quando API falhar"},
            {"name": "ssh_password", "label": "SSH Password (fallback)", "type": "password", "required": False, "env": "FORTIGATE_SSH_PASSWORD", "show_when_transport": ["api"], "tooltip": "Opcional - usado como fallback quando API falhar"},
            {"name": "ssh_user_main", "label": "SSH User", "type": "text", "required": True, "env": "FORTIGATE_SSH_USER", "show_when_transport": ["ssh"]},
            {"name": "ssh_password_main", "label": "SSH Password", "type": "password", "required": True, "env": "FORTIGATE_SSH_PASSWORD", "show_when_transport": ["ssh"]},
            {"name": "test_interval", "label": "Intervalo de testes (seg)", "type": "text", "default": "21600", "env": "", "tooltip": "Intervalo automatico de teste de conexao em segundos. 21600=6h, 3600=1h, 0=desabilitado"},
            {"name": "vdom", "label": "VDOM", "type": "text", "required": False, "default": "root", "env": "FORTIGATE_VDOM", "tooltip": "Virtual Domain (default: root)"},
        ], "test_fn": "fw.fw_status"}}}},
    "edr": {"label": "EDR / XDR / Endpoint Security", "products": {"SentinelOne": {"SentinelOne": {
        "methods": ["api"],
        "description": "SentinelOne Singularity - blacklist de hash, isolamento e threats",
        "capabilities": {"blacklist_hash": "Bloqueio por Hash (SHA1/SHA256)", "isolate_agent": "Isolamento de Agente",
                         "deisolate_agent": "Remocao de Isolamento", "scan_agent": "Scan Remoto",
                         "read_threats": "Leitura de Threats", "read_agents": "Leitura de Agentes"},
        "form_fields": [
            {"name": "base_url", "label": "Server URL", "type": "text", "required": True, "env": "S1_BASE_URL", "tooltip": "Ex: https://usea1-partners.sentinelone.net"},
            {"name": "api_token", "label": "API Token", "type": "password", "required": True, "env": "S1_API_TOKEN"},
            {"name": "site_ids", "label": "Site IDs", "type": "text", "required": False, "env": "S1_SITE_IDS", "tooltip": "IDs separados por virgula"},
            {"name": "verify_ssl", "label": "Verificar SSL", "type": "select", "options": ["true", "false"], "default": "true", "env": "S1_VERIFY_SSL"},
            {"name": "test_interval", "label": "Intervalo de testes (seg)", "type": "text", "default": "21600", "env": "", "tooltip": "21600=6h, 3600=1h, 0=desabilitado"},
        ], "test_fn": "edr.edr_status"}}}},
    "identity": {"label": "Identity / IAM", "products": {"Microsoft": {"Active Directory": {
        "methods": ["ldap", "winrm"],
        "description": "Microsoft Active Directory - consulta e acoes em contas via LDAP",
        "capabilities": {"query_user": "Consultar Usuario", "disable_user": "Desabilitar Conta",
                         "enable_user": "Habilitar Conta", "reset_password": "Resetar Senha",
                         "unlock_user": "Desbloquear Conta", "list_users": "Listar Usuarios"},
        "form_fields": [
            {"name": "dc_ip", "label": "IP do Domain Controller", "type": "text", "required": True, "env": "VM_DC01_IP"},
            {"name": "domain", "label": "Domain Name", "type": "text", "required": True, "env": "DOMAIN_NAME", "tooltip": "Ex: empresa.local"},
            {"name": "admin_user", "label": "Username", "type": "text", "required": True, "env": "DOMAIN_ADMIN", "tooltip": "Conta de servico com permissao de leitura de Event Log"},
            {"name": "admin_password", "label": "Password", "type": "password", "required": True, "env": "DOMAIN_ADMIN_PASSWORD"},
            {"name": "port", "label": "Porta", "type": "text", "default": "389", "env": "LDAP_PORT", "tooltip": "389=ldap, 636=ldaps, 5985=winrm-http, 5986=winrm-https"},
            {"name": "transport", "label": "Transport", "type": "select", "options": ["ldap", "ldaps", "winrm-http", "winrm-https"], "default": "ldap", "env": "AD_TRANSPORT", "onchange": True},
            {"name": "test_interval", "label": "Intervalo de testes (seg)", "type": "text", "default": "21600", "env": "", "tooltip": "21600=6h, 3600=1h, 0=desabilitado"},
            {"name": "cert_path", "label": "Certificado TLS (path na HIN)", "type": "text", "required": False, "env": "AD_CERT_PATH", "placeholder": "/opt/certs/ad-cert.pem", "tooltip": "Path do certificado PEM para ldaps ou winrm-https", "show_when_transport": ["ldaps", "winrm-https"]},
        ], "test_fn": "ad.ad_list_disabled_users"}}}},
    "dns": {"label": "DNS Server", "products": {"Microsoft": {"DNS Server": {
        "methods": ["winrm", "bastion-ssh"],
        "description": "Microsoft Windows DNS Server - DNS sinkhole via WinRM ou SSH bastion",
        "capabilities": {"block_domain": "Sinkhole de Dominio", "unblock_domain": "Remover Sinkhole",
                         "flush_cache": "Flush de Cache DNS", "list_blocked": "Listagem de Dominios Bloqueados"},
        "form_fields": [
            {"name": "dc_ip", "label": "IP do Domain Controller / DNS Server", "type": "text", "required": True, "env": "VM_DC01_IP", "tooltip": "IP do Windows Server que hospeda o DNS (geralmente o DC01)"},
            {"name": "domain", "label": "Domain Name", "type": "text", "required": True, "env": "DOMAIN_NAME", "tooltip": "Ex: empresa.local"},
            {"name": "admin_user", "label": "Username", "type": "text", "required": True, "env": "DOMAIN_ADMIN", "tooltip": "Conta com permissao de administrar DNS"},
            {"name": "admin_password", "label": "Password", "type": "password", "required": True, "env": "DOMAIN_ADMIN_PASSWORD"},
            {"name": "port", "label": "Porta", "type": "text", "default": "389", "env": "LDAP_PORT", "tooltip": "389=ldap, 636=ldaps, 5985=winrm-http, 5986=winrm-https"},
            {"name": "transport", "label": "Transport", "type": "select", "options": ["ldap", "ldaps", "winrm-http", "winrm-https"], "default": "winrm-http", "env": "AD_TRANSPORT", "onchange": True},
            {"name": "test_interval", "label": "Intervalo de testes (seg)", "type": "text", "default": "21600", "env": "", "tooltip": "21600=6h, 3600=1h, 0=desabilitado"},
            {"name": "cert_path", "label": "Certificado TLS (path na HIN)", "type": "text", "required": False, "env": "AD_CERT_PATH", "placeholder": "/opt/certs/dc-cert.pem", "tooltip": "Path do certificado PEM para ldaps ou winrm-https", "show_when_transport": ["ldaps", "winrm-https"]},
        ], "test_fn": "ad.dns_status"}}}},
}

_PLAYBOOKS_CATALOG = {
    "firewall": {"Fortinet": {"FortiGate": [
        {"id": "fw_block_ip", "name": "Bloquear IP/CIDR",
         "description": "Adiciona endereco IP ou bloco CIDR a lista de bloqueio no FortiGate via address group.",
         "inputs": [
             {"name": "ip_address", "required": True, "format": "IPv4 ou CIDR", "example": "1.2.3.4 | 192.168.1.0/24",
              "source": "src_ip, dest_ip, attacker_ip, blocked_ip, remote_ip"},
             {"name": "comment", "required": False, "format": "string", "example": "SafeLabs SOC - APT block"},
             {"name": "ttl_minutes", "required": False, "format": "inteiro (minutos)", "example": "60 (0 = permanente)"},
         ]},
        {"id": "fw_unblock_ip", "name": "Desbloquear IP/CIDR",
         "description": "Remove IP ou CIDR da lista de bloqueio.",
         "inputs": [
             {"name": "ip_address", "required": True, "format": "IPv4 ou CIDR", "example": "1.2.3.4"},
         ]},
        {"id": "fw_block_domain", "name": "Bloquear Dominio (DNS Filter)",
         "description": "Adiciona dominio ao DNS filter do FortiGate, bloqueando a resolucao DNS.",
         "inputs": [
             {"name": "domain", "required": True, "format": "FQDN", "example": "evil-domain.com | phishing.net",
              "source": "domain, hostname, dns_query, url (extrair dominio)"},
             {"name": "ttl_minutes", "required": False, "format": "inteiro", "example": "0 (permanente)"},
         ]},
        {"id": "fw_block_url", "name": "Bloquear URL (URL Filter)",
         "description": "Adiciona URL especifica ao URL filter, bloqueando acesso HTTP/HTTPS.",
         "inputs": [
             {"name": "url", "required": True, "format": "URL completa ou parcial", "example": "http://evil.com/payload | *.malware.com/*",
              "source": "url, request_url, http_url, web_url"},
             {"name": "ttl_minutes", "required": False, "format": "inteiro", "example": "0"},
         ]},
        {"id": "fw_isolate_host", "name": "Isolar Host da Rede",
         "description": "Adiciona IP ao grupo de hosts isolados, bloqueando todo trafego externo do endpoint.",
         "inputs": [
             {"name": "ip", "required": True, "format": "IPv4 (IP interno do host)", "example": "10.254.2.100",
              "source": "src_ip, host_ip, device_ip, internal_ip"},
             {"name": "reason", "required": False, "format": "string", "example": "Ransomware detected - SOC isolation"},
             {"name": "ttl_minutes", "required": False, "format": "inteiro", "example": "0"},
         ]},
        {"id": "fw_deisolate_host", "name": "Remover Isolamento",
         "description": "Remove host do grupo de isolamento, restaurando acesso a rede.",
         "inputs": [
             {"name": "ip", "required": True, "format": "IPv4", "example": "10.254.2.100"},
         ]},
    ]}},
    "edr": {"SentinelOne": {"SentinelOne": [
        {"id": "edr_blacklist_hash", "name": "Bloquear Hash de Arquivo",
         "description": "Adiciona hash SHA1 ou SHA256 a blacklist do SentinelOne, impedindo execucao do arquivo em todos os endpoints.",
         "inputs": [
             {"name": "hash_value", "required": True, "format": "SHA1 (40 hex) ou SHA256 (64 hex)", "example": "3020BD9D4609842A1CBC4682CDF9C30F67776991 (SHA1) | a1b2c3... (SHA256)",
              "source": "file_hash, sha1, sha256, md5 (converter para SHA1/SHA256), hash, filehash"},
             {"name": "description", "required": False, "format": "string", "example": "Malware block - Ticket #123"},
         ]},
        {"id": "edr_isolate_agent", "name": "Isolar Agente/Endpoint",
         "description": "Coloca o endpoint em isolamento de rede via agente SentinelOne (quarentena).",
         "inputs": [
             {"name": "agent_id", "required": True, "format": "UUID do agente S1", "example": "1234567890abcdef",
              "source": "agent_id, s1_agent_id, endpoint_id (campo do log SentinelOne)"},
             {"name": "reason", "required": False, "format": "string", "example": "Compromised host - lateral movement"},
         ]},
        {"id": "edr_deisolate_agent", "name": "Remover Isolamento",
         "description": "Remove o endpoint do isolamento, restaurando conectividade.",
         "inputs": [
             {"name": "agent_id", "required": True, "format": "UUID do agente S1", "example": "1234567890abcdef"},
         ]},
        {"id": "edr_scan_agent", "name": "Scan Remoto",
         "description": "Inicia scan antivirus/ameacas no endpoint via agente.",
         "inputs": [
             {"name": "agent_id", "required": True, "format": "UUID do agente S1", "example": "1234567890abcdef"},
         ]},
    ]}},
    "identity": {"Microsoft": {"Active Directory": [
        {"id": "ad_disable_user", "name": "Desabilitar Conta",
         "description": "Desabilita a conta do usuario no Active Directory, impedindo login.",
         "inputs": [
             {"name": "username", "required": True, "format": "SAM, UPN ou DOMAIN\\user", "example": "john.doe | john@empresa.com | EMPRESA\\john.doe",
              "source": "username, user, account, logon_name, sam_account, target_user_name"},
             {"name": "reason", "required": False, "format": "string", "example": "Credential leak - SOC action"},
         ]},
        {"id": "ad_enable_user", "name": "Habilitar Conta",
         "description": "Reabilita conta de usuario desabilitada.",
         "inputs": [
             {"name": "username", "required": True, "format": "SAM, UPN ou DOMAIN\\user", "example": "john.doe"},
         ]},
        {"id": "ad_force_password_reset", "name": "Forcar Reset de Senha",
         "description": "Marca a conta para obrigar troca de senha no proximo login.",
         "inputs": [
             {"name": "username", "required": True, "format": "SAM, UPN ou DOMAIN\\user", "example": "john.doe | EMPRESA\\john.doe"},
         ]},
        {"id": "ad_unlock_user", "name": "Desbloquear Conta",
         "description": "Desbloqueia conta bloqueada por tentativas excessivas de senha.",
         "inputs": [
             {"name": "username", "required": True, "format": "SAM, UPN ou DOMAIN\\user", "example": "john.doe"},
         ]},
    ]}},
    "dns": {"Microsoft": {"DNS Server": [
        {"id": "dns_block_domain", "name": "Sinkhole de Dominio",
         "description": "Cria zona RPZ no Windows DNS Server, redirecionando resolucoes do dominio para 0.0.0.0 (sinkhole).",
         "inputs": [
             {"name": "domain", "required": True, "format": "FQDN (sem www ou subdominio)", "example": "evil-domain.com | phishing.net",
              "source": "domain, hostname, dns_query, query_name, fqdn (extrair base domain)"},
         ]},
        {"id": "dns_unblock_domain", "name": "Remover Sinkhole",
         "description": "Remove a zona RPZ, restaurando resolucao normal do dominio.",
         "inputs": [
             {"name": "domain", "required": True, "format": "FQDN", "example": "evil-domain.com"},
         ]},
        {"id": "dns_flush_cache", "name": "Flush de Cache DNS",
         "description": "Limpa o cache DNS do servidor, forcando resolucao fresca.",
         "inputs": []},
    ]}},
}

_CLASS_LABELS = {"firewall": "Firewall", "edr": "EDR/XDR", "identity": "Identity", "dns": "DNS"}
_METHOD_LABELS = {"api": "API", "ssh": "SSH", "ldap": "LDAP", "winrm": "WinRM", "bastion-ssh": "SSH Bastion"}


# ─── HTML ────────────────────────────────────────────────────────────────────

PAGE = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeLabs MCP</title>
<style>
:root{--bg:#06090f;--bg2:#0d1321;--bg3:#111827;--border:#1a2744;--green:#00ff88;--cyan:#00d4ff;--orange:#ff6b35;--red:#ff2d55;--yellow:#ffd60a;--purple:#bf5af2;--text:#c8d4e8;--dim:#5a6a85}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Courier New',monospace;min-height:100vh}
nav{background:rgba(10,15,25,.98);border-bottom:1px solid var(--border);padding:0 20px;display:flex;align-items:center;gap:12px;height:52px;position:sticky;top:0;z-index:100}
.logo{font-size:1.05rem;font-weight:900;color:var(--green);text-shadow:0 0 16px rgba(0,255,136,.4);letter-spacing:.06em;margin-right:auto}
.logo span{color:var(--cyan)}
.ns{font-size:.72rem;display:flex;gap:12px}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:4px;animation:pulse 2s infinite}
.dot.ok{background:var(--green);box-shadow:0 0 6px var(--green)}
.dot.err{background:var(--red);box-shadow:0 0 6px var(--red);animation:none}
.dot.load{background:var(--yellow);box-shadow:0 0 6px var(--yellow)}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.tabs{display:flex;gap:3px;padding:14px 20px 0;background:var(--bg)}
.tab{padding:9px 18px;border:1px solid var(--border);background:var(--bg2);color:var(--dim);cursor:pointer;border-radius:5px 5px 0 0;font-family:inherit;font-size:.82rem;transition:all .13s;letter-spacing:.04em;border-bottom:none}
.tab:hover{color:var(--cyan);border-color:rgba(0,212,255,.4)}
.tab.active{background:var(--bg3);color:var(--green);border-color:var(--green);font-weight:700}
.panels{background:var(--bg3);border:1px solid var(--border);border-radius:0 6px 6px 6px;margin:0 20px 20px;padding:20px;min-height:420px}
.panel{display:none}.panel.active{display:block}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px}
@media(max-width:820px){.g2,.g3{grid-template-columns:1fr}}
.card{background:var(--bg2);border:1px solid var(--border);border-radius:7px;padding:15px}
.card-title{font-size:.78rem;text-transform:uppercase;letter-spacing:.12em;font-weight:700;margin-bottom:12px;display:flex;align-items:center;gap:8px}
.field{display:flex;flex-direction:column;gap:5px;margin-bottom:10px}
.field label{font-size:.7rem;text-transform:uppercase;letter-spacing:.1em;color:var(--dim)}
.field input,.field select,.field textarea{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:9px 12px;border-radius:5px;font-family:inherit;font-size:.83rem;width:100%;transition:border-color .13s}
.field input:focus,.field select:focus,.field textarea:focus{outline:none;border-color:var(--green);box-shadow:0 0 0 2px rgba(0,255,136,.08)}
.field select option{background:var(--bg2)}
.field textarea{resize:vertical;min-height:80px}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}
.row .field{flex:1;min-width:140px;margin-bottom:0}
.btn{padding:9px 18px;border:1px solid;border-radius:5px;font-family:inherit;font-size:.8rem;cursor:pointer;letter-spacing:.04em;transition:all .13s;white-space:nowrap;font-weight:600;text-transform:uppercase}
.b-green{background:rgba(0,255,136,.08);border-color:var(--green);color:var(--green)}
.b-green:hover{background:rgba(0,255,136,.18);box-shadow:0 0 12px rgba(0,255,136,.25)}
.b-red{background:rgba(255,45,85,.08);border-color:var(--red);color:var(--red)}
.b-red:hover{background:rgba(255,45,85,.18);box-shadow:0 0 12px rgba(255,45,85,.25)}
.b-orange{background:rgba(255,107,53,.08);border-color:var(--orange);color:var(--orange)}
.b-orange:hover{background:rgba(255,107,53,.18);box-shadow:0 0 12px rgba(255,107,53,.25)}
.b-cyan{background:rgba(0,212,255,.08);border-color:var(--cyan);color:var(--cyan)}
.b-cyan:hover{background:rgba(0,212,255,.18);box-shadow:0 0 12px rgba(0,212,255,.25)}
.b-purple{background:rgba(191,90,242,.08);border-color:var(--purple);color:var(--purple)}
.b-purple:hover{background:rgba(191,90,242,.18);box-shadow:0 0 12px rgba(191,90,242,.25)}
.btn:disabled{opacity:.35;cursor:not-allowed}
.btns{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}
.impact{background:rgba(255,45,85,.07);border:1px solid rgba(255,45,85,.25);border-radius:5px;padding:8px 12px;font-size:.77rem;color:var(--red);margin:8px 0}
.impact::before{content:'! IMPACTO: ';font-weight:700}
.term{background:#000;border:1px solid var(--border);border-radius:6px;margin-top:14px;overflow:hidden}
.term-hdr{background:#0a0a0a;padding:7px 14px;display:flex;align-items:center;gap:7px;border-bottom:1px solid #111;font-size:.72rem;color:var(--dim)}
.term-hdr .cc{display:flex;gap:5px}
.term-hdr .cc span{width:11px;height:11px;border-radius:50%}
.c1{background:#ff5f57}.c2{background:#febc2e}.c3{background:#28c840}
.term-body{padding:13px;white-space:pre-wrap;word-break:break-all;font-size:.78rem;min-height:100px;max-height:320px;overflow-y:auto}
.ok{color:var(--green)}.err{color:var(--red)}.warn{color:var(--yellow)}.info{color:var(--cyan)}.dim{color:var(--dim)}
.spin{display:inline-block;width:12px;height:12px;border:2px solid rgba(0,255,136,.2);border-top-color:var(--green);border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:6px}
@keyframes spin{to{transform:rotate(360deg)}}
.pill{padding:2px 9px;border-radius:12px;font-size:.7rem;font-weight:700;text-transform:uppercase}
.p-ok{background:rgba(0,255,136,.12);color:var(--green)}
.p-err{background:rgba(255,45,85,.12);color:var(--red)}
.p-warn{background:rgba(255,107,53,.12);color:var(--orange)}
.p-info{background:rgba(0,212,255,.12);color:var(--cyan)}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px}
.stat{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:13px;position:relative;overflow:hidden}
.stat::before{content:'';position:absolute;top:0;left:0;right:0;height:2px}
.stat.g::before{background:var(--green)}.stat.c::before{background:var(--cyan)}
.stat.o::before{background:var(--orange)}.stat.r::before{background:var(--red)}
.stat .lbl{font-size:.68rem;text-transform:uppercase;letter-spacing:.1em;color:var(--dim);margin-bottom:5px}
.stat .val{font-size:1.3rem;font-weight:900;color:var(--green)}
.stat.c .val{color:var(--cyan)}.stat.o .val{color:var(--orange)}.stat.r .val{color:var(--red)}
.stat .sub{font-size:.72rem;color:var(--dim);margin-top:3px}
.tbl{width:100%;border-collapse:collapse;font-size:.8rem}
.tbl th{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);font-size:.68rem;text-transform:uppercase;letter-spacing:.08em;color:var(--dim)}
.tbl td{padding:9px 10px;border-bottom:1px solid rgba(26,39,68,.5)}
.tbl tr:hover td{background:rgba(0,255,136,.03)}
.ioc-box{background:var(--bg);border:1px dashed var(--border);border-radius:5px;padding:12px;margin-top:10px}
.ioc-box-title{font-size:.72rem;text-transform:uppercase;letter-spacing:.1em;color:var(--cyan);margin-bottom:8px}
.tag-btn{padding:3px 9px;border-radius:3px;font-size:.72rem;border:1px solid;cursor:pointer;background:none;font-family:inherit;transition:all .13s;margin:2px}
.tag-ip{border-color:var(--orange);color:var(--orange)}.tag-ip:hover{background:rgba(255,107,53,.15)}
.tag-domain{border-color:var(--cyan);color:var(--cyan)}.tag-domain:hover{background:rgba(0,212,255,.15)}
.tag-hash{border-color:var(--purple);color:var(--purple)}.tag-hash:hover{background:rgba(191,90,242,.15)}
hr{border:none;border-top:1px solid var(--border);margin:16px 0}
.glitch{font-size:1.5rem;font-weight:900;color:var(--green);text-shadow:0 0 20px rgba(0,255,136,.5),2px 0 var(--red),-2px 0 var(--cyan);animation:glitch 5s infinite}
@keyframes glitch{0%,88%,100%{text-shadow:0 0 20px rgba(0,255,136,.5)}90%{text-shadow:0 0 20px rgba(0,255,136,.5),3px 0 var(--red),-3px 0 var(--cyan)}94%{text-shadow:0 0 20px rgba(0,255,136,.5),-3px 0 var(--red),3px 0 var(--cyan)}}
.file-upload{display:none}
</style>
</head>
<body>

<nav>
  <div class="logo">SAFE<span>LABS</span> MCP <span style="font-size:.65rem;color:var(--dim);margin-left:4px">v1.0</span></div>
  <div class="ns">
    <span><span class="dot load" id="d-fw"></span>FortiGate</span>
    <span><span class="dot load" id="d-edr"></span>SentinelOne</span>
    <span><span class="dot load" id="d-ad"></span>AD/DNS</span>
  </div>
</nav>

<div class="tabs">
  <button class="tab active" data-tab="dashboard" id="nav-dashboard">Dashboard</button>
  <button class="tab" data-tab="fw" id="nav-fw" data-intg-class="firewall" style="display:none">Firewall</button>
  <button class="tab" data-tab="edr" id="nav-edr" data-intg-class="edr" style="display:none">EDR / XDR</button>
  <button class="tab" data-tab="ad" id="nav-ad" data-intg-class="identity" style="display:none">Active Directory</button>
  <button class="tab" data-tab="dns" id="nav-dns" data-intg-class="dns" style="display:none">DNS</button>
  <button class="tab" data-tab="playbooks" id="nav-playbooks" style="display:none">Playbooks</button>
  <button class="tab" data-tab="apt">Threat Intel</button>
  <button class="tab" data-tab="config">Settings</button>
</div>

<div class="panels">

<!-- DASHBOARD -->
<div class="panel active" id="tab-dashboard">
  <div style="display:flex;align-items:center;gap:16px;margin-bottom:18px">
    <div>
      <div class="glitch">SOC CONTAINMENT</div>
      <div style="color:var(--dim);font-size:.8rem;margin-top:4px">SafeLabs MCP — Resposta a Incidentes</div>
    </div>
    <div style="margin-left:auto;text-align:right;font-size:.75rem">
      <div style="color:var(--dim)">HIN lnx01-hin</div>
      <div style="color:var(--green);font-size:.9rem;font-weight:700">10.254.2.27:8080</div>
    </div>
  </div>
  <div class="stats" id="dash-stats"><div style="color:var(--dim);padding:16px">Carregando...</div></div>
    <div class="g3" id="dash-quick-actions"><div style="color:var(--dim);padding:16px">Carregando acoes rapidas...</div></div>
  <div class="term"><div class="term-hdr"><div class="cc"><span class="c1"></span><span class="c2"></span><span class="c3"></span></div><span>CONSOLE</span><div style="margin-left:auto;display:flex;gap:8px"><button style="background:none;border:none;color:var(--cyan);cursor:pointer;font-size:.7rem" onclick="exportLog('term-dash','console')" title="Exportar log">&#9660; EXPORT</button><button style="background:none;border:none;color:var(--dim);cursor:pointer;font-size:.7rem" onclick="termClear('term-dash')">CLEAR</button></div></div><div class="term-body dim" id="term-dash">Pronto...</div></div>
</div>

<!-- FIREWALL -->
<div class="panel" id="tab-fw">
  <div style="color:var(--orange);font-weight:700;font-size:.85rem;letter-spacing:.1em;text-transform:uppercase;margin-bottom:16px">FortiGate — Contencao de Rede</div>
  <div class="g2">
    <div class="card">
      <div class="card-title" style="color:var(--orange)">Bloquear IP / CIDR</div>
      <div class="row">
        <div class="field"><label>IP ou CIDR</label><input id="fw-ip" placeholder="57.128.59.134 ou 10.0.0.0/24"></div>
        <div class="field" style="max-width:180px"><label>Motivo</label><input id="fw-ip-cmt" value="SafeLabs SOC"></div>
        <div class="field" style="max-width:110px"><label>TTL (min)</label><input id="fw-ip-ttl" type="number" value="0" min="0" placeholder="0=perm"></div>
      </div>
      <div class="ioc-box">
        <div class="ioc-box-title">Importar lista de IPs</div>
        <textarea id="fw-ip-import" placeholder="Cole IPs (um por linha)&#10;# Comentarios sao ignorados" style="height:70px"></textarea>
        <div class="row" style="margin-top:6px">
          <input type="file" id="fw-ip-file" class="file-upload" accept=".txt,.csv,.list" onchange="loadFileToTextarea(this,'fw-ip-import')">
          <button class="btn b-cyan" style="font-size:.72rem" onclick="document.getElementById('fw-ip-file').click()">ARQUIVO</button>
          <button class="btn b-orange" style="flex:1" onclick="fwBulkIpImport()">IMPORTAR E BLOQUEAR</button>
        </div>
      </div>
      <div class="btns">
        <button class="btn b-orange" onclick="fwBlockIp()">BLOQUEAR</button>
        <button class="btn b-cyan" onclick="fwUnblockIp()">DESBLOQUEAR</button>
      </div>
    </div>
    <div class="card">
      <div class="card-title" style="color:var(--cyan)">Bloquear Dominio / URL</div>
      <div class="row">
        <div class="field"><label>Dominio ou URL</label><input id="fw-domain" placeholder="malicious.com"></div>
        <div class="field" style="max-width:110px"><label>TTL (min)</label><input id="fw-domain-ttl" type="number" value="0" min="0" placeholder="0=perm"></div>
      </div>
      <div class="ioc-box">
        <div class="ioc-box-title">Importar lista</div>
        <textarea id="fw-domain-import" placeholder="Cole dominios (um por linha)" style="height:70px"></textarea>
        <div class="row" style="margin-top:6px">
          <select id="fw-domain-import-type" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px;border-radius:4px;font-family:inherit;font-size:.8rem">
            <option value="domain">Dominios (DNS filter)</option>
            <option value="url">URLs (URL filter)</option>
          </select>
          <input type="file" id="fw-domain-file" class="file-upload" accept=".txt,.csv,.list" onchange="loadFileToTextarea(this,'fw-domain-import')">
          <button class="btn b-cyan" style="font-size:.72rem" onclick="document.getElementById('fw-domain-file').click()">ARQUIVO</button>
          <button class="btn b-cyan" style="flex:1" onclick="fwBulkDomainImport()">IMPORTAR E BLOQUEAR</button>
        </div>
      </div>
      <div class="btns">
        <button class="btn b-cyan" onclick="fwBlockDomain()">BLOQUEAR</button>
        <button class="btn b-green" onclick="fwUnblockDomain()">DESBLOQUEAR</button>
      </div>
    </div>
    <div class="card" style="border-color:rgba(255,45,85,.25)">
      <div class="card-title" style="color:var(--red)">Isolar Host Interno</div>
      <div class="impact">Host perde acesso a internet. Politica deny e criada no FW.</div>
      <div class="row">
        <div class="field"><label>IP do Host</label><input id="fw-host" placeholder="10.254.2.152"></div>
        <div class="field"><label>Motivo</label><input id="fw-host-r" value="Host comprometido — SOC"></div>
        <div class="field" style="max-width:110px"><label>TTL (min)</label><input id="fw-host-ttl" type="number" value="0" min="0" placeholder="0=perm"></div>
      </div>
      <div class="btns">
        <button class="btn b-red" onclick="fwIsolate()">ISOLAR HOST</button>
        <button class="btn b-green" onclick="fwDeisolate()">REMOVER ISOLAMENTO</button>
      </div>
    </div>
    <div class="card">
      <div class="card-title" style="color:var(--green)">Bloqueios Ativos no FortiGate</div>
      <p style="font-size:.77rem;color:var(--dim);margin-bottom:10px">IPs, dominios, URLs e hosts isolados (objetos safelabs-*)</p>
      <div class="btns">
        <button class="btn b-green" onclick="api('POST','/api/fw/list',{},'term-fw')">VER BLOQUEIOS</button>
        <button class="btn b-cyan" onclick="statusIntg('firewall','term-fw')">STATUS</button>
      </div>
    </div>
  </div>
  <div class="term"><div class="term-hdr"><div class="cc"><span class="c1"></span><span class="c2"></span><span class="c3"></span></div><span>FORTIGATE OUTPUT</span><div style="margin-left:auto;display:flex;gap:8px"><button style="background:none;border:none;color:var(--cyan);cursor:pointer;font-size:.7rem" onclick="exportLog('term-fw','fortigate')" title="Exportar log">&#9660; EXPORT</button><button style="background:none;border:none;color:var(--dim);cursor:pointer;font-size:.7rem" onclick="termClear('term-fw')">CLEAR</button></div></div><div class="term-body dim" id="term-fw">Aguardando acao...</div></div>
</div>

<!-- EDR/XDR -->
<div class="panel" id="tab-edr">
  <div style="color:var(--cyan);font-weight:700;font-size:.85rem;letter-spacing:.1em;text-transform:uppercase;margin-bottom:16px">SentinelOne — Contencao de Endpoint</div>
  <div class="card" style="margin-bottom:14px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px">
      <div style="color:var(--green);font-weight:700;font-size:.8rem;text-transform:uppercase">Agentes no Site</div>
      <div style="display:flex;gap:7px">
        <button class="btn b-green" onclick="loadAgents()">ATUALIZAR</button>
        <button class="btn b-cyan" onclick="edrListThreats()">VER THREATS</button>
      </div>
    </div>
    <table class="tbl">
      <thead><tr><th>Nome</th><th>OS</th><th>Rede</th><th>Threats</th><th>IP</th><th>Acoes</th></tr></thead>
      <tbody id="agents-body"><tr><td colspan="6" style="text-align:center;color:var(--dim);padding:16px">Clique em ATUALIZAR</td></tr></tbody>
    </table>
  </div>
  <div class="g2">
    <div class="card" style="border-color:rgba(255,45,85,.25)">
      <div class="card-title" style="color:var(--red)">Isolar / Controlar Agente</div>
      <div class="impact">Network Quarantine — host perde conectividade</div>
      <div class="field"><label>Agent ID</label><input id="edr-id" placeholder="2442300432464470030"></div>
      <div class="field"><label>Motivo</label><input id="edr-r" value="Contencao SOC"></div>
      <div class="btns">
        <button class="btn b-red" onclick="edrIsolate()">ISOLAR</button>
        <button class="btn b-green" onclick="edrDeisolate()">REMOVER ISOLAMENTO</button>
        <button class="btn b-cyan" onclick="edrScan()" title="O S1 pode levar alguns minutos para sincronizar a blacklist antes de detectar via scan">SCAN</button>
        <button class="btn b-orange" onclick="edrChain()">CONTENCAO TOTAL</button>
      </div>
    </div>
    <div class="card">
      <div class="card-title" style="color:var(--purple)">Blacklist de Hash</div>
      <div class="field"><label>Hash (SHA1 40hex, SHA256 64hex ou MD5 32hex)</label><input id="edr-hash" placeholder="65dc04f3f75deb3b287cca3138d9d0ec36b8bea0"></div>
      <div class="field"><label>Descricao</label><input id="edr-hash-d" value="SafeLabs SOC — IOC block"></div>
      <div class="ioc-box">
        <div class="ioc-box-title">Importar hashes em lote</div>
        <textarea id="edr-hash-import" placeholder="Cole hashes (SHA1/SHA256, um por linha)" style="height:65px"></textarea>
        <div class="row" style="margin-top:6px">
          <input type="file" id="edr-hash-file" class="file-upload" accept=".txt,.csv,.list" onchange="loadFileToTextarea(this,'edr-hash-import')">
          <button class="btn b-cyan" style="font-size:.72rem" onclick="document.getElementById('edr-hash-file').click()">ARQUIVO</button>
          <button class="btn b-purple" style="flex:1" onclick="edrBulkHash()">IMPORTAR E BLACKLIST</button>
        </div>
      </div>
      <div class="btns">
        <button class="btn b-purple" onclick="edrBlacklist()">ADICIONAR HASH</button>
        <button class="btn b-cyan" onclick="api('POST','/api/edr/collect-iocs',{},'term-edr')">COLETAR IOCs</button>
      </div>
    </div>
  </div>
  <div class="term"><div class="term-hdr"><div class="cc"><span class="c1"></span><span class="c2"></span><span class="c3"></span></div><span>EDR OUTPUT</span><div style="margin-left:auto;display:flex;gap:8px"><button style="background:none;border:none;color:var(--cyan);cursor:pointer;font-size:.7rem" onclick="exportLog('term-edr','edr')" title="Exportar log">&#9660; EXPORT</button><button style="background:none;border:none;color:var(--dim);cursor:pointer;font-size:.7rem" onclick="termClear('term-edr')">CLEAR</button></div></div><div class="term-body dim" id="term-edr">Aguardando acao...</div></div>
</div>

<!-- ACTIVE DIRECTORY -->
<div class="panel" id="tab-ad">
  <div style="color:var(--purple);font-weight:700;font-size:.85rem;letter-spacing:.1em;text-transform:uppercase;margin-bottom:16px">Active Directory — Usuarios do Dominio</div>
  <div class="g2">
    <div>
      <div class="card" style="margin-bottom:14px">
        <div class="card-title" style="color:var(--cyan)">Verificar e Agir em Usuario</div>
        <div class="field"><label>Usuario (sam, UPN ou domain\user)</label><input id="ad-user" placeholder="harpia.user ou user@safelabs.lab"></div>
        <div class="field"><label>Motivo</label><input id="ad-r" value="Credencial comprometida — SOC"></div>
        <div class="btns">
          <button class="btn b-cyan" onclick="adStatus()">VER STATUS</button>
          <button class="btn b-red" onclick="adDisable()">DESATIVAR</button>
          <button class="btn b-green" onclick="adEnable()">REATIVAR</button>
          <button class="btn b-orange" onclick="adResetPwd()">RESET SENHA</button>
          <button class="btn b-cyan" onclick="adUnlock()">DESBLOQUEAR</button>
        </div>
      </div>
      <div class="card" style="border-color:rgba(255,107,53,.3)">
        <div class="card-title" style="color:var(--orange)">Contencao em Lote — Credential Leak</div>
        <div class="field"><label>Usuarios (um por linha)</label>
          <textarea id="ad-bulk" placeholder="harpia.user&#10;claro.user&#10;user@safelabs.lab" style="height:85px"></textarea>
        </div>
        <div class="row">
          <div class="field" style="max-width:220px"><label>Acao</label>
            <select id="ad-bulk-act">
              <option value="status">Verificar status</option>
              <option value="reset-password">Forcar reset de senha</option>
              <option value="disable">Desativar contas</option>
              <option value="unlock">Desbloquear contas</option>
            </select>
          </div>
          <button class="btn b-orange" onclick="adBulk()" style="align-self:flex-end">EXECUTAR</button>
        </div>
      </div>
    </div>
    <div>
      <div class="card" style="margin-bottom:14px">
        <div class="card-title" style="color:var(--green)">Usuarios Ativos do Dominio</div>
        <div id="ad-users-list" style="font-size:.78rem;color:var(--dim)">Clique em CARREGAR USUARIOS</div>
        <div class="btns">
          <button class="btn b-green" onclick="loadAdUsers()">CARREGAR USUARIOS</button>
          <button class="btn b-cyan" onclick="api('POST','/api/ad/list-disabled',{},'term-ad')">LISTAR DESATIVADOS</button>
        </div>
      </div>
    </div>
  </div>
  <div class="term"><div class="term-hdr"><div class="cc"><span class="c1"></span><span class="c2"></span><span class="c3"></span></div><span>ACTIVE DIRECTORY OUTPUT</span><div style="margin-left:auto;display:flex;gap:8px"><button style="background:none;border:none;color:var(--cyan);cursor:pointer;font-size:.7rem" onclick="exportLog('term-ad','active-directory')" title="Exportar log">&#9660; EXPORT</button><button style="background:none;border:none;color:var(--dim);cursor:pointer;font-size:.7rem" onclick="termClear('term-ad')">CLEAR</button></div></div><div class="term-body dim" id="term-ad">Aguardando acao...</div></div>
</div>

<!-- DNS -->
<div class="panel" id="tab-dns">
  <div style="color:var(--green);font-weight:700;font-size:.85rem;letter-spacing:.1em;text-transform:uppercase;margin-bottom:16px">Windows DNS — Sinkhole 0.0.0.0</div>
  <div class="g2">
    <div class="card">
      <div class="card-title" style="color:var(--cyan)">Bloquear Dominio (Sinkhole)</div>
      <div class="field"><label>Dominio (sem http/https)</label><input id="dns-domain" placeholder="malicious.com"></div>
      <div class="ioc-box">
        <div class="ioc-box-title">Importar lista de dominios</div>
        <textarea id="dns-import" placeholder="Cole dominios (um por linha)" style="height:90px"></textarea>
        <div class="row" style="margin-top:6px">
          <input type="file" id="dns-file" class="file-upload" accept=".txt,.csv,.list" onchange="loadFileToTextarea(this,'dns-import')">
          <button class="btn b-cyan" style="font-size:.72rem" onclick="document.getElementById('dns-file').click()">ARQUIVO</button>
          <button class="btn b-cyan" style="flex:1" onclick="dnsBulkImport()">IMPORTAR E BLOQUEAR</button>
        </div>
      </div>
      <div class="btns">
        <button class="btn b-cyan" onclick="dnsBlock()">BLOQUEAR</button>
        <button class="btn b-green" onclick="dnsUnblock()">REMOVER BLOQUEIO</button>
      </div>
    </div>
    <div class="card">
      <div class="card-title" style="color:var(--green)">Status e Ferramentas</div>
      <div class="btns" style="flex-direction:column;align-items:stretch">
        <button class="btn b-green" onclick="statusIntg('dns','term-dns')">STATUS DO SERVIDOR DNS</button>
        <button class="btn b-cyan" onclick="api('POST','/api/dns/list',{},'term-dns')" style="text-align:left">VER DOMINIOS BLOQUEADOS</button>
        <button class="btn b-orange" onclick="api('POST','/api/dns/flush',{},'term-dns')" style="text-align:left">FLUSH CACHE (efeito imediato)</button>
      </div>
    </div>
  </div>
  <div class="term"><div class="term-hdr"><div class="cc"><span class="c1"></span><span class="c2"></span><span class="c3"></span></div><span>DNS SINKHOLE OUTPUT</span><div style="margin-left:auto;display:flex;gap:8px"><button style="background:none;border:none;color:var(--cyan);cursor:pointer;font-size:.7rem" onclick="exportLog('term-dns','dns')" title="Exportar log">&#9660; EXPORT</button><button style="background:none;border:none;color:var(--dim);cursor:pointer;font-size:.7rem" onclick="termClear('term-dns')">CLEAR</button></div></div><div class="term-body dim" id="term-dns">Aguardando acao...</div></div>
</div>

<!-- THREAT INTEL -->
<div class="panel" id="tab-apt">
<style>
.camp-card{background:var(--bg2);border:1px solid rgba(255,45,85,.2);border-radius:6px;margin-bottom:12px;overflow:hidden;transition:border-color .2s}
.camp-card:hover{border-color:rgba(255,45,85,.5)}
.camp-card .cc-head{padding:12px 16px;display:flex;align-items:center;gap:10px;border-bottom:1px solid rgba(255,45,85,.15);flex-wrap:wrap}
.camp-card .cc-name{font-weight:700;color:var(--red);font-size:.85rem;flex:1;min-width:180px}
.camp-card .cc-body{padding:10px 16px}
.ioc-counts{display:flex;gap:14px;font-size:.72rem;margin-bottom:8px}
.cont-bar{background:#1a2744;border-radius:4px;height:6px;margin:8px 0;overflow:hidden}
.cont-fill{height:100%;border-radius:4px;background:linear-gradient(90deg,var(--green),var(--cyan));transition:width .5s}
.camp-add-form{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:16px;margin-bottom:16px;display:none}
.origin-badge{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.65rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase}
.origin-russia{background:rgba(255,45,85,.12);color:#ff2d55;border:1px solid rgba(255,45,85,.3)}
.origin-china{background:rgba(255,159,10,.12);color:#ff9f0a;border:1px solid rgba(255,159,10,.3)}
.origin-iran{background:rgba(255,214,10,.12);color:#ffd60a;border:1px solid rgba(255,214,10,.3)}
.origin-nk{background:rgba(191,90,242,.12);color:#bf5af2;border:1px solid rgba(191,90,242,.3)}
.origin-other{background:rgba(90,106,133,.12);color:#5a6a85;border:1px solid rgba(90,106,133,.3)}
.apt-summary{display:grid;grid-template-columns:repeat(5,1fr);gap:12px;margin-bottom:16px}
.apt-stat{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:12px 16px;text-align:center}
.apt-stat .sv{font-size:1.4rem;font-weight:700;color:var(--red)}
.apt-stat .sl{font-size:.7rem;color:var(--dim);margin-top:4px;text-transform:uppercase;letter-spacing:.08em}
.apt-search{display:flex;gap:8px;margin-bottom:14px;align-items:center}
.apt-search input{flex:1;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:4px;font-family:inherit;font-size:.78rem}
.apt-search input:focus{outline:none;border-color:var(--red);box-shadow:0 0 0 2px rgba(255,45,85,.15)}
.apt-search select{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px 10px;border-radius:4px;font-family:inherit;font-size:.75rem}
.mitre-link{font-size:.65rem;color:var(--cyan);text-decoration:none;opacity:.7;font-weight:600}
.mitre-link:hover{opacity:1;text-decoration:underline}
.apt-tbl{width:100%;border-collapse:collapse;font-size:.73rem}
.apt-tbl th{background:var(--bg);color:var(--dim);font-size:.65rem;text-transform:uppercase;letter-spacing:.06em;padding:8px 6px;text-align:left;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:1}
.apt-tbl th.sortable{cursor:pointer;user-select:none;transition:color .15s}
.apt-tbl th.sortable:hover{color:var(--text)}
.apt-tbl th.sortable .sort-arrow{font-size:.55rem;margin-left:3px;opacity:.4}
.apt-tbl th.sortable.asc .sort-arrow,.apt-tbl th.sortable.desc .sort-arrow{opacity:1;color:var(--cyan)}
.apt-tbl td{padding:6px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:middle}
.apt-tbl tr:hover{background:rgba(255,45,85,.03)}
.apt-tbl tr.selected{background:rgba(255,45,85,.08)}
.apt-tbl .cb-col{width:30px;text-align:center}
.apt-tbl .name-col{font-weight:600;color:var(--text);white-space:nowrap}
.apt-tbl .act-col{white-space:nowrap;text-align:right}
.apt-tbl .act-btn{background:none;border:1px solid var(--border);color:var(--dim);cursor:pointer;padding:2px 6px;border-radius:3px;font-size:.65rem;font-family:inherit;margin-left:3px;transition:all .15s}
.apt-tbl .act-btn:hover{border-color:var(--text);color:var(--text)}
.apt-tbl .act-btn.b-check{color:var(--green);border-color:rgba(50,215,75,.3)}
.apt-tbl .act-btn.b-check:hover{background:rgba(50,215,75,.1)}
.apt-tbl .act-btn.b-apply{color:var(--orange);border-color:rgba(255,159,10,.3)}
.apt-tbl .act-btn.b-apply:hover{background:rgba(255,159,10,.1)}
.apt-tbl .act-btn.b-del{color:var(--red);border-color:rgba(255,45,85,.3)}
.apt-tbl .act-btn.b-del:hover{background:rgba(255,45,85,.1)}
.pct-bar{display:inline-block;width:60px;height:6px;background:#1a2744;border-radius:3px;overflow:hidden;vertical-align:middle;margin-right:4px}
.pct-fill{height:100%;border-radius:3px;transition:width .3s}
.apt-tbl-wrap{max-height:480px;overflow-y:auto;border:1px solid var(--border);border-radius:6px;margin-bottom:10px}
.batch-bar{display:flex;align-items:center;gap:8px;padding:6px 10px;background:var(--bg2);border:1px solid var(--border);border-radius:6px;margin-bottom:10px;font-size:.72rem}
.batch-bar select,.batch-bar label{font-size:.72rem;color:var(--dim)}
.batch-bar select{background:var(--bg);border:1px solid var(--border);color:var(--text);padding:4px 6px;border-radius:3px}
</style>

<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
  <div style="color:var(--red);font-weight:700;font-size:.95rem;letter-spacing:.06em">Threat Intelligence &mdash; APT Groups</div>
  <div style="display:flex;gap:6px;flex-wrap:wrap">
    <button class="btn b-green" onclick="refreshAptContainment()" style="font-size:.72rem">&#8635; CHECK GLOBAL</button>
    <button class="btn b-orange" onclick="applySelectedGaps()" style="font-size:.72rem">&#9654; APPLY SELECIONADOS</button>
    <button class="btn b-red" onclick="toggleAddCampForm()" style="font-size:.72rem">+ NOVA CAMPANHA</button>
  </div>
</div>

<div class="apt-summary" id="apt-summary">
  <div class="apt-stat"><div class="sv" id="as-total">-</div><div class="sl">APT Groups</div></div>
  <div class="apt-stat"><div class="sv" style="color:var(--orange)" id="as-iocs">-</div><div class="sl">Total IOCs</div></div>
  <div class="apt-stat"><div class="sv" style="color:var(--green)" id="as-covered">-</div><div class="sl">Cobertura</div></div>
  <div class="apt-stat"><div class="sv" style="color:var(--cyan)" id="as-origins">-</div><div class="sl">Origens</div></div>
  <div class="apt-stat"><div class="sv" style="color:var(--dim);font-size:.7rem" id="as-lastcheck">-</div><div class="sl">Ultimo Check</div></div>
</div>

<div class="apt-search">
  <input type="text" id="apt-filter" placeholder="Buscar APT por nome, tag, origem..." oninput="filterAptList()">
  <select id="apt-origin-filter" onchange="filterAptList()">
    <option value="">Todas origens</option>
    <option value="Russia">Russia</option>
    <option value="China">China</option>
    <option value="Iran">Iran</option>
    <option value="North Korea">North Korea</option>
    <option value="other">Outros</option>
  </select>
  <select id="apt-coverage-filter" onchange="filterAptList()">
    <option value="">Cobertura</option>
    <option value="full">100% Coberto</option>
    <option value="partial">Parcial</option>
    <option value="none">Sem cobertura</option>
    <option value="unchecked">Nao verificado</option>
  </select>
</div>

<!-- Add Campaign Form -->
<div class="camp-add-form" id="camp-add-form">
  <div style="font-size:.8rem;font-weight:700;color:var(--red);margin-bottom:10px">Nova Campanha APT</div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px">
    <div><label class="form-label">Nome <span style="color:var(--red)">*</span></label><input class="form-input" id="camp-name" placeholder="APT28 / Fancy Bear"></div>
    <div><label class="form-label">Adversario</label><input class="form-input" id="camp-adv" placeholder="APT28"></div>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:8px">
    <div><label class="form-label">Origem</label><input class="form-input" id="camp-origin" placeholder="Russia, China, Iran..."></div>
    <div><label class="form-label">MITRE ID</label><input class="form-input" id="camp-mitre" placeholder="G0007"></div>
  </div>
  <div style="margin-bottom:8px"><label class="form-label">Descricao</label><input class="form-input" id="camp-desc" placeholder="Grupo de ameaca russo focado em espionagem"></div>
  <div style="margin-bottom:8px"><label class="form-label">Tags (virgula)</label><input class="form-input" id="camp-tags" placeholder="russia, espionagem, apt28"></div>
  <div style="font-size:.73rem;color:var(--dim);margin-bottom:6px;font-weight:700">IOCs (um por linha)</div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px">
    <div><label class="form-label" style="color:var(--orange)">IPs</label><textarea class="form-input" id="camp-ips" rows="3" placeholder="1.2.3.4&#10;5.6.7.8" style="resize:vertical"></textarea></div>
    <div><label class="form-label" style="color:var(--cyan)">Dominios</label><textarea class="form-input" id="camp-domains" rows="3" placeholder="evil.com&#10;malware.net" style="resize:vertical"></textarea></div>
    <div><label class="form-label" style="color:var(--purple)">Hashes (SHA1/256)</label><textarea class="form-input" id="camp-hashes" rows="3" placeholder="3020BD9D..." style="resize:vertical"></textarea></div>
    <div><label class="form-label" style="color:var(--yellow)">URLs</label><textarea class="form-input" id="camp-urls" rows="3" placeholder="http://evil.com/p" style="resize:vertical"></textarea></div>
  </div>
  <div style="display:flex;gap:8px">
    <button class="btn b-green" onclick="saveCampaign()" style="font-size:.75rem">SALVAR</button>
    <button class="btn" onclick="toggleAddCampForm()" style="font-size:.75rem;background:var(--bg);border:1px solid var(--border)">CANCELAR</button>
  </div>
</div>

<div id="apt-list" style="font-size:.8rem;color:var(--dim)">Carregando campanhas...</div>

<div class="term" style="margin-top:14px"><div class="term-hdr"><div class="cc"><span class="c1"></span><span class="c2"></span><span class="c3"></span></div><span>THREAT INTEL OUTPUT</span><div style="margin-left:auto;display:flex;gap:8px"><button style="background:none;border:none;color:var(--cyan);cursor:pointer;font-size:.7rem" onclick="exportLog('term-apt','threat-intel')" title="Exportar log">&#9660; EXPORT</button><button style="background:none;border:none;color:var(--dim);cursor:pointer;font-size:.7rem" onclick="termClear('term-apt')">CLEAR</button></div></div><div class="term-body dim" id="term-apt" style="max-height:400px;overflow-y:auto">Pronto...</div></div>
</div>

<div class="panel" id="tab-playbooks">
<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
  <div style="color:var(--cyan);font-weight:700;font-size:.95rem;letter-spacing:.06em">Playbooks Disponiveis</div>
  <div style="font-size:.73rem;color:var(--dim)" id="pb-subtitle">Baseados nas integracoes ativas</div>
</div>
<div id="playbooks-area"><div style="color:var(--dim);padding:20px;text-align:center">Carregando playbooks...</div></div>
<div class="term" style="margin-top:14px"><div class="term-hdr"><div class="cc"><span class="c1"></span><span class="c2"></span><span class="c3"></span></div><span>PLAYBOOKS OUTPUT</span><div style="margin-left:auto;display:flex;gap:8px"><button style="background:none;border:none;color:var(--cyan);cursor:pointer;font-size:.7rem" onclick="exportLog('term-pb','playbooks')" title="Exportar log">&#9660; EXPORT</button><button style="background:none;border:none;color:var(--dim);cursor:pointer;font-size:.7rem" onclick="termClear('term-pb')">CLEAR</button></div></div><div class="term-body dim" id="term-pb">Pronto...</div></div>
</div>

<!-- SETTINGS -->
<div class="panel" id="tab-config">
<style>
.intg-table{width:100%;border-collapse:collapse;font-size:.79rem;margin-bottom:16px}
.intg-table th{background:var(--bg2);color:var(--dim);text-align:left;padding:8px 10px;border-bottom:2px solid var(--border);font-weight:600;letter-spacing:.06em;font-size:.72rem;text-transform:uppercase}
.intg-table td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:middle}
.intg-table tr:hover td{background:rgba(255,255,255,.02)}
.badge-cls{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.68rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em}
.badge-firewall{background:rgba(255,107,53,.15);color:#ff6b35;border:1px solid rgba(255,107,53,.3)}
.badge-edr{background:rgba(191,90,242,.15);color:#bf5af2;border:1px solid rgba(191,90,242,.3)}
.badge-identity{background:rgba(0,212,255,.15);color:#00d4ff;border:1px solid rgba(0,212,255,.3)}
.badge-dns{background:rgba(0,255,136,.15);color:#00ff88;border:1px solid rgba(0,255,136,.3)}
.badge-status{display:inline-block;padding:2px 8px;border-radius:12px;font-size:.68rem;font-weight:700}
.badge-ok{background:rgba(0,255,136,.15);color:#00ff88;border:1px solid rgba(0,255,136,.3)}
.badge-warn{background:rgba(255,214,10,.15);color:#ffd60a;border:1px solid rgba(255,214,10,.3)}
.badge-dis{background:rgba(90,106,133,.15);color:#5a6a85;border:1px solid rgba(90,106,133,.2)}
.sw{position:relative;display:inline-block;width:36px;height:20px;cursor:pointer}
.sw input{opacity:0;width:0;height:0}
.sw-slider{position:absolute;top:0;left:0;right:0;bottom:0;background:var(--border);border-radius:20px;transition:.2s}
.sw-slider:before{content:"";position:absolute;width:14px;height:14px;left:3px;top:3px;background:#5a6a85;border-radius:50%;transition:.2s}
.sw input:checked+.sw-slider{background:rgba(0,255,136,.25);border:1px solid var(--green)}
.sw input:checked+.sw-slider:before{transform:translateX(16px);background:var(--green)}
.ic-btn{background:none;border:none;cursor:pointer;padding:4px 6px;border-radius:4px;font-size:.9rem;opacity:.6;transition:.15s}
.ic-btn:hover{opacity:1;background:rgba(255,255,255,.06)}
.test-result-card{padding:12px;background:#06090f;border-radius:6px;border:1px solid #1a2744;font-size:.79rem}
.test-result-card .tr-row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #1a2744}
.test-result-card .tr-row:last-child{border:none}
.test-result-card .tr-label{color:#5a6a85;min-width:120px}
.test-result-card .tr-val{color:#c8d4e8;text-align:right;word-break:break-all;max-width:260px}
.tr-ok{color:#00ff88!important}.tr-err{color:#ff2d55!important}.tr-warn{color:#ffd60a!important}
.help-panel{position:fixed;top:0;left:-580px;width:560px;height:100vh;background:#0d1321;border-right:1px solid #1a2744;z-index:9998;transition:left .25s cubic-bezier(.4,0,.2,1);display:flex;flex-direction:column;box-shadow:8px 0 32px rgba(0,0,0,.5)}
.help-panel.open{left:0}
.help-panel .hp-hdr{background:#111827;padding:14px 20px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #1a2744;flex-shrink:0}
.help-panel .hp-body{flex:1;overflow-y:auto;padding:16px 20px}
.pb-card{background:#06090f;border:1px solid #1a2744;border-radius:6px;margin-bottom:12px;overflow:hidden}
.pb-card .pb-head{padding:10px 14px;background:#111827;display:flex;align-items:center;gap:8px}
.pb-card .pb-name{font-weight:700;color:#00d4ff;font-size:.82rem}
.pb-card .pb-desc{font-size:.73rem;color:#5a6a85;padding:8px 14px;border-bottom:1px solid #1a2744}
.pb-card .pb-inputs{padding:8px 14px}
.pb-input-row{display:grid;grid-template-columns:140px 1fr;gap:6px;padding:4px 0;border-bottom:1px solid #0d1321;font-size:.72rem}
.pb-input-row:last-child{border:none}
.pb-input-name{font-weight:700;color:#c8d4e8}
.pb-input-fmt{color:#5a6a85}
.pb-input-src{color:#bf5af2;font-size:.68rem;margin-top:2px}
.pb-req{color:#ff2d55;font-size:.65rem;vertical-align:top}
.pb-opt{color:#5a6a85;font-size:.65rem;vertical-align:top}
.slide-panel{position:fixed;top:0;right:-520px;width:480px;height:100vh;background:var(--bg2);border-left:1px solid var(--border);z-index:9999;transition:right .25s cubic-bezier(.4,0,.2,1);display:flex;flex-direction:column;box-shadow:-8px 0 32px rgba(0,0,0,.5)}
.slide-panel.open{right:0}
.slide-hdr{background:var(--bg3);padding:12px 20px;display:flex;align-items:center;gap:10px;border-bottom:1px solid var(--border);flex-shrink:0}
.slide-hdr span{font-size:.85rem;font-weight:700;color:var(--text);flex:1}
.slide-body{flex:1;overflow-y:auto;padding:20px}
.slide-footer{background:var(--bg3);padding:12px 20px;border-top:1px solid var(--border);display:flex;gap:8px;justify-content:flex-end;flex-shrink:0}
.form-label{font-size:.73rem;color:var(--dim);margin-bottom:4px;display:block;font-weight:600}
.form-label .req{color:var(--red);margin-left:2px}
.form-input{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:7px 10px;border-radius:4px;font-family:inherit;font-size:.78rem;margin-bottom:10px}
.form-input:focus{outline:none;border-color:var(--cyan);box-shadow:0 0 0 2px rgba(0,212,255,.15)}
.form-select{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:7px 10px;border-radius:4px;font-family:inherit;font-size:.78rem;margin-bottom:10px}
.cap-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:12px}
.cap-item{display:flex;align-items:center;gap:8px;font-size:.75rem;color:var(--text)}
.overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.4);z-index:9998;display:none}
.overlay.visible{display:block}
.wizard-step{display:none}.wizard-step.active{display:block}
.step-title{font-size:.8rem;color:var(--dim);margin-bottom:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em}
</style>

<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px">
  <div style="color:var(--cyan);font-weight:700;font-size:.95rem;letter-spacing:.06em">Integracoes</div>
  <button class="btn b-green" style="font-size:.75rem;padding:6px 14px" onclick="openNewIntg()">+ Nova Integracao</button>
</div>

<table class="intg-table" id="intg-table">
<thead><tr>
  <th>Nome</th><th>Classe</th><th>Vendor</th><th>Produto</th><th>Metodo</th><th>Status</th><th style="text-align:center">Acoes</th>
</tr></thead>
<tbody id="intg-tbody"><tr><td colspan="7" style="color:var(--dim);padding:20px;text-align:center">Carregando...</td></tr></tbody>
</table>

<div class="term" style="margin-top:14px"><div class="term-hdr"><div class="cc"><span class="c1"></span><span class="c2"></span><span class="c3"></span></div><span>SETTINGS OUTPUT</span><div style="margin-left:auto;display:flex;gap:8px"><button style="background:none;border:none;color:var(--cyan);cursor:pointer;font-size:.7rem" onclick="exportLog('term-config','settings')" title="Exportar log">&#9660; EXPORT</button><button style="background:none;border:none;color:var(--dim);cursor:pointer;font-size:.7rem" onclick="termClear('term-config')">CLEAR</button></div></div><div class="term-body dim" id="term-config">Pronto...</div></div>

<!-- Slide panel para criar/editar integracao -->
<!-- Help Panel -->
<div class="overlay" id="help-overlay" onclick="closeHelp()" style="display:none"></div>
<div class="help-panel" id="help-panel">
  <div class="hp-hdr">
    <span style="font-size:.85rem;font-weight:700;color:#bf5af2">&#63;</span>
    <span id="help-title" style="font-size:.85rem;font-weight:700;color:#c8d4e8;flex:1">Playbooks e Inputs</span>
    <button class="ic-btn" onclick="closeHelp()" style="font-size:1rem;color:#5a6a85">&#x2715;</button>
  </div>
  <div class="hp-body" id="help-body"><div style="color:#5a6a85;padding:20px">Carregando...</div></div>
</div>
<!-- Slide Panel -->
<div class="overlay" id="slide-overlay" onclick="closePanel()"></div>
<div class="slide-panel" id="slide-panel">
  <div class="slide-hdr">
    <span id="slide-title" style="flex:1">Nova Integracao</span>
    <button class="ic-btn" id="btn-help-modal" onclick="showCatalogHelp()" title="Playbooks e Inputs" style="color:#bf5af2;display:none">&#63;</button>
    <button class="ic-btn" onclick="closePanel()" style="font-size:1rem;color:var(--dim)">&#x2715;</button>
  </div>
  <div class="slide-body" id="slide-body">
    <!-- Wizard step 1: Selecionar classe -->
    <div class="wizard-step active" id="step-1">
      <div class="step-title">Passo 1 de 3 — Selecionar Classe</div>
      <div id="class-cards" style="display:flex;flex-direction:column;gap:8px"></div>
    </div>
    <!-- Wizard step 2: Selecionar vendor/produto -->
    <div class="wizard-step" id="step-2">
      <div class="step-title">Passo 2 de 3 — Selecionar Vendor / Produto</div>
      <div id="product-cards" style="display:flex;flex-direction:column;gap:8px"></div>
    </div>
    <!-- Wizard step 3: Formulario de configuracao -->
    <div class="wizard-step" id="step-3">
      <div class="step-title">Passo 3 de 3 — Configurar Integracao</div>
      <div style="margin-bottom:12px">
        <label class="form-label">Nome da integracao <span class="req">*</span></label>
        <input class="form-input" id="f-name" placeholder="Ex: FortiGate LAB">
      </div>
      <div id="form-fields-container"></div>
      <div style="margin-top:12px;margin-bottom:4px;font-size:.73rem;color:var(--dim);font-weight:700;text-transform:uppercase">Capabilities habilitadas</div>
      <div class="cap-grid" id="cap-grid"></div>
    </div>
  </div>
  <div class="slide-footer">
    <button class="btn" id="btn-back" onclick="wizardBack()" style="display:none;background:var(--bg);border:1px solid var(--border);color:var(--dim)">Voltar</button>
    <button class="btn" onclick="closePanel()" style="background:var(--bg);border:1px solid var(--border);color:var(--dim)">Cancelar</button>
    <button class="btn" id="btn-test" onclick="testCurrentForm()" style="display:none;background:var(--bg);border:1px solid var(--border);color:var(--cyan)">Testar</button>
    <button class="btn b-green" id="btn-next" onclick="wizardNext()">Proximo</button>
  </div>
</div>
</div>

</div>

<script>
document.querySelectorAll('.tab').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    var _panel=document.getElementById('tab-' + btn.dataset.tab);
    if(_panel) _panel.classList.add('active');
  });
});
function goTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  const el = document.getElementById('tab-' + name);
  if (el) el.classList.add('active');
  if (name === 'apt') { loadAptCampaigns().catch(function(e){console.error('loadApt:',e);}); }
  if (name === 'ad') { try{loadAdUsers();}catch(e){} }
}
function termClear(id) { const el = document.getElementById(id); if (el) el.innerHTML = ''; }
function termSet(id, text) {
  const el = document.getElementById(id);
  if (!el) return;
  let html = '';
  try {
    const d = JSON.parse(text);
    const pretty = JSON.stringify(d, null, 2);
    html = pretty.split('\n').map(l => {
      const esc = l.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      if (esc.includes('"ok": true') || esc.includes('"ok":true') || esc.includes(': "connected"')) return '<span class="ok">'+esc+'</span>';
      if (esc.includes('"error"') || esc.includes('"ok": false') || esc.includes('"ok":false')) return '<span class="err">'+esc+'</span>';
      if (esc.includes('"message"')) return '<span class="warn">'+esc+'</span>';
      return '<span>'+esc+'</span>';
    }).join('\n');
  } catch {
    html = text.split('\n').map(l => {
      const esc = l.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
      if (l.startsWith('[OK]') || l.includes('BLOCKED') || l.includes('ISOLATED')) return '<span class="ok">'+esc+'</span>';
      if (l.startsWith('[ERRO]') || l.includes('FAIL') || l.includes('error')) return '<span class="err">'+esc+'</span>';
      if (l.startsWith('[AVISO]') || l.includes('ALREADY') || l.includes('NOT_FOUND')) return '<span class="warn">'+esc+'</span>';
      return '<span class="info">'+esc+'</span>';
    }).join('\n');
  }
  el.innerHTML = html;
  el.parentElement.scrollTop = el.parentElement.scrollHeight;
}
function termLoading(id, msg) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = '<span class="info"><span class="spin"></span>'+(msg||'Executando...')+'</span>';
}
async function api(method, url, params, termId, btn) {
  if (btn) btn.disabled = true;
  termLoading(termId);
  try {
    const opts = {method, headers: {'Content-Type': 'application/x-www-form-urlencoded'}};
    if (method === 'POST') opts.body = new URLSearchParams(params);
    const r = await fetch(url, opts);
    const text = await r.text();
    termSet(termId, text);
  } catch(e) { termSet(termId, JSON.stringify({error: e.message})); }
  if (btn) btn.disabled = false;
}
function loadFileToTextarea(input, textareaId) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = function(e) { document.getElementById(textareaId).value = e.target.result; };
  reader.readAsText(file);
  input.value = '';
}
function parseIOCLines(raw) {
  return raw.split('\n').map(l => l.split('#')[0].trim()).filter(Boolean);
}

// ── FIREWALL ──
function fwBlockIp() {
  const ip = document.getElementById('fw-ip').value.trim();
  const cmt = document.getElementById('fw-ip-cmt').value.trim();
  const ttl = document.getElementById('fw-ip-ttl').value || '0';
  if (!ip) { alert('Digite um IP'); return; }
  api('POST', '/api/fw/block-ip', {ip, comment: cmt, ttl_minutes: ttl}, 'term-fw');
}
function fwUnblockIp() {
  const ip = document.getElementById('fw-ip').value.trim();
  if (!ip) { alert('Digite um IP'); return; }
  api('POST', '/api/fw/unblock-ip', {ip}, 'term-fw');
}
function fwBlockDomain() {
  const d = document.getElementById('fw-domain').value.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  const ttl = document.getElementById('fw-domain-ttl').value || '0';
  if (!d) { alert('Digite um dominio'); return; }
  api('POST', '/api/fw/block-domain', {domain: d, ttl_minutes: ttl}, 'term-fw');
}
function fwUnblockDomain() {
  const d = document.getElementById('fw-domain').value.trim().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
  if (!d) { alert('Digite um dominio'); return; }
  api('POST', '/api/fw/unblock-domain', {domain: d}, 'term-fw');
}
function fwIsolate() {
  const ip = document.getElementById('fw-host').value.trim();
  const r = document.getElementById('fw-host-r').value.trim();
  const ttl = document.getElementById('fw-host-ttl').value || '0';
  if (!ip) { alert('Digite o IP do host'); return; }
  if (!confirm('Isolar '+ip+'?\nHost perdera acesso a internet!')) return;
  api('POST', '/api/fw/isolate', {ip, reason: r, ttl_minutes: ttl}, 'term-fw');
}
function fwDeisolate() {
  const ip = document.getElementById('fw-host').value.trim();
  if (!ip) { alert('Digite o IP do host'); return; }
  api('POST', '/api/fw/deisolate', {ip}, 'term-fw');
}
async function fwBulkIpImport() {
  const ips = parseIOCLines(document.getElementById('fw-ip-import').value);
  if (!ips.length) { alert('Nenhum IP valido'); return; }
  if (!confirm('Bloquear '+ips.length+' IPs no FortiGate?')) return;
  termLoading('term-fw', 'Bloqueando '+ips.length+' IPs...');
  const results = [];
  for (const ip of ips) {
    try {
      const r = await fetch('/api/fw/block-ip', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: new URLSearchParams({ip, comment:'SafeLabs SOC bulk'})});
      const t = await r.text();
      results.push(t.includes('BLOCKED') || t.includes('ALREADY') ? '[OK] '+ip : '[ERRO] '+ip);
    } catch(e) { results.push('[ERRO] '+ip+': '+e.message); }
  }
  termSet('term-fw', results.join('\n')+'\n\nTotal: '+ips.length+' IPs processados');
}
async function fwBulkDomainImport() {
  const items = parseIOCLines(document.getElementById('fw-domain-import').value);
  const type = document.getElementById('fw-domain-import-type').value;
  if (!items.length) { alert('Nenhum item valido'); return; }
  if (!confirm('Bloquear '+items.length+' '+type+'s no FortiGate?')) return;
  const url = type === 'url' ? '/api/fw/block-url' : '/api/fw/block-domain';
  const key = type === 'url' ? 'url' : 'domain';
  termLoading('term-fw', 'Bloqueando '+items.length+' '+type+'s...');
  const results = [];
  for (const d of items) {
    try {
      const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: new URLSearchParams({[key]: d})});
      const t = await r.text();
      results.push(t.includes('BLOCKED') || t.includes('ALREADY') ? '[OK] '+d : '[ERRO] '+d);
    } catch(e) { results.push('[ERRO] '+d+': '+e.message); }
  }
  termSet('term-fw', results.join('\n')+'\n\nTotal: '+items.length+' itens');
}

// ── EDR ──
function setAgentId(id, name) {
  document.getElementById('edr-id').value = id;
  termSet('term-edr', 'Agent ID: '+name+' ('+id+')');
}
function edrIsolate() {
  const id = document.getElementById('edr-id').value.trim();
  const r = document.getElementById('edr-r').value.trim();
  if (!id) { alert('Selecione um Agent ID'); return; }
  if (!confirm('Isolar agente '+id+'?\nHost perdera toda conectividade!')) return;
  api('POST', '/api/edr/isolate', {agent_id: id, reason: r}, 'term-edr');
}
function edrDeisolate() {
  const id = document.getElementById('edr-id').value.trim();
  if (!id) { alert('Selecione um Agent ID'); return; }
  api('POST', '/api/edr/deisolate', {agent_id: id}, 'term-edr');
}
function edrScan() {
  const id = document.getElementById('edr-id').value.trim();
  if (!id) { alert('Selecione um Agent ID'); return; }
  api('POST', '/api/edr/scan', {agent_id: id}, 'term-edr');
}
function edrChain() {
  const id = document.getElementById('edr-id').value.trim();
  if (!id) { alert('Selecione um Agent ID'); return; }
  if (!confirm('Contencao Total em '+id+'?\n1. Isolar\n2. Scan\n3. Coletar IOCs')) return;
  api('POST', '/api/edr/chain', {agent_id: id}, 'term-edr');
}
function edrBlacklist() {
  const h = document.getElementById('edr-hash').value.trim();
  const d = document.getElementById('edr-hash-d').value.trim();
  if (!h) { alert('Digite o hash'); return; }
  if (!/^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$/.test(h)) {
    alert('Hash invalido. Aceitos: MD5 (32), SHA1 (40) ou SHA256 (64) hex chars.');
    return;
  }
  api('POST', '/api/edr/blacklist-hash', {hash_value: h, description: d}, 'term-edr');
}
async function edrBulkHash() {
  const raw = document.getElementById('edr-hash-import').value.trim();
  if (!raw) { alert('Cole os hashes'); return; }
  const hashes = parseIOCLines(raw).filter(h => /^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$/.test(h));
  if (!hashes.length) { alert('Nenhum hash SHA1/SHA256 valido'); return; }
  if (!confirm('Adicionar '+hashes.length+' hashes a blacklist S1?')) return;
  termLoading('term-edr', 'Adicionando '+hashes.length+' hashes...');
  const results = [];
  for (const h of hashes) {
    try {
      await fetch('/api/edr/blacklist-hash', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: new URLSearchParams({hash_value: h, description: 'SafeLabs SOC bulk'})});
      results.push('[OK] '+h);
    } catch(e) { results.push('[ERRO] '+h+': '+e.message); }
  }
  termSet('term-edr', results.join('\n')+'\n\nTotal: '+hashes.length+' hashes');
}
async function edrListThreats() {
  termLoading('term-edr', 'Buscando threats...');
  try {
    const r = await fetch('/api/edr/list-threats', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: ''});
    const text = await r.text();
    try {
      const data = JSON.parse(text);
      if (data.threats && data.threats.length === 0) {
        termSet('term-edr', JSON.stringify({message: data.message || 'Nenhuma threat nao tratada no momento', filter: data.filter || {}}, null, 2));
      } else {
        termSet('term-edr', text);
      }
    } catch { termSet('term-edr', text); }
  } catch(e) { termSet('term-edr', JSON.stringify({error: e.message})); }
}
async function loadAgents() {
  const tbody = document.getElementById('agents-body');
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--dim);padding:12px"><span class="spin"></span> Carregando...</td></tr>';
  try {
    const r = await fetch('/api/edr/agents');
    const agents = await r.json();
    if (agents.error) { tbody.innerHTML = '<tr><td colspan="6" style="color:var(--red)">'+agents.error+'</td></tr>'; return; }
    tbody.innerHTML = agents.map(a => '<tr>'+
      '<td style="font-weight:700;color:var(--green)">'+(a.name||'?')+'</td>'+
      '<td style="color:var(--dim)">'+(a.os||'?').substring(0,20)+'</td>'+
      '<td><span class="pill '+(a.network==='connected'?'p-ok':'p-err')+'">'+(a.network||'?')+'</span></td>'+
      '<td><span class="pill '+(a.active_threats>0?'p-err':'p-ok')+'">'+(a.active_threats||0)+'</span></td>'+
      '<td style="color:var(--dim);font-size:.75rem">'+(a.ips||'?')+'</td>'+
      '<td style="white-space:nowrap"><button class="btn b-cyan" style="padding:3px 9px;font-size:.7rem" onclick="setAgentId(\''+a.id+'\',\''+a.name+'\')">SELECT</button></td>'+
    '</tr>').join('');
  } catch(e) { tbody.innerHTML = '<tr><td colspan="6" style="color:var(--red)">[ERRO] '+e.message+'</td></tr>'; }
}

// ── AD ──
function setAdUser(u) { document.getElementById('ad-user').value = u; }
function adStatus() { const u=document.getElementById('ad-user').value.trim(); if(!u){alert('Digite um usuario');return;} api('POST','/api/ad/status',{username:u},'term-ad'); }
function adDisable() { const u=document.getElementById('ad-user').value.trim(); const r=document.getElementById('ad-r').value.trim(); if(!u){alert('Digite um usuario');return;} if(!confirm('Desativar "'+u+'"?')) return; api('POST','/api/ad/disable',{username:u,reason:r},'term-ad'); }
function adEnable() { const u=document.getElementById('ad-user').value.trim(); if(!u){alert('Digite um usuario');return;} api('POST','/api/ad/enable',{username:u},'term-ad'); }
function adResetPwd() { const u=document.getElementById('ad-user').value.trim(); if(!u){alert('Digite um usuario');return;} api('POST','/api/ad/reset-password',{username:u},'term-ad'); }
function adUnlock() { const u=document.getElementById('ad-user').value.trim(); if(!u){alert('Digite um usuario');return;} api('POST','/api/ad/unlock',{username:u},'term-ad'); }
function adBulk() {
  const raw=document.getElementById('ad-bulk').value.trim();
  const act=document.getElementById('ad-bulk-act').value;
  if(!raw){alert('Cole os usuarios');return;}
  const users=raw.split('\n').map(u=>u.trim()).filter(Boolean);
  if(!users.length){alert('Nenhum usuario');return;}
  if(act!=='status'&&!confirm('Executar "'+act+'" em '+users.length+' usuarios?')) return;
  api('POST','/api/ad/bulk',{users:JSON.stringify(users),action:act},'term-ad');
}
async function loadAdUsers() {
  const el = document.getElementById('ad-users-list');
  if(!el) return;
  el.innerHTML = '<span class="spin"></span> Carregando usuarios...';
  try {
    const r = await fetch('/api/ad/users');
    const data = await r.json();
    if (data.error) { el.innerHTML = '<div class="err">'+data.error+'</div>'; return; }
    const users = data.users || [];
    if (!users.length) { el.innerHTML = '<div style="color:var(--dim)">Nenhum usuario ativo encontrado.</div>'; return; }
    el.innerHTML = '<div style="margin-bottom:8px;font-size:.73rem;color:var(--dim)">'+users.length+' usuarios ativos</div>'
      + '<table style="width:100%;border-collapse:collapse;font-size:.75rem">'
      + '<thead><tr style="border-bottom:2px solid var(--border)">'
      + '<th style="text-align:left;padding:6px 8px;color:var(--dim)">Conta</th>'
      + '<th style="text-align:left;padding:6px 8px;color:var(--dim)">Nome</th>'
      + '<th style="text-align:left;padding:6px 8px;color:var(--dim)">Email</th>'
      + '<th style="text-align:left;padding:6px 8px;color:var(--dim)">Ultimo logon</th>'
      + '<th style="text-align:center;padding:6px 8px;color:var(--dim)">Acoes</th>'
      + '</tr></thead><tbody>'
      + users.map(function(u){
          return '<tr style="border-bottom:1px solid var(--border)">'
            + '<td style="padding:6px 8px;font-family:monospace;color:var(--cyan)">'+u.sam+'</td>'
            + '<td style="padding:6px 8px">'+u.name+'</td>'
            + '<td style="padding:6px 8px;color:var(--dim)">'+u.mail+'</td>'
            + '<td style="padding:6px 8px;color:var(--dim);font-size:.7rem">'+(u.last_logon||'-')+'</td>'
            + '<td style="padding:4px 8px;text-align:center">'
            + '<button class="ic-btn" title="Desabilitar" onclick="adAction(\'disable\',\''+u.sam+'\')" style="color:var(--red)">&#128683;</button>'
            + '<button class="ic-btn" title="Reset senha" onclick="adAction(\'reset-password\',\''+u.sam+'\')" style="color:var(--yellow)">&#128273;</button>'
            + '</td></tr>';
        }).join('')
      + '</tbody></table>';
  } catch(e) { el.innerHTML = '<div class="err">'+e.message+'</div>'; }
}

async function adAction(action, username) {
  if(!confirm(action+' para '+username+'?')) return;
  termLoading('term-ad','Executando '+action+' em '+username+'...');
  try {
    const url = '/api/ad/'+action;
    const r = await fetch(url, {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:'username='+encodeURIComponent(username)});
    const t = await r.text();
    termSet('term-ad', t);
  } catch(e) { termSet('term-ad', JSON.stringify({error:e.message})); }
}

async function dnsBulkImport() {
  const domains = parseIOCLines(document.getElementById('dns-import').value);
  if (!domains.length) { alert('Nenhum dominio valido'); return; }
  if (!confirm('Bloquear '+domains.length+' dominios no DNS?')) return;
  termLoading('term-dns', 'Bloqueando '+domains.length+' dominios...');
  const results = [];
  for (const d of domains) {
    try {
      const r = await fetch('/api/dns/block', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: new URLSearchParams({domain: d.replace(/^https?:\/\//,'').replace(/\/.*$/,'')})});
      const t = await r.text();
      try { const j=JSON.parse(t); results.push(j.ok?'[OK] '+d:'[ERRO] '+d+': '+(j.output||j.error||'')); }
      catch { results.push('[OK] '+d); }
    } catch(e) { results.push('[ERRO] '+d+': '+e.message); }
  }
  termSet('term-dns', results.join('\n')+'\n\nTotal: '+domains.length+' dominios');
}

// ── DASHBOARD ──
async function checkStatus() {
  try {
    const r = await fetch('/api/status');
    const d = await r.json();
    for (const [k, v] of Object.entries(d)) {
      const dot = document.getElementById('d-'+k);
      if (dot) dot.className = 'dot '+(v?'ok':'err');
    }
  } catch {}
}
async function loadDashStatus() {
  try {
    const r = await fetch('/api/status/full');
    const d = await r.json();
    const agEl = document.getElementById('dash-agents');
    let html = '';
    for (const [k, info] of Object.entries(d)) {
      const ok = info.ok;
      const sc = document.getElementById('sc-'+k);
      const sv = document.getElementById('sv-'+k);
      if (sc) sc.className = 'stat '+(ok?(k==='edr'?'c':'g'):'r');
      if (sv) sv.textContent = ok?(info.value||'ONLINE'):'OFFLINE';
      html += '<div style="color:'+(ok?'var(--green)':'var(--red)')+';font-size:.77rem">'+(ok?'OK':'OFFLINE')+' '+k.toUpperCase()+': '+(ok?(info.value||'OK'):'Offline')+'</div>';
    }
    if (agEl) agEl.innerHTML = html;
  } catch(e) {
    const agEl = document.getElementById('dash-agents');
    if (agEl) agEl.textContent = 'Erro: '+e.message;
  }
}
checkStatus();
setInterval(checkStatus, 30000);

// ── THREAT INTEL ──

// == APT CAMPAIGNS ==
var _aptCache = [];
var _containmentMap = {};
function _originClass(o){
  if(!o) return 'origin-other';
  var l=o.toLowerCase();
  if(l.indexOf('russia')>=0||l.indexOf('cis')>=0) return 'origin-russia';
  if(l.indexOf('china')>=0) return 'origin-china';
  if(l.indexOf('iran')>=0) return 'origin-iran';
  if(l.indexOf('korea')>=0) return 'origin-nk';
  return 'origin-other';
}
function _updateSummary(camps){
  var total=camps.length, iocs=0, origins={}, checked=0, covered=0;
  camps.forEach(function(cp){
    var io=cp.iocs||{};
    iocs+=(io.ips||[]).length+(io.domains||[]).length+(io.hashes||[]).length+(io.urls||[]).length;
    if(cp.origin) origins[cp.origin]=1;
    if(cp.containment && cp.containment.pct_contained!==undefined){checked++;if(cp.containment.pct_contained>=100) covered++;}
  });
  var se=function(id,v){var e=document.getElementById(id);if(e)e.textContent=v;};
  se('as-total',total);
  se('as-iocs',iocs);
  se('as-covered',checked?covered+'/'+total:'N/A');
  se('as-origins',Object.keys(origins).length);
}
function filterAptList(){
  var q=(document.getElementById('apt-filter').value||'').toLowerCase();
  var orig=document.getElementById('apt-origin-filter').value;
  var cov=document.getElementById('apt-coverage-filter').value;
  var filtered=_aptCache.filter(function(cp){
    if(q){
      var haystack=(cp.name+' '+cp.adversary+' '+(cp.tags||[]).join(' ')+' '+(cp.origin||'')+' '+(cp.description||'')).toLowerCase();
      if(haystack.indexOf(q)<0) return false;
    }
    if(orig){
      var o=(cp.origin||'').toLowerCase();
      if(orig==='other'){if(o.indexOf('russia')>=0||o.indexOf('china')>=0||o.indexOf('iran')>=0||o.indexOf('korea')>=0) return false;}
      else if(o.indexOf(orig.toLowerCase())<0) return false;
    }
    if(cov){
      var ct=cp.containment||_containmentMap[cp.id]||null;
      if(cov==='full'&&(!ct||ct.pct_contained<100)) return false;
      if(cov==='partial'&&(!ct||ct.pct_contained<=0||ct.pct_contained>=100)) return false;
      if(cov==='none'&&(!ct||ct.pct_contained>0)) return false;
      if(cov==='unchecked'&&ct) return false;
    }
    return true;
  });
  _renderAptCards(_sortCamps(filtered));
}
var _aptSortCol='name';
var _aptSortAsc=true;

function aptSort(col){
  if(_aptSortCol===col){_aptSortAsc=!_aptSortAsc;}
  else{_aptSortCol=col;_aptSortAsc=true;}
  filterAptList();
}

function _sortCamps(camps){
  var col=_aptSortCol,asc=_aptSortAsc;
  return camps.slice().sort(function(a,b){
    var va,vb;
    var ai=a.iocs||{}, bi=b.iocs||{};
    switch(col){
      case 'name': va=(a.name||'').toLowerCase(); vb=(b.name||'').toLowerCase(); break;
      case 'origin': va=(a.origin||'').toLowerCase(); vb=(b.origin||'').toLowerCase(); break;
      case 'mitre': va=(a.mitre_id||''); vb=(b.mitre_id||''); break;
      case 'ips': va=(ai.ips||[]).length; vb=(bi.ips||[]).length; break;
      case 'dom': va=(ai.domains||[]).length; vb=(bi.domains||[]).length; break;
      case 'hash': va=(ai.hashes||[]).length; vb=(bi.hashes||[]).length; break;
      case 'url': va=(ai.urls||[]).length; vb=(bi.urls||[]).length; break;
      case 'total': va=(ai.ips||[]).length+(ai.domains||[]).length+(ai.hashes||[]).length+(ai.urls||[]).length; vb=(bi.ips||[]).length+(bi.domains||[]).length+(bi.hashes||[]).length+(bi.urls||[]).length; break;
      case 'pct': var ac=a.containment||_containmentMap[a.id]; var bc=b.containment||_containmentMap[b.id]; va=ac?ac.pct_contained:-1; vb=bc?bc.pct_contained:-1; break;
      default: va=0;vb=0;
    }
    if(typeof va==='string'){var r=va.localeCompare(vb);return asc?r:-r;}
    return asc?va-vb:vb-va;
  });
}

function _renderAptCards(camps){
  var el=document.getElementById('apt-list');
  if(!el) return;
  if(!camps.length){el.innerHTML='<div style="color:var(--dim);padding:20px;text-align:center">Nenhum APT group encontrado para este filtro.</div>';return;}
  var html='<div class="batch-bar">'
    +'<label><input type="checkbox" id="apt-select-all" onchange="aptToggleAll(this.checked)"> Todos</label>'
    +'<span style="color:var(--dim)">|</span>'
    +'<span id="apt-sel-count" style="color:var(--text)">0 selecionados</span>'
    +'<span style="color:var(--dim)">|</span>'
    +'<span style="color:var(--dim)">Ferramentas:</span>'
    +'<label style="cursor:pointer"><input type="checkbox" class="batch-tool" value="fw" checked> FW</label>'
    +'<label style="cursor:pointer"><input type="checkbox" class="batch-tool" value="dns" checked> DNS</label>'
    +'<label style="cursor:pointer"><input type="checkbox" class="batch-tool" value="edr" checked> EDR</label>'
    +'</div>';
  var _sa=function(col){return ' onclick="aptSort(\''+col+'\')"';};
  var _sh=function(col,label,align){
    var cls='sortable'+(_aptSortCol===col?(_aptSortAsc?' asc':' desc'):'');
    var arrow=_aptSortCol===col?(_aptSortAsc?'&#9650;':'&#9660;'):'&#8597;';
    var st=align?'text-align:center;':'';
    return '<th class="'+cls+'" style="'+st+'"'+_sa(col)+'>'+label+'<span class="sort-arrow">'+arrow+'</span></th>';
  };
  html+='<div class="apt-tbl-wrap"><table class="apt-tbl"><thead><tr>'
    +'<th class="cb-col"><input type="checkbox" id="apt-select-all2" onchange="aptToggleAll(this.checked)"></th>'
    +_sh('name','APT Group')
    +_sh('origin','Origem')
    +_sh('mitre','MITRE')
    +_sh('ips','IPs',true)
    +_sh('dom','Dom',true)
    +_sh('hash','Hash',true)
    +_sh('url','URL',true)
    +_sh('total','Total',true)
    +_sh('pct','Contencao')
    +'<th class="act-col">Acoes</th>'
    +'</tr></thead><tbody>';
  camps.forEach(function(cp){
    var iocs=cp.iocs||{};
    var nIp=(iocs.ips||[]).length, nDom=(iocs.domains||[]).length, nHash=(iocs.hashes||[]).length, nUrl=(iocs.urls||[]).length;
    var total=nIp+nDom+nHash+nUrl;
    var ct=cp.containment||_containmentMap[cp.id]||null;
    var pct=ct?ct.pct_contained:null;
    var oc=_originClass(cp.origin);
    var pctColor=pct===null?'var(--dim)':pct>=80?'var(--green)':pct>=40?'var(--yellow)':'var(--red)';
    var pctBg=pct===null?'transparent':pct>=80?'var(--green)':pct>=40?'var(--yellow)':'var(--red)';
    html+='<tr id="row-'+cp.id+'" data-id="'+cp.id+'">'
      +'<td class="cb-col"><input type="checkbox" class="apt-cb" data-id="'+cp.id+'" onchange="aptSelCount()"></td>'
      +'<td class="name-col">'+cp.name+'</td>'
      +'<td>'+(cp.origin?'<span class="origin-badge '+oc+'" style="font-size:.6rem">'+cp.origin+'</span>':'-')+'</td>'
      +'<td>'+(cp.mitre_id?'<a class="mitre-link" href="https://attack.mitre.org/groups/'+cp.mitre_id+'/" target="_blank">'+cp.mitre_id+'</a>':'-')+'</td>'
      +'<td style="text-align:center;color:var(--orange)">'+nIp+'</td>'
      +'<td style="text-align:center;color:var(--cyan)">'+nDom+'</td>'
      +'<td style="text-align:center;color:var(--purple)">'+nHash+'</td>'
      +'<td style="text-align:center;color:var(--yellow)">'+nUrl+'</td>'
      +'<td style="text-align:center;font-weight:700;color:var(--red)">'+total+'</td>'
      +'<td id="pct-'+cp.id+'">'
        +(pct!==null
          ?'<span class="pct-bar"><span class="pct-fill" style="width:'+pct+'%;background:'+pctBg+'"></span></span>'
           +'<span style="color:'+pctColor+';font-size:.7rem;font-weight:600">'+pct+'%</span>'
          :'<span style="color:var(--dim);font-size:.68rem">--</span>')
      +'</td>'
      +'<td class="act-col">'
        +'<button class="act-btn b-check" onclick="checkCampaignContainment(\''+cp.id+'\')" title="Verificar contencao">CHECK</button>'
        +'<button class="act-btn b-apply" onclick="applyGaps(\''+cp.id+'\')" title="Aplicar gaps pendentes">APPLY</button>'
        +'<button class="act-btn b-del" onclick="deleteCampaign(\''+cp.id+'\')" title="Remover">DEL</button>'
      +'</td></tr>';
  });
  html+='</tbody></table></div>';
  el.innerHTML=html;
}
async function loadAptCampaigns(){
  var el=document.getElementById('apt-list');
  if(!el){console.error('apt-list element not found');return;}
  try{
    var r=await fetch('/api/apt/campaigns');
    if(!r.ok){el.innerHTML='<div class="err">HTTP '+r.status+'</div>';return;}
    var camps=await r.json();
    if(!Array.isArray(camps)){el.innerHTML='<div class="err">Resposta invalida</div>';return;}
    _aptCache=camps;
    _updateSummary(camps);
    _renderAptCards(_sortCamps(camps));
    _loadContainmentFromCache();
  }catch(e){
    console.error('loadAptCampaigns error:',e);
    if(el) el.innerHTML='<div class="err">Erro: '+e.message+'</div>';
  }
}
async function _loadContainmentFromCache(){
  try{
    var r=await fetch('/api/apt/containment/all');
    var bulk=await r.json();
    var camps=bulk.campaigns||{};
    _containmentMap=camps;
    _aptCache.forEach(function(cp){
      if(camps[cp.id]) cp.containment=camps[cp.id];
    });
    Object.keys(camps).forEach(function(cid){_updateCardContainment(cid, camps[cid]);});
    var tsEl=document.getElementById('as-lastcheck');
    if(tsEl && bulk.last_refresh) tsEl.textContent=new Date(bulk.last_refresh).toLocaleString('pt-BR');
    var asEl=document.getElementById('as-covered');
    if(asEl){
      var keys=Object.keys(camps);
      var covered=keys.filter(function(k){return camps[k].pct_contained>=100;}).length;
      asEl.textContent=covered+'/'+keys.length;
    }
    filterAptList();
  }catch(e){console.error('containment cache:',e);}
}
function _ts(){return new Date().toLocaleString('pt-BR',{hour:'2-digit',minute:'2-digit',second:'2-digit'});}
function termAppend(id,text){
  var el=document.getElementById(id);if(!el)return;
  var lines=text.split('\n');
  var html=lines.map(function(l){
    var esc=l.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    if(l.indexOf('[OK]')>=0||l.indexOf('BLOCKED')>=0||l.indexOf('100%')>=0) return '<span class="ok">'+esc+'</span>';
    if(l.indexOf('[ERRO]')>=0||l.indexOf('FAIL')>=0||l.indexOf('error')>=0) return '<span class="err">'+esc+'</span>';
    if(l.indexOf('[WARN]')>=0||l.indexOf('ALREADY')>=0||l.indexOf('SKIP')>=0) return '<span class="warn">'+esc+'</span>';
    if(l.indexOf('---')>=0) return '<span style="color:var(--border)">'+esc+'</span>';
    return '<span class="info">'+esc+'</span>';
  }).join('\n');
  el.innerHTML+='\n'+html;
  el.parentElement.scrollTop=el.parentElement.scrollHeight;
}
function exportLog(termId,prefix){
  var el=document.getElementById(termId);if(!el)return;
  var text=el.innerText||el.textContent;
  if(!text||text.trim()==='Pronto...'||text.trim()==='Aguardando acao...'){alert('Log vazio');return;}
  var blob=new Blob([text],{type:'text/plain'});
  var a=document.createElement('a');
  a.href=URL.createObjectURL(blob);
  a.download=(prefix||'log')+'-'+new Date().toISOString().slice(0,19).replace(/[T:]/g,'-')+'.txt';
  a.click();
  URL.revokeObjectURL(a.href);
}
function aptToggleAll(checked){
  document.querySelectorAll('.apt-cb').forEach(function(cb){cb.checked=checked;});
  var sa=document.getElementById('apt-select-all');if(sa)sa.checked=checked;
  var sa2=document.getElementById('apt-select-all2');if(sa2)sa2.checked=checked;
  aptSelCount();
}
function aptSelCount(){
  var n=document.querySelectorAll('.apt-cb:checked').length;
  var el=document.getElementById('apt-sel-count');
  if(el) el.textContent=n+' selecionados';
}
function _getSelectedTools(){
  var tools=[];
  document.querySelectorAll('.batch-tool:checked').forEach(function(cb){tools.push(cb.value);});
  return tools.length?tools:['fw','dns','edr'];
}
function _getSelectedApts(){
  var ids=[];
  document.querySelectorAll('.apt-cb:checked').forEach(function(cb){ids.push(cb.dataset.id);});
  return ids;
}
async function applySelectedGaps(){
  var ids=_getSelectedApts();
  if(!ids.length){alert('Selecione ao menos um APT group na tabela');return;}
  var tools=_getSelectedTools();
  var toolNames={fw:'Firewall',dns:'DNS Server',edr:'EDR/SentinelOne'};
  var sel=tools.map(function(t){return toolNames[t]||t;}).join(', ');
  if(!confirm('Aplicar gaps de '+ids.length+' APT(s) selecionados via '+sel+'?\n\nISTO PODE DEMORAR dependendo da quantidade de IOCs e ferramentas.')){return;}
  termAppend('term-apt','['+_ts()+'] === BATCH APPLY GAPS ===');
  termAppend('term-apt','['+_ts()+'] APTs selecionados: '+ids.length);
  termAppend('term-apt','['+_ts()+'] Ferramentas: '+sel);
  termAppend('term-apt','['+_ts()+'] AVISO: Cada APT sera processado sequencialmente. Operacao pode levar varios minutos.');
  termAppend('term-apt','---');
  var totalOk=0,totalErr=0,totalSkip=0;
  for(var i=0;i<ids.length;i++){
    var campId=ids[i];
    var camp=_aptCache.find(function(x){return x.id===campId;});
    var name=camp?camp.name:campId;
    termAppend('term-apt','['+_ts()+'] ['+String(i+1)+'/'+ids.length+'] Processando: '+name+'...');
    try{
      var r=await fetch('/api/apt/campaigns/'+campId+'/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tools:tools})});
      var d=await r.json();
      if(d.error){termAppend('term-apt','['+_ts()+'] [ERRO] '+name+': '+d.error);totalErr++;continue;}
      var ok=0,err=0;
      (d.details||[]).forEach(function(it){
        var icon=it.ok?'[OK]':'[ERRO]';
        if(it.ok)ok++;else err++;
        termAppend('term-apt','  '+icon+' '+it.type.toUpperCase()+': '+it.value+(it.target?' -> '+it.target:'')+(it.error?' ('+it.error+')':''));
      });
      totalOk+=ok;totalErr+=err;totalSkip+=(d.skipped||0);
      termAppend('term-apt','['+_ts()+'] '+name+': '+ok+' OK, '+err+' erros'+(d.skipped?' | '+d.skipped+' ignorados':''));
    }catch(e){
      termAppend('term-apt','['+_ts()+'] [ERRO] '+name+': '+e.message);totalErr++;
    }
    termAppend('term-apt','---');
  }
  termAppend('term-apt','['+_ts()+'] === BATCH CONCLUIDO ===');
  termAppend('term-apt','['+_ts()+'] Total: '+totalOk+' OK | '+totalErr+' Erros | '+totalSkip+' Ignorados');
  termAppend('term-apt','['+_ts()+'] Cache de contencao sera atualizado em background...');
}

function _updateCardContainment(campId, d){
  var el=document.getElementById('pct-'+campId);
  if(!el) return;
  var pct=d.pct_contained;
  var pctColor=pct>=80?'var(--green)':pct>=40?'var(--yellow)':'var(--red)';
  el.innerHTML='<span class="pct-bar"><span class="pct-fill" style="width:'+pct+'%;background:'+pctColor+'"></span></span>'
    +'<span style="color:'+pctColor+';font-size:.7rem;font-weight:600">'+pct+'%</span>';
}

async function checkCampaignContainment(campId){
  termAppend('term-apt','['+_ts()+'] Verificando contencao: '+campId+'...');
  try{
    var r=await fetch('/api/apt/containment/all');
    var bulk=await r.json();
    var d=bulk.campaigns[campId];
    if(!d){termAppend('term-apt','['+_ts()+'] [WARN] Campanha '+campId+' nao encontrada no cache. Aguarde refresh...');return;}
    _updateCardContainment(campId, d);
    termAppend('term-apt','['+_ts()+'] '+d.campaign_name+': '+d.pct_contained+'% contida');
    termAppend('term-apt','  IPs: '+d.ips.blocked+'/'+d.ips.total+'  Dom: '+d.domains.blocked+'/'+d.domains.total+'  Hash: '+d.hashes.blocked+'/'+d.hashes.total+(d.urls?'  URL: '+d.urls.blocked+'/'+d.urls.total:''));
    if(d.pct_contained<100){
      if(d.ips.gaps.length) termAppend('term-apt','  [WARN] IPs sem bloqueio: '+d.ips.gaps.join(', '));
      if(d.domains.gaps.length) termAppend('term-apt','  [WARN] Dominios sem bloqueio: '+d.domains.gaps.join(', '));
      if(d.hashes.gaps.length) termAppend('term-apt','  [WARN] Hashes sem blacklist: '+d.hashes.gaps.slice(0,3).join(', ')+(d.hashes.gaps.length>3?'...':''));
      if(d.urls&&d.urls.gaps.length) termAppend('term-apt','  [WARN] URLs sem bloqueio: '+d.urls.gaps.join(', '));
    } else { termAppend('term-apt','  [OK] Contencao completa!'); }
    if(bulk.last_refresh) termAppend('term-apt','  [Cache: '+new Date(bulk.last_refresh).toLocaleString('pt-BR')+']');
  }catch(e){termAppend('term-apt','['+_ts()+'] [ERRO] '+e.message);}
}

async function refreshAptContainment(){
  termAppend('term-apt','['+_ts()+'] === CHECK GLOBAL DE CONTENCAO ===');
  try{
    var r=await fetch('/api/apt/containment/all');
    var bulk=await r.json();
    var camps=bulk.campaigns||{};
    var keys=Object.keys(camps);
    var total=keys.length, covered=0, partial=0, none=0;
    keys.forEach(function(cid){
      var d=camps[cid];
      _updateCardContainment(cid, d);
      if(d.pct_contained>=100) covered++;
      else if(d.pct_contained>0) partial++;
      else none++;
    });
    var asEl=document.getElementById('as-covered');
    if(asEl) asEl.textContent=covered+'/'+total;
    var tsEl=document.getElementById('as-lastcheck');
    if(tsEl && bulk.last_refresh) tsEl.textContent=new Date(bulk.last_refresh).toLocaleString('pt-BR');
    termAppend('term-apt','['+_ts()+'] Total: '+total+' campanhas analisadas');
    termAppend('term-apt','['+_ts()+'] [OK] 100%% contidas: '+covered);
    termAppend('term-apt','['+_ts()+'] [WARN] Parciais: '+partial);
    termAppend('term-apt','['+_ts()+'] [ERRO] Sem cobertura: '+none);
    if(bulk.last_refresh) termAppend('term-apt','['+_ts()+'] Cache: '+new Date(bulk.last_refresh).toLocaleString('pt-BR'));
    termAppend('term-apt','---');
  }catch(e){termAppend('term-apt','['+_ts()+'] [ERRO] '+e.message);}
}

async function applyGaps(campId){
  var tools=_getSelectedTools();
  var toolNames={fw:'Firewall',dns:'DNS Server',edr:'EDR/SentinelOne'};
  var sel=tools.map(function(t){return toolNames[t]||t;}).join(', ');
  var camp=_aptCache.find(function(x){return x.id===campId;});
  var campName=camp?camp.name:campId;
  if(!confirm('Aplicar gaps de "'+campName+'" via '+sel+'?\n\nPode demorar dependendo da qtd de IOCs.')){return;}
  termAppend('term-apt','['+_ts()+'] === APPLY GAPS: '+campName+' ===');
  termAppend('term-apt','['+_ts()+'] Ferramentas: '+sel);
  termAppend('term-apt','['+_ts()+'] Enviando request... (pode demorar)');
  try{
    var r=await fetch('/api/apt/campaigns/'+campId+'/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({tools:tools})});
    var d=await r.json();
    if(d.error){termAppend('term-apt','['+_ts()+'] [ERRO] '+d.error);return;}
    var okCount=0,errCount=0;
    (d.details||[]).forEach(function(it){
      var icon=it.ok?'[OK]':'[ERRO]';
      if(it.ok) okCount++; else errCount++;
      termAppend('term-apt','  '+icon+' '+it.type.toUpperCase()+': '+it.value+(it.target?' -> '+it.target:'')+(it.error?' ('+it.error+')':''));
    });
    termAppend('term-apt','['+_ts()+'] '+campName+': '+okCount+' OK | '+errCount+' Erros'+(d.skipped?' | '+d.skipped+' ignorados':''));
    termAppend('term-apt','['+_ts()+'] Cache de contencao sera atualizado em background...');
    termAppend('term-apt','---');
  }catch(e){termAppend('term-apt','['+_ts()+'] [ERRO] '+e.message);}
}

function toggleAddCampForm(){
  var f=document.getElementById('camp-add-form');
  if(f) f.style.display=f.style.display==='none'?'block':'none';
}

async function saveCampaign(){
  var name=document.getElementById('camp-name').value.trim();
  if(!name){alert('Informe o nome da campanha');return;}
  function lines(id){var v=document.getElementById(id).value.trim();return v?v.split('\n').map(function(s){return s.trim();}).filter(Boolean):[];}
  var body={
    name:name,
    adversary:document.getElementById('camp-adv').value.trim(),
    origin:(document.getElementById('camp-origin')||{}).value||'',
    mitre_id:(document.getElementById('camp-mitre')||{}).value||'',
    description:document.getElementById('camp-desc').value.trim(),
    tags:document.getElementById('camp-tags').value.split(',').map(function(s){return s.trim();}).filter(Boolean),
    iocs:{ips:lines('camp-ips'),domains:lines('camp-domains'),hashes:lines('camp-hashes'),urls:lines('camp-urls')}
  };
  termLoading('term-apt','Salvando campanha...');
  try{
    const r=await fetch('/api/apt/campaigns',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();
    termSet('term-apt',JSON.stringify(d,null,2));
    if(d.ok){toggleAddCampForm();loadAptCampaigns();}
  }catch(e){termSet('term-apt',JSON.stringify({error:e.message}));}
}

async function deleteCampaign(campId){
  if(!confirm('Remover esta campanha?')) return;
  try{
    const r=await fetch('/api/apt/campaigns/'+campId,{method:'DELETE'});
    const d=await r.json();
    termSet('term-apt',JSON.stringify(d,null,2));
    if(d.ok) loadAptCampaigns();
  }catch(e){termSet('term-apt',JSON.stringify({error:e.message}));}
}

// Compatibilidade com botoes antigos
function loadCampaigns(){loadAptCampaigns();}
function checkContainment(){refreshAptContainment();}

let _catalog = {};
let _editingId = null, _wizardStep = 1;
let _selClass = null, _selVendor = null, _selProduct = null;
const _clsBadge = {firewall:'badge-firewall',edr:'badge-edr',identity:'badge-identity',dns:'badge-dns'};
const _clsLabel = {firewall:'Firewall',edr:'EDR / XDR',identity:'Active Directory',dns:'DNS'};
const _mthLabel = {api:'API',ssh:'SSH',ldap:'LDAP',syslog:'Syslog'};


async function loadIntegrations(){
  try{
    const [ri,rc]=await Promise.all([fetch('/api/integrations'),fetch('/api/integrations/catalog')]);
    const intgs=await ri.json(); _catalog=await rc.json();
    const tbody=document.getElementById('intg-tbody');
    if(!intgs.length){tbody.innerHTML='<tr><td colspan=7 style="padding:20px;text-align:center;color:#5a6a85">Nenhuma integracao. Clique em + Nova Integracao.</td></tr>';return;}
    tbody.innerHTML=intgs.map(i=>{
      const cls=i.class||'',enabled=i.enabled!==false,badge=_clsBadge[cls]||'';
      return '<tr>'
        +'<td style="font-weight:700">'+i.name+'</td>'
        +'<td><span class="badge-cls '+badge+'">'+((_clsLabel[cls])||cls)+'</span></td>'
        +'<td style="color:#5a6a85">'+i.vendor+'</td>'
        +'<td style="color:#5a6a85">'+i.product+'</td>'
        +'<td><span style="font-size:.72rem;color:#00d4ff">'+(_mthLabel[i.integration_method]||i.integration_method||'')+'</span></td>'
        +'<td><label class="sw"><input type="checkbox" '+(enabled?'checked':'')+' onchange="toggleIntg(\''+i.id+'\',this)"><span class="sw-slider"></span></label>'
        +' <span class="badge-status '+(enabled?'badge-ok':'badge-dis')+'" title="'+(i.last_status&&i.last_status.timestamp?'Testado: '+new Date(i.last_status.timestamp).toLocaleTimeString('pt-BR'):'Nunca testado')+'">'+(enabled?(i.last_status?(i.last_status.ok?'ATIVO':'OFFLINE'):'ATIVO'):'OFF')+'</span></td>'
        +'<td style="text-align:center">'
        +'<button class="ic-btn" onclick="editIntg(\''+i.id+'\')" title="Editar">&#9998;</button>'
        +'<button class="ic-btn" onclick="showHelp(\''+i.id+'\')" title="Playbooks e Inputs" style="color:#bf5af2">&#63;</button>'
        +'<button class="ic-btn" onclick="testIntg(\''+i.id+'\')" title="Testar conexao" style="color:#00d4ff">&#9654;</button>'
        +'<button class="ic-btn" onclick="deleteIntg(\''+i.id+'\')" title="Remover" style="color:#ff2d55">&#128465;</button>'
        +'</td></tr>';
    }).join('');
  }catch(e){termSet('term-config',JSON.stringify({error:e.message}));}
  try{initDynamicUI();}catch(_err){}
  loadAptCampaigns().catch(function(e){console.error('preload APT:',e);});
}

async function toggleIntg(id,cb){
  try{const r=await fetch('/api/integrations/'+id+'/toggle',{method:'POST'});
    const d=await r.json();termSet('term-config',JSON.stringify(d,null,2));loadIntegrations();initDynamicUI();
  }catch(e){cb.checked=!cb.checked;termSet('term-config',JSON.stringify({error:e.message}));}
}

async function deleteIntg(id){
  if(!confirm('Remover esta integracao?'))return;
  try{const r=await fetch('/api/integrations/'+id,{method:'DELETE'});
    const d=await r.json();termSet('term-config',JSON.stringify(d,null,2));loadIntegrations();
  }catch(e){termSet('term-config',JSON.stringify({error:e.message}));}
}

async function testIntg(id){
  termLoading('term-config','Testando conexao...');
  try{
    const r=await fetch('/api/integrations/'+id+'/test',{method:'POST'});
    const data=await r.json();
    const card=renderTestResult(data);
    document.getElementById('term-config').innerHTML=card;
    document.getElementById('term-config').style.color='';
    // Recarregar integrations para atualizar last_status no dashboard
    const intgs=await fetch('/api/integrations').then(r2=>r2.json());
    const intg=intgs.find(function(i){return i.id===id;});
    if(intg) _showCachedStatus(intg);
  }catch(e){termSet('term-config',JSON.stringify({error:e.message}));}
}

function openNewIntg(){
  _editingId=null;_wizardStep=1;_selClass=null;_selVendor=null;_selProduct=null;
  document.getElementById('slide-title').textContent='Nova Integracao';
  var fn=document.getElementById('f-name'); if(fn) fn.value='';
  var bh=document.getElementById('btn-help-modal'); if(bh) bh.style.display='none';
  document.getElementById('btn-back').style.display='none';
  document.getElementById('btn-test').style.display='none';
  document.getElementById('btn-next').textContent='Proximo';
  document.querySelectorAll('.wizard-step').forEach(s=>s.classList.remove('active'));
  document.getElementById('step-1').classList.add('active');
  renderClassCards();
  document.getElementById('slide-overlay').classList.add('visible');
  document.getElementById('slide-panel').classList.add('open');
}

function editIntg(id){
  _editingId=id;
  fetch('/api/integrations').then(r=>r.json()).then(list=>{
    const intg=list.find(i=>i.id===id);if(!intg)return;
    _selClass=intg.class;_selVendor=intg.vendor;_selProduct=intg.product;_wizardStep=3;
    document.getElementById('slide-title').textContent='Editar: '+intg.name;
    document.getElementById('btn-back').style.display='block';
    document.getElementById('btn-test').style.display='block';
    document.getElementById('btn-next').textContent='Salvar';
    var bhm2=document.getElementById('btn-help-modal'); if(bhm2) bhm2.style.display='block';
    document.querySelectorAll('.wizard-step').forEach(s=>s.classList.remove('active'));
    document.getElementById('step-3').classList.add('active');
    renderFormStep(intg);
  });
  document.getElementById('slide-overlay').classList.add('visible');
  document.getElementById('slide-panel').classList.add('open');
}

function closePanel(){
  document.getElementById('slide-overlay').classList.remove('visible');
  document.getElementById('slide-panel').classList.remove('open');
}

function renderClassCards(){
  const el=document.getElementById('class-cards');
  el.innerHTML=Object.entries(_catalog).map(([cls,info])=>{
    const badge=_clsBadge[cls]||'';
    return '<div style="padding:14px;border:1px solid #1a2744;border-radius:6px;cursor:pointer;background:#0d1321;transition:.15s" id="cls-card-'+cls+'"'
      +' onclick="pickClass(\''+cls+'\')">'
      +'<span class="badge-cls '+badge+'">'+((_clsLabel[cls])||cls)+'</span>'
      +'<span style="margin-left:10px;font-size:.8rem">'+(info.label||'')+'</span></div>';
  }).join('');
}

function pickClass(cls){
  _selClass=cls;_selVendor=null;_selProduct=null;
  document.querySelectorAll('[id^="cls-card-"]').forEach(el=>{el.style.borderColor='#1a2744';el.style.background='#0d1321';});
  var card=document.getElementById('cls-card-'+cls);
  if(card){card.style.borderColor='#00d4ff';card.style.background='rgba(0,212,255,.06)';}
}
function selectClass(cls){
  _selClass=cls;_selVendor=null;_selProduct=null;_wizardStep=2;
  const info=_catalog[cls]||{};const cards=[];
  for(const [vendor,prods] of Object.entries(info.products||{})){
    for(const [prod,pinfo] of Object.entries(prods)){
      cards.push('<div style="padding:14px;border:1px solid #1a2744;border-radius:6px;cursor:pointer;background:#0d1321;transition:.15s" id="prod-card-'+vendor.replace(/ /g,'-')+'-'+prod.replace(/ /g,'-')+'"'
        +' onclick="pickProduct(\''+vendor+'\',\''+prod+'\')">'
        +'<div style="font-weight:700;font-size:.85rem">'+vendor+' — '+prod+'</div>'
        +'<div style="font-size:.73rem;color:#5a6a85;margin-top:4px">'+(pinfo.description||'')+'</div>'
        +'<div style="margin-top:6px;font-size:.7rem;color:#00d4ff">'+(pinfo.methods||[]).join(', ')+'</div>'
        +'</div>');
    }
  }
  document.getElementById('product-cards').innerHTML=cards.join('');
  document.querySelectorAll('.wizard-step').forEach(s=>s.classList.remove('active'));
  document.getElementById('step-2').classList.add('active');
  document.getElementById('btn-back').style.display='block';
}

function pickProduct(vendor,prod){
  _selVendor=vendor;_selProduct=prod;
  document.querySelectorAll('[id^="prod-card-"]').forEach(el=>{el.style.borderColor='#1a2744';el.style.background='#0d1321';});
  var id='prod-card-'+vendor.replace(/ /g,'-')+'-'+prod.replace(/ /g,'-');
  var card=document.getElementById(id);
  if(card){card.style.borderColor='#00d4ff';card.style.background='rgba(0,212,255,.06)';}
}
function selectProduct(vendor,prod){
  _selVendor=vendor;_selProduct=prod;_wizardStep=3;
  document.querySelectorAll('.wizard-step').forEach(s=>s.classList.remove('active'));
  document.getElementById('step-3').classList.add('active');
  document.getElementById('btn-test').style.display='block';
  document.getElementById('btn-next').textContent=_editingId?'Salvar':'Criar';
  var bhm=document.getElementById('btn-help-modal'); if(bhm) bhm.style.display='block';
  renderFormStep(null);
}

function renderFormStep(existing){
  const pinfo=(_catalog[_selClass]&&_catalog[_selClass].products&&_catalog[_selClass].products[_selVendor]&&_catalog[_selClass].products[_selVendor][_selProduct])||{};
  const fields=pinfo.form_fields||[],caps=pinfo.capabilities||{};
  const existingCaps=(existing&&existing.capabilities)||{};
  const existingProxy=(existing&&existing.proxy)||{};
  if(existing)document.getElementById('f-name').value=existing.name||'';
  const curTransport=(existing&&(existing.transport||existing.integration_method))||((fields.find(function(f){return f.name==='transport';})||{}).default)||'api';
  function fieldVisible(f,tval){if(!f.show_when_transport)return true;return f.show_when_transport.indexOf(tval)>=0;}
  function renderFields(tval){
    return fields.map(function(f){
      var val=existing?(existing[f.name]||''):(f.default||'');
      var hidden=!fieldVisible(f,tval)?'style="display:none"':'';
      var req=f.required?'<span style="color:#ff2d55">*</span>':'';
      var isFallback=(f.tooltip&&f.tooltip.indexOf('fallback')>=0)?' <span style="color:#ffd60a;font-size:.67rem">[fallback]</span>':'';
      var optLabel=(f.required===false&&!f.show_when_transport)?' <span style="color:#5a6a85;font-size:.67rem">(opcional)</span>':'';
      var tip=f.tooltip?' <span title="'+f.tooltip+'" style="color:#5a6a85;font-size:.65rem">&#9432;</span>':'';
      var onch=f.onchange?'onchange="onTransportChange(this.value)"':'';
      if(f.type==='select')return '<div id="ffd-'+f.name+'" '+hidden+'><label class="form-label">'+f.label+req+optLabel+tip+'</label>'
        +'<select class="form-select" id="ff-'+f.name+'" '+onch+'>'+(f.options||[]).map(function(o){return '<option value="'+o+'"'+(val===o?' selected':'')+'>'+o+'</option>';}).join('')+'</select></div>';
      return '<div id="ffd-'+f.name+'" '+hidden+'><label class="form-label">'+f.label+req+optLabel+isFallback+tip+'</label>'
        +'<input class="form-input" id="ff-'+f.name+'" type="'+(f.type==='password'?'password':'text')+'" value="'+(f.type==='password'?'':val)+'" placeholder="'+(f.placeholder||f.tooltip||'')+'"></div>';
    }).join('');
  }
  document.getElementById('form-fields-container').innerHTML=renderFields(curTransport);
  document.getElementById('form-fields-container').innerHTML+=
    '<div style="margin-top:16px;border-top:1px solid #1a2744;padding-top:12px">'+
    '<label class="cap-item" style="font-size:.77rem;color:#aaa;font-weight:700;text-transform:uppercase;letter-spacing:.06em">'+
    '<input type="checkbox" id="proxy-enabled" '+(existingProxy.enabled?'checked':'')+' onchange="toggleProxy(this.checked)"> Usar Proxy / Gateway (Bastion)</label>'+
    '<div id="proxy-fields" style="'+(existingProxy.enabled?'':'display:none')+';margin-top:8px;padding:10px;background:#0d1321;border-radius:4px;border:1px solid #1a2744">'+
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px">'+
    '<div><label class="form-label">IP/Hostname</label><input class="form-input" id="proxy-host" value="'+(existingProxy.host||'')+'" placeholder="204.216.179.29"></div>'+
    '<div><label class="form-label">Porta</label><input class="form-input" id="proxy-port" type="text" value="'+(existingProxy.port||'22')+'" placeholder="22"></div>'+
    '<div><label class="form-label">Usuario</label><input class="form-input" id="proxy-user" value="'+(existingProxy.user||'')+'" placeholder="opc"></div>'+
    '<div><label class="form-label">Senha</label><input class="form-input" id="proxy-pass" type="password" value="" placeholder=""></div>'+
    '</div></div></div>';
  document.getElementById('cap-grid').innerHTML=Object.entries(caps).map(function(e){var k=e[0],label=e[1];
    return '<label class="cap-item"><input type="checkbox" id="cap-'+k+'" '+(existingCaps[k]!==false?'checked':'')+'>'+' '+label+'</label>';
  }).join('');
}
function onTransportChange(val){
  var pinfo=(_catalog[_selClass]&&_catalog[_selClass].products&&_catalog[_selClass].products[_selVendor]&&_catalog[_selClass].products[_selVendor][_selProduct])||{};
  (pinfo.form_fields||[]).forEach(function(f){
    var el=document.getElementById('ffd-'+f.name);
    if(!el)return;
    if(!f.show_when_transport){el.style.display='';return;}
    el.style.display=f.show_when_transport.indexOf(val)>=0?'':'none';
  });
}
function toggleProxy(on){
  document.getElementById('proxy-fields').style.display=on?'':'none';
}

function wizardBack(){
  if(_wizardStep===3){_wizardStep=2;document.querySelectorAll('.wizard-step').forEach(s=>s.classList.remove('active'));document.getElementById('step-2').classList.add('active');document.getElementById('btn-test').style.display='none';document.getElementById('btn-next').textContent='Proximo';var bh=document.getElementById('btn-help-modal');if(bh)bh.style.display='none';}
  else if(_wizardStep===2){_wizardStep=1;document.querySelectorAll('.wizard-step').forEach(s=>s.classList.remove('active'));document.getElementById('step-1').classList.add('active');document.getElementById('btn-back').style.display='none';}
}

async function wizardNext(){
  if(_wizardStep===1){
    if(!_selClass){alert('Selecione uma classe de integracao');return;}
    selectClass(_selClass);return;
  }
  if(_wizardStep===2){
    if(!_selVendor||!_selProduct){alert('Selecione um vendor e produto');return;}
    selectProduct(_selVendor,_selProduct);
    return;
  }
  if(_wizardStep<3)return;
  const name=document.getElementById('f-name').value.trim();
  if(!name){alert('Informe o nome da integracao');return;}
  const pinfo=(_catalog[_selClass]&&_catalog[_selClass].products&&_catalog[_selClass].products[_selVendor]&&_catalog[_selClass].products[_selVendor][_selProduct])||{};
  const caps=pinfo.capabilities||{};const capVals={};
  for(const k of Object.keys(caps)) capVals[k]=document.getElementById('cap-'+k)?document.getElementById('cap-'+k).checked:false;
  const mel=document.getElementById('ff-transport');
  const proxyEl=document.getElementById('proxy-enabled');
  const proxyEnabled=proxyEl&&proxyEl.checked;
  const proxy=proxyEnabled?{enabled:true,
    host:(document.getElementById('proxy-host')||{}).value||'',
    port:(document.getElementById('proxy-port')||{}).value||'22',
    user:(document.getElementById('proxy-user')||{}).value||'',
    password:(document.getElementById('proxy-pass')||{}).value||''
  }:{enabled:false};
  const body={name:name,'class':_selClass,vendor:_selVendor,product:_selProduct,
    integration_method:mel?mel.value:(pinfo.methods||['api'])[0],enabled:true,capabilities:capVals,proxy:proxy};
  termLoading('term-config',(_editingId?'Atualizando':'Criando')+' integracao...');
  try{
    const url=_editingId?'/api/integrations/'+_editingId:'/api/integrations';
    const r=await fetch(url,{method:_editingId?'PUT':'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    const d=await r.json();termSet('term-config',JSON.stringify(d,null,2));
    if(d.ok||d.integration){closePanel();loadIntegrations();initDynamicUI();}else alert(d.error||'Erro ao salvar');
  }catch(e){termSet('term-config',JSON.stringify({error:e.message}));}
}

async function testCurrentForm(){
  if(!_editingId){
    // Can test with current form values even before saving
    alert('Salve primeiro para testar a conexao.');
    return;
  }
  testIntg(_editingId);
}


// == HELP / PLAYBOOKS ==
let _pbCatalog = {};
async function _loadPbCatalog(){
  if(Object.keys(_pbCatalog).length>0) return _pbCatalog;
  try{ const r=await fetch('/api/integrations/catalog/playbooks'); _pbCatalog=await r.json(); }catch(e){}
  return _pbCatalog;
}
async function showHelp(intgId){
  const list=await fetch('/api/integrations').then(r=>r.json());
  const intg=list.find(i=>i.id===intgId);
  if(!intg) return;
  await _loadPbCatalog();
  const pbs=(_pbCatalog[intg.class]&&_pbCatalog[intg.class][intg.vendor]&&_pbCatalog[intg.class][intg.vendor][intg.product])||[];
  document.getElementById('help-title').textContent=intg.name+' ? Playbooks';
  renderHelpBody(pbs, intg.product);
  document.getElementById('help-overlay').style.display='block';
  document.getElementById('help-panel').classList.add('open');
}
async function showCatalogHelp(){
  if(!_selClass||!_selVendor||!_selProduct) return;
  await _loadPbCatalog();
  const pbs=(_pbCatalog[_selClass]&&_pbCatalog[_selClass][_selVendor]&&_pbCatalog[_selClass][_selVendor][_selProduct])||[];
  document.getElementById('help-title').textContent=_selProduct+' ? Playbooks';
  renderHelpBody(pbs, _selProduct);
  document.getElementById('help-overlay').style.display='block';
  document.getElementById('help-panel').classList.add('open');
}
function renderHelpBody(playbooks, product){
  const el=document.getElementById('help-body');
  if(!playbooks||!playbooks.length){
    el.innerHTML='<div style="color:#5a6a85;padding:20px">Nenhum playbook documentado para '+product+'.</div>';
    return;
  }
  el.innerHTML='<div style="font-size:.72rem;color:#5a6a85;margin-bottom:12px">Cada playbook abaixo mostra os campos de entrada necessarios, seu formato e de quais campos de um log/alerta de seguranca o valor pode ser extraido.</div>'
    +playbooks.map(function(pb){
      const inputRows=pb.inputs&&pb.inputs.length?pb.inputs.map(function(inp){
        var req=inp.required?'<span class="pb-req">*obr</span>':'<span class="pb-opt">opc</span>';
        var src=inp.source?'<div class="pb-input-src">&#128279; Origem no log: '+inp.source+'</div>':'';
        return '<div class="pb-input-row">'
          +'<div><div class="pb-input-name">'+inp.name+' '+req+'</div>'
          +'<div class="pb-input-fmt">formato: '+inp.format+'</div>'
          +'<div class="pb-input-fmt" style="color:#ffd60a">ex: '+inp.example+'</div>'+src+'</div>'
          +'</div>';
      }).join(''):'<div style="color:#5a6a85;font-size:.72rem;padding:6px">Sem parametros de entrada.</div>';
      return '<div class="pb-card">'
        +'<div class="pb-head"><span style="color:#ffd60a;font-size:.68rem;font-family:monospace">'+pb.id+'</span>'
        +'<span class="pb-name" style="margin-left:8px">'+pb.name+'</span></div>'
        +(pb.description?'<div class="pb-desc">'+pb.description+'</div>':'')
        +'<div class="pb-inputs"><div style="font-size:.7rem;color:#5a6a85;font-weight:700;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Inputs</div>'
        +inputRows+'</div></div>';
    }).join('');
}
function closeHelp(){
  document.getElementById('help-overlay').style.display='none';
  document.getElementById('help-panel').classList.remove('open');
}
// == TEST RESULT DISPLAY ==
function renderTestResult(data){
  if(!data) return '<div class="err">Sem resposta do servidor</div>';
  const ok=data.ok||data.connection==='ok';
  const clr=ok?'#00ff88':'#ff2d55';
  const badge='<span style="color:'+clr+';font-weight:700;font-size:.85rem">'+(ok?'&#9679; CONECTADO':'&#9679; FALHA')+'</span>';
  function row(lbl,val,cls){if(!val&&val!==0)return '';return '<div class="tr-row"><span class="tr-label">'+lbl+'</span><span class="tr-val '+(cls||'')+'">'+val+'</span></div>';}
  const permR=data.permissions&&data.permissions.read;
  const permW=data.permissions&&data.permissions.write;
  return '<div class="test-result-card">'+
    '<div style="margin-bottom:10px">'+badge+'</div>'+
    (data.integration?row('Integração',data.integration):'') +
    (data.url?row('URL / IP',data.url):'') +
    (data.hostname?row('Hostname',data.hostname):'') +
    (data.version?row('Versão',data.version):'') +
    (data.serial?row('Serial',data.serial):'') +
    (data.platform?row('Plataforma',data.platform):'') +
    (data.domain?row('Domínio',data.domain):'') +
    (data.agents_found!==undefined?row('Agentes encontrados',data.agents_found):'') +
    (data.zones?row('Zonas DNS',data.zones):'') +
    (data.method?row('Método',data.method):'') +
    (permR?row('Permissão leitura',permR,permR==='ok'?'tr-ok':'tr-err'):'') +
    (permW?row('Permissão escrita',permW,permW==='ok'?'tr-ok':permW==='not_tested'?'tr-warn':'tr-err'):'') +
    (data.error?'<div style="color:#ff2d55;margin-top:8px;font-size:.73rem;word-break:break-all">'+data.error+'</div>':'')+
    '</div>';
}

// == DYNAMIC UI: tabs, dashboard, playbooks ==
const _TAB_CLASS_MAP = {fw:'firewall',edr:'edr',ad:'identity',dns:'dns'};
const _CLASS_COLORS = {firewall:'var(--orange)',edr:'var(--purple)',identity:'var(--cyan)',dns:'var(--green)'};
const _CLASS_TAB_LABELS = {firewall:'Firewall',edr:'EDR / XDR',identity:'Active Directory',dns:'DNS'};

async function initDynamicUI(){
  try { if(typeof fetch==='undefined') return; 
    const intgs = await fetch('/api/integrations').then(r=>r.json());
    const enabled = intgs.filter(function(i){return i.enabled!==false;});
    const enabledClasses = new Set(enabled.map(function(i){return i['class'];}));

    // 1. Show/hide nav tabs
    Object.entries(_TAB_CLASS_MAP).forEach(function(e){
      var el=document.getElementById('nav-'+e[0]);
      if(el) el.style.display=enabledClasses.has(e[1])?'':'none';
    });
    var nbp=document.getElementById('nav-playbooks');
    if(nbp) nbp.style.display=enabled.length>0?'':'none';

    // 2. Dashboard stat cards
    var statsEl=document.getElementById('dash-stats');
    if(statsEl){
      if(!enabled.length){
        statsEl.innerHTML='<div style="color:var(--dim);padding:16px;font-size:.8rem">Nenhuma integracao ativa. Configure em <strong>Settings</strong>.</div>';
      } else {
        var statColors={firewall:'g',edr:'c',identity:'g',dns:'c'};
        statsEl.innerHTML=enabled.map(function(i){
          var col=statColors[i['class']]||'g';
          return '<div class="stat '+col+'" id="sc-'+i.id+'" onclick="goTab(\''+_getTabForClass(i['class'])+'\')" style="cursor:pointer">'
            +'<div class="lbl">'+i.product+'</div>'
            +'<div class="val" id="sv-'+i.id+'">...</div>'
            +'<div class="sub">'+(_CLASS_TAB_LABELS[i['class']]||i['class'])+'</div>'
            +'</div>';
        }).join('');
        enabled.forEach(function(i){ _showCachedStatus(i); });
      }
    }

    // 3. Quick action cards
    var qaEl=document.getElementById('dash-quick-actions');
    if(qaEl){
      var qaDescs={
        firewall:'Bloquear IP, dominio, URL · Isolar host',
        edr:'Blacklist hash · Isolar agente · Scan remoto',
        identity:'Desabilitar conta · Reset senha · Desbloquear',
        dns:'Sinkhole dominio · Flush cache'
      };
      var qaBorders={firewall:'rgba(255,107,53,.3)',edr:'rgba(191,90,242,.3)',identity:'rgba(0,212,255,.3)',dns:'rgba(0,255,136,.3)'};
      if(!enabled.length){
        qaEl.innerHTML='<div style="color:var(--dim);font-size:.78rem;padding:10px">Configure integracoes em Settings para ver acoes rapidas.</div>';
      } else {
        var seen=new Set();
        qaEl.innerHTML=enabled.filter(function(i){if(seen.has(i['class']))return false;seen.add(i['class']);return true;}).map(function(i){
          var tab=_getTabForClass(i['class']);
          var color=_CLASS_COLORS[i['class']]||'var(--cyan)';
          return '<div class="card" style="cursor:pointer;border-color:'+( qaBorders[i['class']]||'var(--border)')+'" onclick="goTab(\''+tab+'\')">'
            +'<div style="font-weight:700;color:'+color+';margin-bottom:4px">'+(_CLASS_TAB_LABELS[i['class']]||i['class'])+'</div>'
            +'<div style="font-size:.75rem;color:var(--dim)">'+(qaDescs[i.class]||'')+'</div>'
            +'</div>';
        }).join('');
      }
    }

    // 4. Playbooks panel
    _renderPlaybooksPanel(enabled);

  } catch(e){ console.error('initDynamicUI:', e); }
}

function _getTabForClass(cls){
  var map={firewall:'fw',edr:'edr',identity:'ad',dns:'dns'};
  return map[cls]||'dashboard';
}

function _showCachedStatus(intg){
  var el=document.getElementById('sv-'+intg.id);
  var sc=document.getElementById('sc-'+intg.id);
  var last=intg.last_status;
  if(!last){
    if(el){el.textContent='Nunca testado';el.style.color='var(--dim)';}
    return;
  }
  var ok=last.ok;
  var details=last.details||{};
  if(el){
    if(ok){
      var ver=details.version?details.version.split(',')[0].split(' ').slice(-1)[0]||'OK':(details.agents_found!==undefined?details.agents_found+' agentes':'OK');
      el.textContent=ver; el.style.color='var(--green)';
    } else {
      el.textContent='OFFLINE'; el.style.color='var(--red)';
    }
  }
  if(sc) sc.style.borderColor=ok?'rgba(0,255,136,.3)':'rgba(255,45,85,.3)';
  // Mostrar idade do ultimo teste no titulo do card
  if(last.timestamp){
    try{
      var ts=new Date(last.timestamp);
      var age=Math.round((Date.now()-ts.getTime())/60000);
      var ageStr=age<1?'agora':age<60?age+'min atr?s':Math.round(age/60)+'h atr?s';
      if(sc){ sc.title='Ultimo teste: '+ts.toLocaleString('pt-BR')+'\n'+ageStr; }
    }catch(e){}
  }
}
async function _loadIntgStatus(intg){
  // Manter compatibilidade - agora usa cache
  _showCachedStatus(intg);
}

async function _renderPlaybooksPanel(enabled){
  var el=document.getElementById('playbooks-area');
  if(!el) return;
  if(!enabled||!enabled.length){
    el.innerHTML='<div style="color:var(--dim);padding:20px;text-align:center">Nenhuma integracao ativa. Ative integracoes em Settings.</div>';
    return;
  }
  await _loadPbCatalog();
  var html='';
  var seen=new Set();
  enabled.forEach(function(i){
    var key=i['class']+'|'+i.vendor+'|'+i.product;
    if(seen.has(key)) return; seen.add(key);
    var pbs=(_pbCatalog[i['class']]&&_pbCatalog[i.class][i.vendor]&&_pbCatalog[i.class][i.vendor][i.product])||[];
    var caps=i.capabilities||{};
    var allowed=pbs.filter(function(pb){return caps[pb.id]!==false;});
    if(!allowed.length) return;
    var color=_CLASS_COLORS[i['class']]||'var(--cyan)';
    html+='<div style="margin-bottom:20px">'
      +'<div style="display:flex;align-items:center;gap:8px;margin-bottom:10px">'
      +'<span class="badge-cls badge-'+i['class']+'">'+(_CLASS_TAB_LABELS[i['class']]||i['class'])+'</span>'
      +'<span style="font-weight:700;color:'+color+';font-size:.85rem">'+i.product+'</span>'
      +'<span style="color:var(--dim);font-size:.72rem;margin-left:4px">'+i.name+'</span></div>'
      +allowed.map(function(pb){
        var reqInputs=pb.inputs&&pb.inputs.length?pb.inputs.filter(function(inp){return inp.required;}).map(function(inp){return inp.name;}).join(', '):'';
        return '<div class="pb-card" style="margin-bottom:8px">'
          +'<div class="pb-head" style="display:flex;align-items:center;justify-content:space-between">'
          +'<div style="display:flex;align-items:center;gap:8px">'
          +'<span style="color:var(--dim);font-size:.68rem;font-family:monospace">'+pb.id+'</span>'
          +'<span class="pb-name">'+pb.name+'</span></div>'
          +'<button class="btn" style="font-size:.7rem;padding:3px 10px;background:rgba(0,212,255,.08);border-color:rgba(0,212,255,.25);color:var(--cyan)" '
          +'onclick="goTab(\''+_getTabForClass(i['class'])+'\')" title="Ir para aba de execucao">Executar</button>'
          +'</div>'
          +(pb.description?'<div class="pb-desc">'+pb.description+'</div>':'')
          +(reqInputs?'<div style="padding:5px 14px;font-size:.7rem;color:var(--dim)">Inputs: <span style="color:var(--yellow)">'+reqInputs+'</span></div>':'')
          +'</div>';
      }).join('')+'</div>';
  });
  el.innerHTML=html||'<div style="color:var(--dim);padding:20px">Nenhum playbook habilitado.</div>';
}

// == UPDATES ==
function loadConfig(){loadIntegrations();}
function saveConfig(){}
async function statusIntg(cls, termId){
  termLoading(termId, 'Verificando...');
  try{
    var map={firewall:'/api/fw/status',edr:'/api/edr/status',identity:'/api/ad/list-disabled',dns:'/api/dns/status'};
    var url=map[cls]; if(!url){termSet(termId,'Classe nao suportada');return;}
    var r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:''});
    var raw=await r.json();
    var ok=!raw.error&&(raw.hostname||raw.ok||raw.status==='connected'||raw.count!==undefined);
    var data={ok:ok,connection:ok?'ok':'error'};
    if(cls==='firewall'){data.integration='FortiGate';data.hostname=raw.hostname;data.version=raw.version;data.serial=raw.serial;data.url=raw.host;data.method=raw.transport||'ssh';}
    else if(cls==='edr'){data.integration='SentinelOne';data.platform='SentinelOne';data.agents_found=raw.agents_found;data.method='api';}
    else if(cls==='identity'){data.integration='Active Directory';data.domain='safelabs.lab';data.method='ldap';data.agents_found=(raw.count||0)+' contas desativadas';}
    else if(cls==='dns'){data.integration='DNS Server';data.domain=raw.domain;data.method=raw.transport||'winrm';}
    if(ok) data.permissions={read:'ok',write:'not_tested'};
    else data.error=raw.error||'Falha na conexao';
    var el=document.getElementById(termId);
    if(el){el.innerHTML=renderTestResult(data);el.style.color='';}
  }catch(e){termSet(termId,JSON.stringify({error:e.message}));}
}
function testConnection(module){
  const map={firewall:'/api/fw/status',edr:'/api/edr/status',ad:'/api/ad/list-disabled',dns:'/api/dns/status'};
  fetch(map[module]||'/api/status',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:''}).then(r=>r.text()).then(t=>termSet('term-config',t)).catch(e=>termSet('term-config',JSON.stringify({error:e.message})));
}

loadIntegrations();
</script>
</body>
</html>"""

def _run_integration_test(intg):
    try:
        cls = intg.get("class","")
        intg_id = intg.get("id","")
        test_map = {"firewall":"fw.fw_status","edr":"edr.edr_status","identity":"ad.ad_list_disabled_users","dns":"ad.dns_status"}
        fn = test_map.get(cls,"fw.fw_status")
        raw = json.loads(_call(fn))
        ok = bool(raw.get("ok") or raw.get("status")=="connected" or raw.get("hostname") or raw.get("count") is not None)
        details = {}
        if cls == "firewall":
            details = {"url":f"{_ENV.get('FORTIGATE_WEB_IP','?')}:{_ENV.get('FORTIGATE_WEB_PORT','80')}","version":raw.get("version",""),"hostname":raw.get("hostname","")}
        elif cls == "edr":
            details = {"url":raw.get("base_url",""),"agents_found":raw.get("agents_found",0)}
        elif cls == "identity":
            details = {"url":f"ldap://{_ENV.get('VM_DC01_IP','?')}","domain":_ENV.get("DOMAIN_NAME","?")}
        elif cls == "dns":
            details = {"url":f"dns://{raw.get('dc_ip','?')}","zones":raw.get("output","")}
        if not ok:
            details["error"] = raw.get("error","Connection failed")
        with _intg_lock:
            if _INTEGRATIONS_PATH.is_file():
                try:
                    _all = json.loads(_INTEGRATIONS_PATH.read_text(encoding="utf-8"))
                except Exception:
                    _all = [dict(i) for i in _DEFAULT_INTEGRATIONS]
            else:
                _all = [dict(i) for i in _DEFAULT_INTEGRATIONS]
            for _i, _it in enumerate(_all):
                if _it.get("id") == intg_id:
                    _all[_i]["last_status"] = {"ok":ok,"connection":"ok" if ok else "error",
                        "timestamp":datetime.now(timezone.utc).isoformat(),"details":details}
                    break
            _INTEGRATIONS_PATH.write_text(json.dumps(_all, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass

def _bg_status_checker():
    time.sleep(3600)  # aguardar 1h antes do primeiro teste automatico
    while True:
        try:
            integrations = _load_integrations()
            for intg in integrations:
                if not intg.get("enabled", True):
                    continue
                interval = int(intg.get("test_interval", 21600))
                if interval <= 0:
                    continue
                last = intg.get("last_status", {})
                last_ts = last.get("timestamp")
                if last_ts:
                    try:
                        last_time = datetime.fromisoformat(last_ts)
                        age = (datetime.now(timezone.utc) - last_time).total_seconds()
                        if age < interval:
                            continue
                    except Exception:
                        pass
                _run_integration_test(intg)
        except Exception:
            pass
        time.sleep(60)

threading.Thread(target=_bg_status_checker, daemon=True).start()

# --- Background containment cache refresher ---
_containment_cache_ts: str = ""
_containment_all_cache: dict = {}
_containment_lock = threading.Lock()

def _refresh_containment_cache():
    global _containment_cache_ts, _containment_all_cache
    try:
        _cache.pop("containment_status", None)
        status = _get_containment_status()
        campaigns = _load_apt_campaigns()
        results = {}
        for camp in campaigns:
            cid = camp.get("id", "")
            if not cid:
                continue
            r = _apt_containment_check(cid)
            results[cid] = r
        with _containment_lock:
            _containment_all_cache = results
            _containment_cache_ts = datetime.now(timezone.utc).isoformat()
    except Exception:
        pass

def _bg_containment_checker():
    time.sleep(30)
    _refresh_containment_cache()
    while True:
        time.sleep(3600)
        _refresh_containment_cache()

threading.Thread(target=_bg_containment_checker, daemon=True).start()

# ─── HTTP Handler ─────────────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, body, ct="text/html", code=200):
        if isinstance(body, dict):
            body = json.dumps(body, ensure_ascii=False)
            ct = "application/json"
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ct + "; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _post(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", errors="ignore") if length > 0 else ""
        ct = self.headers.get("Content-Type", "")
        if "application/json" in ct:
            try:
                return json.loads(raw)
            except Exception:
                pass
        data = {}
        for pair in raw.split("&"):
            if "=" in pair:
                k, _, v = pair.partition("=")
                data[urllib.parse.unquote_plus(k)] = urllib.parse.unquote_plus(v)
        return data

    def _s(self, key, default=""):
        return _san(self._data.get(key, default))

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self._send(PAGE); return
        if path == "/api/status":
            self._send({"fw": bool(_fw), "edr": bool(_edr), "ad": bool(_ad)}); return
        if path == "/api/status/full":
            result = {}
            try:
                s = json.loads(_call("fw.fw_status"))
                result["fw"] = {"ok": not s.get("error"), "value": s.get("hostname", "ONLINE")}
            except: result["fw"] = {"ok": False}
            try:
                s = json.loads(_call("edr.edr_status"))
                result["edr"] = {"ok": s.get("ok", s.get("status") == "connected"), "value": f"{s.get('agents_found',0)} agentes"}
            except: result["edr"] = {"ok": False}
            try:
                s = json.loads(_call("ad.dns_status"))
                result["ad"] = {"ok": s.get("ok", False), "value": "safelabs.lab"}
            except: result["ad"] = {"ok": False}
            try:
                s = json.loads(_call("ad.dns_list_blocked"))
                result["dns"] = {"ok": True, "value": f"{s.get('count', 0)} bloqueados"}
            except: result["dns"] = {"ok": False}
            self._send(result); return
        if path == "/api/edr/agents":
            self._send(_call("edr.edr_list_agents"), ct="application/json"); return
        if path == "/api/config":
            self._send(_get_config_masked()); return
        if path.startswith("/api/apt/campaigns"):
            qs = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(qs)
            days = min(max(int(params.get("days", ["90"])[0]), 1), 365)
            self._send(json.dumps(_get_apt_campaigns(days), ensure_ascii=False), ct="application/json"); return
        if path == "/api/containment/status":
            self._send(json.dumps(_get_containment_status(), ensure_ascii=False), ct="application/json"); return
        if path == "/api/apt/campaigns":
            self._send(json.dumps(_load_apt_campaigns(), ensure_ascii=False), ct="application/json"); return
        if path == "/api/apt/containment/all":
            with _containment_lock:
                result = {"campaigns": _containment_all_cache, "last_refresh": _containment_cache_ts, "cached": True}
            self._send(json.dumps(result, ensure_ascii=False), ct="application/json"); return
        if path == "/api/apt/containment/refresh":
            threading.Thread(target=_refresh_containment_cache, daemon=True).start()
            self._send(json.dumps({"ok": True, "message": "Refresh iniciado em background"}), ct="application/json"); return
        if path.startswith("/api/apt/containment/"):
            _cid = path.split("/")[4]
            self._send(json.dumps(_apt_containment_check(_cid), ensure_ascii=False), ct="application/json"); return
        if path == "/api/edr/blacklist":
            self._send(_call("edr.edr_get_blacklist_hashes"), ct="application/json"); return
        if path == "/api/ad/users":
            include_dis = "all" in self.path
            self._send(_call("ad.ad_list_all_users", include_dis), ct="application/json"); return
        if path == "/api/integrations":
            self._send(json.dumps(_load_integrations(), ensure_ascii=False), ct="application/json"); return
        if path == "/api/integrations/catalog":
            self._send(json.dumps(_INTEGRATION_CATALOG, ensure_ascii=False), ct="application/json"); return
        if path.startswith("/api/integrations/") and path.endswith("/status"):
            _sid = path.split("/")[3]
            _dl = _load_integrations()
            _si = next((i for i in _dl if i.get("id")==_sid), None)
            if not _si:
                self._send({"error":"not found"}, code=404); return
            ls = _si.get("last_status")
            if not ls:
                self._send({"ok":False,"connection":"never_tested","timestamp":None}); return
            self._send(ls, ct="application/json"); return
        if path == "/api/integrations/catalog/playbooks":
            self._send(json.dumps(_PLAYBOOKS_CATALOG, ensure_ascii=False), ct="application/json"); return
        self._send("Not found", code=404)

    def do_POST(self):
        path = self.path.split("?")[0]
        self._data = self._post()

        try:
            # FW
            if path == "/api/fw/status":
                self._send(_call("fw.fw_status"), ct="application/json")
            elif path == "/api/fw/block-ip":
                g = _guard("firewall", "block_ip")
                if g: self._send(g, code=g.get("code",403)); return
                ip = self._s("ip"); cmt = self._s("comment", "SafeLabs SOC")
                ttl = int(self._s("ttl_minutes", "0") or "0")
                if not ip: self._send({"error": "IP required"}); return
                self._send(_call("fw.fw_block_ip", ip, cmt, ttl), ct="application/json")
            elif path == "/api/fw/unblock-ip":
                self._send(_call("fw.fw_unblock_ip", self._s("ip")), ct="application/json")
            elif path == "/api/fw/block-domain":
                g = _guard("firewall", "block_domain")
                if g: self._send(g, code=g.get("code",403)); return
                domain = self._s("domain") or self._s("value")
                ttl = int(self._s("ttl_minutes", "0") or "0")
                if not domain: self._send({"error": "domain required"}); return
                self._send(_call("fw.fw_block_domain", domain, ttl), ct="application/json")
            elif path == "/api/fw/unblock-domain":
                self._send(_call("fw.fw_unblock_domain", self._s("domain")), ct="application/json")
            elif path == "/api/fw/block-url":
                g = _guard("firewall", "block_url")
                if g: self._send(g, code=g.get("code",403)); return
                url_val = self._s("url") or self._s("value")
                ttl = int(self._s("ttl_minutes", "0") or "0")
                if not url_val: self._send({"error": "url required"}); return
                self._send(_call("fw.fw_block_url", url_val, ttl), ct="application/json")
            elif path == "/api/fw/unblock-url":
                self._send(_call("fw.fw_unblock_url", self._s("url")), ct="application/json")
            elif path == "/api/fw/isolate":
                g = _guard("firewall", "isolate_host")
                if g: self._send(g, code=g.get("code",403)); return
                ip = self._s("ip"); reason = self._s("reason", "SOC")
                ttl = int(self._s("ttl_minutes", "0") or "0")
                self._send(_call("fw.fw_isolate_host", ip, reason, ttl), ct="application/json")
            elif path == "/api/fw/deisolate":
                self._send(_call("fw.fw_deisolate_host", self._s("ip")), ct="application/json")
            elif path == "/api/fw/list":
                self._send(_call("fw.fw_list_iocs"), ct="application/json")
            elif path == "/api/fw/bulk-ip":
                self._send(_call("fw.fw_block_ip_list", self._s("list_name")), ct="application/json")
            elif path == "/api/fw/bulk-domain":
                self._send(_call("fw.fw_block_domain_list", self._s("list_name")), ct="application/json")
            # EDR
            elif path == "/api/edr/status":
                self._send(_call("edr.edr_status"), ct="application/json")
            elif path == "/api/edr/isolate":
                g = _guard("edr", "isolate_agent")
                if g: self._send(g, code=g.get("code",403)); return
                self._send(_call("edr.edr_isolate_agent", self._s("agent_id"), self._s("reason","SOC")), ct="application/json")
            elif path == "/api/edr/deisolate":
                self._send(_call("edr.edr_deisolate_agent", self._s("agent_id")), ct="application/json")
            elif path == "/api/edr/scan":
                self._send(_call("edr.edr_scan_agent", self._s("agent_id")), ct="application/json")
            elif path == "/api/edr/list-threats":
                self._send(_call("edr.edr_list_threats"), ct="application/json")
            elif path == "/api/edr/collect-iocs":
                self._send(_call("edr.edr_collect_iocs"), ct="application/json")
            elif path == "/api/edr/blacklist-hash":
                g = _guard("edr", "blacklist_hash")
                if g: self._send(g, code=g.get("code",403)); return
                h = self._s("hash_value") or self._s("sha1")
                if not h or not re.match(r'^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$', h):
                    self._send({"error": "Hash invalido (MD5=32, SHA1=40, SHA256=64 hex chars)"}); return
                self._send(_call("edr.edr_blacklist_hash", h, self._s("description","SOC")), ct="application/json")
            elif path == "/api/edr/blacklist-list":
                self._send(_call("edr.edr_blacklist_hash_list", self._s("list_name")), ct="application/json")
            elif path == "/api/edr/chain":
                self._send(_call("edr.edr_containment_chain", self._s("agent_id")), ct="application/json")
            # AD
            elif path == "/api/ad/status":
                self._send(_call("ad.ad_user_status", self._s("username")), ct="application/json")
            elif path == "/api/ad/disable":
                g = _guard("identity", "disable_user")
                if g: self._send(g, code=g.get("code",403)); return
                self._send(_call("ad.ad_disable_user", self._s("username"), self._s("reason","SOC")), ct="application/json")
            elif path == "/api/ad/enable":
                self._send(_call("ad.ad_enable_user", self._s("username")), ct="application/json")
            elif path == "/api/ad/reset-password":
                self._send(_call("ad.ad_force_password_reset", self._s("username")), ct="application/json")
            elif path == "/api/ad/unlock":
                self._send(_call("ad.ad_unlock_user", self._s("username")), ct="application/json")
            elif path == "/api/ad/list-disabled":
                self._send(_call("ad.ad_list_disabled_users"), ct="application/json")
            elif path == "/api/ad/list-all":
                inc = self._s("include_disabled", "false").lower() == "true"
                self._send(_call("ad.ad_list_all_users", inc), ct="application/json")
            elif path == "/api/ad/bulk":
                raw_users = self._data.get("users", "[]")
                action = self._s("action", "status")
                try:
                    users = json.loads(raw_users)
                    users = [_san(u) for u in users if u][:50]
                except: self._send({"error": "Formato invalido"}); return
                if action not in ("status","disable","enable","reset-password","unlock"):
                    self._send({"error": "Acao invalida"}); return
                self._send(_call("ad.ad_containment_from_leak", users, action), ct="application/json")
            elif path == "/api/ad/cert-check":
                self._send(_call("ad.ad_dns_check_certificate_store_modification"), ct="application/json")
            # APT Campaigns CRUD
            elif path == "/api/apt/campaigns":
                body = self._data if isinstance(self._data, dict) else {}
                required = ["name", "iocs"]
                missing = [f for f in required if not body.get(f)]
                if missing:
                    self._send({"error": f"Campos obrigatorios: {missing}"}); return
                new_camp = {
                    "id": str(uuid.uuid4())[:8],
                    "name": _san(body.get("name", ""), 100),
                    "adversary": _san(body.get("adversary", ""), 60),
                    "origin": _san(body.get("origin", ""), 60),
                    "mitre_id": _san(body.get("mitre_id", ""), 20),
                    "description": _san(body.get("description", ""), 500),
                    "tags": [_san(t, 40) for t in (body.get("tags") or [])[:10]],
                    "last_updated": datetime.now(timezone.utc).isoformat(),
                    "iocs": {
                        "ips": list(body.get("iocs", {}).get("ips", [])),
                        "domains": list(body.get("iocs", {}).get("domains", [])),
                        "hashes": list(body.get("iocs", {}).get("hashes", [])),
                        "urls": list(body.get("iocs", {}).get("urls", [])),
                    },
                }
                data = _load_apt_campaigns()
                data.append(new_camp)
                _save_apt_campaigns(data)
                self._send({"ok": True, "campaign": new_camp})
            elif path.startswith("/api/apt/campaigns/") and path.endswith("/check"):
                _cid2 = path.split("/")[4]
                self._send(json.dumps(_apt_containment_check(_cid2), ensure_ascii=False), ct="application/json")
            elif path.startswith("/api/apt/campaigns/") and path.endswith("/apply"):
                _cid3 = path.split("/")[4]
                _body = self._data if isinstance(self._data, dict) else {}
                _tools = _body.get("tools", ["fw", "dns", "edr"])
                _result = _apt_containment_check(_cid3)
                if "error" in _result:
                    self._send(_result); return
                _applied = []
                _skipped = 0
                if "fw" in _tools:
                    for _ip in _result["ips"]["gaps"][:50]:
                        try:
                            _r = _call("fw.fw_block_ip", _ip, "APT containment")
                            _parsed = json.loads(_r) if isinstance(_r, str) and _r.strip().startswith("{") else {"raw": str(_r)}
                            _ok = _parsed.get("ok", False) or "already" in str(_r).lower() or "success" in str(_r).lower()
                            _applied.append({"type": "ip", "value": _ip, "ok": _ok, "error": "" if _ok else _parsed.get("error", str(_r)[:80])})
                        except Exception as _e:
                            _applied.append({"type": "ip", "value": _ip, "ok": False, "error": str(_e)[:80]})
                    for _dom in _result["domains"]["gaps"][:50]:
                        try:
                            _r = _call("fw.fw_block_domain", _dom, 0)
                            _parsed = json.loads(_r) if isinstance(_r, str) and _r.strip().startswith("{") else {"raw": str(_r)}
                            _ok = _parsed.get("ok", False) or "already" in str(_r).lower() or "success" in str(_r).lower()
                            _applied.append({"type": "domain", "value": _dom, "ok": _ok, "target": "fw", "error": "" if _ok else _parsed.get("error", str(_r)[:80])})
                        except Exception as _e:
                            _applied.append({"type": "domain", "value": _dom, "ok": False, "target": "fw", "error": str(_e)[:80]})
                else:
                    _skipped += len(_result["ips"]["gaps"])
                if "dns" in _tools:
                    for _dom in _result["domains"]["gaps"][:50]:
                        try:
                            _r = _call("ad.dns_block_domain", _dom)
                            _parsed = json.loads(_r) if isinstance(_r, str) and _r.strip().startswith("{") else {"raw": str(_r)}
                            _ok = _parsed.get("ok", False) or "already" in str(_r).lower() or "success" in str(_r).lower()
                            _applied.append({"type": "domain", "value": _dom, "ok": _ok, "target": "dns", "error": "" if _ok else _parsed.get("error", str(_r)[:80])})
                        except Exception as _e:
                            _applied.append({"type": "domain", "value": _dom, "ok": False, "target": "dns", "error": str(_e)[:80]})
                else:
                    _skipped += len(_result["domains"]["gaps"])
                if "edr" in _tools:
                    for _h in _result["hashes"]["gaps"][:50]:
                        try:
                            _r = _call("edr.edr_blacklist_hash", _h, "APT containment")
                            _parsed = json.loads(_r) if isinstance(_r, str) and _r.strip().startswith("{") else {"raw": str(_r)}
                            _ok = _parsed.get("ok", False) or "already" in str(_r).lower() or "success" in str(_r).lower()
                            _err = ""
                            if not _ok:
                                _err = _parsed.get("error", str(_r)[:120])
                                if "400" in str(_err) and len(_h) == 64:
                                    _err = "SentinelOne aceita apenas SHA1 (40 chars). Hash SHA256 nao suportado para blacklist."
                            _applied.append({"type": "hash", "value": _h[:16]+"...", "ok": _ok, "error": _err})
                        except Exception as _e:
                            _applied.append({"type": "hash", "value": _h[:16]+"...", "ok": False, "error": str(_e)[:80]})
                else:
                    _skipped += len(_result["hashes"]["gaps"])
                if "fw" in _tools and _result.get("urls", {}).get("gaps"):
                    for _url in _result["urls"]["gaps"][:50]:
                        try:
                            _r = _call("fw.fw_block_url", _url, 0)
                            _parsed = json.loads(_r) if isinstance(_r, str) and _r.strip().startswith("{") else {"raw": str(_r)}
                            _ok = "BLOCKED" in str(_r) or _parsed.get("ok", False) or "success" in str(_r).lower()
                            _applied.append({"type": "url", "value": _url[:50], "ok": _ok, "target": "fw", "error": "" if _ok else str(_r)[:80]})
                        except Exception as _e:
                            _applied.append({"type": "url", "value": _url[:50], "ok": False, "target": "fw", "error": str(_e)[:80]})
                _cache.pop("containment_status", None)
                threading.Thread(target=_refresh_containment_cache, daemon=True).start()
                self._send({"ok": True, "applied": len(_applied), "skipped": _skipped, "details": _applied})
            # DNS
            elif path == "/api/dns/status":
                self._send(_call("ad.dns_status"), ct="application/json")
            elif path == "/api/dns/block":
                g = _guard("dns", "block_domain")
                if g: self._send(g, code=g.get("code",403)); return
                self._send(_call("ad.dns_block_domain", self._s("domain")), ct="application/json")
            elif path == "/api/dns/unblock":
                self._send(_call("ad.dns_unblock_domain", self._s("domain")), ct="application/json")
            elif path == "/api/dns/block-list":
                self._send(_call("ad.dns_block_domain_list", self._s("list_name")), ct="application/json")
            elif path == "/api/dns/flush":
                self._send(_call("ad.dns_flush_cache"), ct="application/json")
            elif path == "/api/dns/list":
                self._send(_call("ad.dns_list_blocked"), ct="application/json")
            # Integrations CRUD
            elif path == "/api/integrations":
                body = self._data if isinstance(self._data, dict) else {}
                required = ["name", "class", "vendor", "product", "integration_method"]
                missing = [f for f in required if not body.get(f)]
                if missing:
                    self._send({"error": f"Campos obrigatorios: {missing}"}); return
                intg_class = body.get("class", "").strip()
                if intg_class not in _INTEGRATION_CATALOG:
                    self._send({"error": f"Classe desconhecida: {intg_class}"}); return
                new_intg = {
                    "id": str(uuid.uuid4())[:8] + "-" + re.sub(r"[^a-z0-9]", "-", body.get("name","").lower())[:20],
                    "name": _san(body.get("name",""), 100),
                    "class": intg_class,
                    "vendor": _san(body.get("vendor",""), 60),
                    "product": _san(body.get("product",""), 60),
                    "integration_method": _san(body.get("integration_method","api"), 30),
                    "fallback_method": _san(body.get("fallback_method",""), 30),
                    "enabled": bool(body.get("enabled", True)),
                    "capabilities": body.get("capabilities", {}),
                }
                data = _load_integrations()
                data.append(new_intg)
                _save_integrations(data)
                self._send({"ok": True, "integration": new_intg})
            elif path.startswith("/api/integrations/") and path.endswith("/toggle"):
                intg_id = path.split("/")[3]
                data = _load_integrations()
                for intg in data:
                    if intg.get("id") == intg_id:
                        intg["enabled"] = not intg.get("enabled", True)
                        _save_integrations(data)
                        self._send({"ok": True, "id": intg_id, "enabled": intg["enabled"]}); return
                self._send({"error": "Integration not found"}, code=404)
            elif path.startswith("/api/integrations/") and path.endswith("/test"):
                intg_id = path.split("/")[3]
                intg_list = _load_integrations()
                intg = next((i for i in intg_list if i.get("id") == intg_id), None)
                if not intg:
                    self._send({"error": "Integration not found"}, code=404); return
                cls = intg.get("class", "")
                vendor = intg.get("vendor", "")
                product = intg.get("product", "")
                method = intg.get("integration_method", "api")
                test_map = {"firewall": "fw.fw_status", "edr": "edr.edr_status",
                            "identity": "ad.ad_list_disabled_users", "dns": "ad.dns_status"}
                fn = test_map.get(cls, "fw.fw_status")
                raw = json.loads(_call(fn))
                # Build rich test result
                ok = bool(raw.get("ok") or raw.get("status") == "connected" or
                          raw.get("hostname") or raw.get("count") is not None)
                result = {
                    "ok": ok,
                    "integration": intg.get("name", ""),
                    "class": cls, "vendor": vendor, "product": product,
                    "method": method,
                    "connection": "ok" if ok else "error",
                }
                # Enrich by class
                if cls == "firewall":
                    result["url"] = f"{_ENV.get('FORTIGATE_WEB_IP','?')}:{_ENV.get('FORTIGATE_WEB_PORT','80')}"
                    result["version"] = raw.get("version", "")
                    result["hostname"] = raw.get("hostname", "")
                    result["serial"] = raw.get("serial", "")
                    result["permissions"] = {"read": "ok" if ok else "error", "write": "ok" if ok else "not_tested"}
                elif cls == "edr":
                    result["url"] = raw.get("base_url", _ENV.get("S1_BASE_URL","?"))
                    result["platform"] = raw.get("platform", "SentinelOne")
                    result["agents_found"] = raw.get("agents_found", 0)
                    result["site_ids"] = raw.get("site_ids", [])
                    result["permissions"] = {"read": "ok" if ok else "error", "write": "ok" if ok else "not_tested"}
                elif cls == "identity":
                    result["url"] = f"ldap://{_ENV.get('VM_DC01_IP','?')}:{_ENV.get('LDAP_PORT','389')}"
                    result["domain"] = _ENV.get("DOMAIN_NAME", "?")
                    result["disabled_count"] = raw.get("count", 0)
                    result["permissions"] = {"read": "ok" if ok else "error", "write": "ok" if ok else "not_tested"}
                elif cls == "dns":
                    result["url"] = f"dns://{raw.get('dc_ip', _ENV.get('VM_DNS_IP','?'))}"
                    result["domain"] = raw.get("domain", "")
                    result["zones"] = raw.get("output", "")
                    result["permissions"] = {"read": "ok" if ok else "error", "write": "ok" if ok else "not_tested"}
                if not ok:
                    result["error"] = raw.get("error", "Connection failed")
                # Salvar last_status no integrations.json
                with _intg_lock:
                    if _INTEGRATIONS_PATH.is_file():
                        try:
                            _all = json.loads(_INTEGRATIONS_PATH.read_text(encoding="utf-8"))
                        except Exception:
                            _all = [dict(i) for i in _DEFAULT_INTEGRATIONS]
                    else:
                        _all = [dict(i) for i in _DEFAULT_INTEGRATIONS]
                    for _i, _it in enumerate(_all):
                        if _it.get("id") == intg_id:
                            _all[_i]["last_status"] = {
                                "ok": result["ok"],
                                "connection": result.get("connection","unknown"),
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "details": {k:v for k,v in result.items() if k not in ("ok","connection","integration","class","vendor","product","method")}
                            }
                            break
                    _INTEGRATIONS_PATH.write_text(json.dumps(_all, indent=2, ensure_ascii=False), encoding="utf-8")
                self._send(result, ct="application/json")
            # Config
            elif path == "/api/config":
                ct_header = self.headers.get("Content-Type", "")
                if "application/json" in ct_header:
                    result = _update_config(self._data)
                    self._send(result)
                else:
                    self._send(_get_config_masked())
            elif path == "/api/config/test":
                module = self._s("module")
                test_fns = {"firewall": "fw.fw_status", "edr": "edr.edr_status",
                            "dns": "ad.dns_status", "ad": "ad.ad_list_disabled_users"}
                self._send(_call(test_fns.get(module, "fw.fw_status")), ct="application/json")
            else:
                self._send({"error": "endpoint not found"}, code=404)
        except Exception as e:
            self._send({"error": str(e), "trace": traceback.format_exc()[-400:]}, code=500)


    def do_PUT(self):
        path = self.path.split("?")[0]
        self._data = self._post()
        try:
            if path.startswith("/api/apt/campaigns/"):
                _cid = path.split("/")[4]
                body = self._data if isinstance(self._data, dict) else {}
                data = _load_apt_campaigns()
                for _i, _cp in enumerate(data):
                    if _cp.get("id") == _cid:
                        for k in ("name", "adversary", "description", "tags", "iocs"):
                            if k in body:
                                data[_i][k] = body[k]
                        data[_i]["last_updated"] = datetime.now(timezone.utc).isoformat()
                        _save_apt_campaigns(data)
                        self._send({"ok": True, "campaign": data[_i]}); return
                self._send({"error": "Campaign not found"}, code=404)
            elif path.startswith("/api/integrations/"):
                intg_id = path.split("/")[3]
                body = self._data if isinstance(self._data, dict) else {}
                data = _load_integrations()
                for i, intg in enumerate(data):
                    if intg.get("id") == intg_id:
                        for k in ("name", "integration_method", "fallback_method", "enabled", "capabilities"):
                            if k in body:
                                data[i][k] = body[k]
                        _save_integrations(data)
                        self._send({"ok": True, "integration": data[i]}); return
                self._send({"error": "Integration not found"}, code=404)
            else:
                self._send({"error": "Not found"}, code=404)
        except Exception as e:
            self._send({"error": str(e)}, code=500)

    def do_DELETE(self):
        path = self.path.split("?")[0]
        try:
            if path.startswith("/api/apt/campaigns/"):
                _cid = path.split("/")[4]
                data = _load_apt_campaigns()
                orig = len(data)
                data = [cp for cp in data if cp.get("id") != _cid]
                if len(data) == orig:
                    self._send({"error": "Campaign not found"}, code=404); return
                _save_apt_campaigns(data)
                self._send({"ok": True, "deleted": _cid})
            elif path.startswith("/api/integrations/"):
                intg_id = path.split("/")[3]
                data = _load_integrations()
                orig_len = len(data)
                data = [i for i in data if i.get("id") != intg_id]
                if len(data) == orig_len:
                    self._send({"error": "Integration not found"}, code=404); return
                _save_integrations(data)
                self._send({"ok": True, "deleted": intg_id})
            else:
                self._send({"error": "Not found"}, code=404)
        except Exception as e:
            self._send({"error": str(e)}, code=500)


def main():
    port = int(os.environ.get("MCP_WEB_PORT", "8080"))
    host = os.environ.get("MCP_WEB_HOST", "0.0.0.0")
    print(f"+------------------------------------------------------+")
    print(f"|  SafeLabs MCP Web v1.0 -- SOC Containment Console   |")
    print(f"|  URL: http://{host}:{port}/                         |")
    print(f"+------------------------------------------------------+")
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Stopped.")


if __name__ == "__main__":
    main()
