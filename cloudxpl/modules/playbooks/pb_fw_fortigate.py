#!/usr/bin/env python3
"""
Playbook N2 — FortiGate Firewall Containment
=============================================
Bloqueia/desbloqueia IOCs e isola hosts internos via FortiGate REST API.
Sempre opera em objetos com prefixo "safelabs-" para não afetar regras existentes.

IOC Blocking (externos):
  python3 pb_fw_fortigate.py --action block   --type ip      --ioc 1.2.3.4
  python3 pb_fw_fortigate.py --action block   --type domain  --ioc malicious.com
  python3 pb_fw_fortigate.py --action block   --type url     --ioc "https://evil.com/path"
  python3 pb_fw_fortigate.py --action block   --type country --ioc CN
  python3 pb_fw_fortigate.py --action unblock --type ip      --ioc 1.2.3.4

Host Isolation (hosts internos comprometidos):
  python3 pb_fw_fortigate.py --action isolate   --type host --ioc 10.0.0.50
  python3 pb_fw_fortigate.py --action isolate   --type host --ioc 10.0.0.0/24
  python3 pb_fw_fortigate.py --action isolate   --type host --ioc 10.0.0.10-10.0.0.20
  python3 pb_fw_fortigate.py --action deisolate --type host --ioc 10.0.0.50

Gerais:
  python3 pb_fw_fortigate.py --action list
  python3 pb_fw_fortigate.py --action status
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Constantes — nomes dos objetos SafeLabs no FortiGate
# ---------------------------------------------------------------------------
PFX                  = "safelabs"
GRP_IP               = f"{PFX}-blocklist-ip"
GRP_GEO              = f"{PFX}-blocklist-geo"
GRP_ISOLATED         = f"{PFX}-isolated-hosts"      # hosts internos isolados
GRP_EXCEPTIONS       = f"{PFX}-exceptions-hosts"    # hosts com bypass (TI, Kali, etc.)
DNS_FILTER_NAME      = f"{PFX}-dns-block"
URLFILTER_NAME       = f"{PFX}-url-block"
POLICY_INBOUND       = f"{PFX}-ioc-block-inbound"
POLICY_OUTBOUND      = f"{PFX}-ioc-block-outbound"
POLICY_EXCEPTIONS    = f"{PFX}-exceptions-bypass"   # ACCEPT-ALL para hosts de exceção
POLICY_ISOLATE_EGRESS  = f"{PFX}-host-isolate-egress"
POLICY_ISOLATE_INGRESS = f"{PFX}-host-isolate-ingress"
POLICY_COMMENT       = "SafeLabs N2 Playbook — IOC containment (não editar manualmente)"
EXCEPTION_COMMENT    = "SafeLabs N2 — Bypass para hosts de exceção (TI, Kali, etc.)"

# Políticas DENY que as exceções devem preceder (ordem de prioridade para move)
_DENY_POLICIES_ORDERED = [
    POLICY_INBOUND, POLICY_OUTBOUND,
    POLICY_ISOLATE_EGRESS, POLICY_ISOLATE_INGRESS,
]


# ---------------------------------------------------------------------------
# Validação de IOCs — executada ANTES de qualquer operação
# ---------------------------------------------------------------------------

_VALID_DOMAIN_RE = re.compile(r'^[a-z0-9]([a-z0-9\-\.]*[a-z0-9])?$', re.I)

def validate_ioc(value: str, ioc_type: str) -> tuple[bool, str]:
    """
    Valida o formato de um IOC antes de aplicar.
    Retorna (válido, mensagem_de_erro_ou_aviso).
    """
    v = value.strip()
    if not v:
        return False, "valor vazio"

    if ioc_type == "domain":
        domain = v.lstrip("*.")
        if "/" in domain:
            return False, "contém '/' — para paths use --type url"
        if " " in domain:
            return False, "contém espaços"
        if ".." in domain:
            return False, "pontos consecutivos"
        if "." not in domain:
            return False, "não é FQDN (falta ponto)"
        if not _VALID_DOMAIN_RE.match(domain):
            return False, "caracteres inválidos"
        return True, ""

    elif ioc_type == "ip":
        try:
            ipaddress.ip_network(v, strict=False)
            return True, ""
        except ValueError as e:
            return False, str(e)

    elif ioc_type == "url":
        if "." not in v:
            return False, "URL inválida (sem ponto)"
        return True, ""

    elif ioc_type == "country":
        if not re.match(r'^[A-Za-z]{2}$', v):
            return False, "código de país inválido (use 2 letras, ex: BR, CN)"
        return True, ""

    elif ioc_type == "host":
        v_clean = v
        if "-" in v:
            parts = v.split("-")
            try:
                ipaddress.ip_address(parts[0].strip())
                ipaddress.ip_address(parts[1].strip())
                return True, ""
            except ValueError:
                pass
        try:
            ipaddress.ip_network(v_clean, strict=False)
            return True, ""
        except ValueError as e:
            return False, str(e)

    return True, ""


def validate_list_file(list_path: "Path", ioc_type: str, stop_on_error: bool = False) -> dict:
    """
    Valida todas as entradas de uma lista.
    Retorna dict: {valid: [...], invalid: [(v, msg), ...], stats: {...}}.
    Imprime resumo. Se stop_on_error e houver inválidos, retorna invalid list.
    """
    values: list[str] = []
    for line in list_path.read_text(encoding="utf-8-sig").splitlines():
        line = line.split("#")[0].strip()
        if line:
            values.append(line)

    valid: list[str] = []
    invalid: list[tuple[str, str]] = []
    warnings: list[tuple[str, str]] = []

    for v in values:
        ok, msg = validate_ioc(v, ioc_type)
        if ok:
            # Aviso sem bloquear
            if ioc_type == "domain" and "/" in v:
                warnings.append((v, "contém '/' — pode não funcionar como zona DNS"))
            elif ioc_type == "url" and not any(v.startswith(p) for p in ("http://", "https://", "*.")):
                warnings.append((v, "URL sem protocolo — será tratada como wildcard"))
            valid.append(v)
        else:
            invalid.append((v, msg))

    stats = {"total": len(values), "valid": len(valid),
             "invalid": len(invalid), "warnings": len(warnings)}

    print(f"Validação '{list_path.name}' [{ioc_type}]: "
          f"{stats['valid']} válidos | {stats['invalid']} inválidos | {stats['warnings']} avisos")
    if invalid:
        print(f"  Inválidos (top 10):")
        for v, msg in invalid[:10]:
            print(f"    - {v!r}: {msg}")
    if warnings:
        print(f"  Avisos (top 5):")
        for v, msg in warnings[:5]:
            print(f"    ! {v!r}: {msg}")

    return {"valid": valid, "invalid": invalid, "warnings": warnings, "stats": stats}


# ---------------------------------------------------------------------------
# Env
# ---------------------------------------------------------------------------

def load_env(path: Path) -> dict[str, str]:
    env: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip().strip('"').strip("'")
    # OS env overrides
    for k in list(env):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


# ---------------------------------------------------------------------------
# FortiGate API client
# ---------------------------------------------------------------------------

class FortiGateAPI:
    def __init__(self, host: str, api_key: str, port: int = 80, vdom: str = "root",
                 protocol: str = "http", verify_ssl: bool = False):
        """
        Cliente FortiGate REST API.
        protocol: 'http' (padrão, porta 80) ou 'https' (porta 443).
        Em ambientes onde o acesso HTTPS externo não está disponível,
        usar HTTP com 'admin-port 80' (habilitado em System > Settings).
        """
        self.base = f"{protocol}://{host}:{port}/api/v2/cmdb"
        self.params = f"access_token={urllib.parse.quote(api_key)}&vdom={vdom}"
        # SSL context: só usado quando protocol == "https"
        self.ctx: ssl.SSLContext | None = None
        if protocol == "https":
            self.ctx = ssl.create_default_context()
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
            if hasattr(ssl, "OP_IGNORE_UNEXPECTED_EOF"):
                self.ctx.options |= ssl.OP_IGNORE_UNEXPECTED_EOF

    def _url(self, path: str, extra: str = "") -> str:
        qs = self.params + (f"&{extra}" if extra else "")
        return f"{self.base}/{path.lstrip('/')}?{qs}"

    def _open(self, req: urllib.request.Request, timeout: int = 30) -> Any:
        kwargs: dict = {"timeout": timeout}
        if self.ctx:
            kwargs["context"] = self.ctx
        with urllib.request.urlopen(req, **kwargs) as r:
            return json.loads(r.read().decode())

    def get(self, path: str, filter_str: str = "") -> Any:
        url = self._url(path, f"filter={urllib.parse.quote(filter_str)}" if filter_str else "")
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        return self._open(req)

    def post(self, path: str, data: dict) -> Any:
        body = json.dumps(data).encode()
        req = urllib.request.Request(
            self._url(path), data=body, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        return self._open(req)

    def put(self, path: str, data: dict) -> Any:
        body = json.dumps(data).encode()
        req = urllib.request.Request(
            self._url(path), data=body, method="PUT",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        return self._open(req)

    def move(self, path: str, policy_id: int, where: str, neighbor: int) -> Any:
        """Move uma política (where='before'/'after' neighbor_id)."""
        url = self._url(
            f"{path}/{policy_id}",
            f"action=move&where={where}&neighbor={neighbor}",
        )
        req = urllib.request.Request(
            url, data=b"{}", method="PUT",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        return self._open(req)

    def delete(self, path: str) -> Any:
        req = urllib.request.Request(
            self._url(path), method="DELETE",
            headers={"Accept": "application/json"},
        )
        return self._open(req)

    def exists(self, path: str) -> bool:
        try:
            r = self.get(path)
            return bool(r.get("results"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return False
            raise


# ---------------------------------------------------------------------------
# FortiGate CLI client (transporte SSH — fallback quando HTTPS não funciona)
# ---------------------------------------------------------------------------

class FortiGateCLI:
    """
    Acessa o FortiGate via SSH CLI interativo.
    Usado quando HTTPS/REST API não está disponível externamente.
    Configure: FORTIGATE_TRANSPORT=ssh no .env

    Implementa as mesmas operações de alto nível que o resto do playbook usa,
    diretamente como comandos CLI em vez de chamadas REST.
    """

    DNS_FILTER_ID  = 1   # ID do dnsfilter domain-filter safelabs
    URL_FILTER_ID  = 1   # ID do webfilter urlfilter safelabs

    def __init__(self, host: str, user: str, password: str, port: int = 22,
                 vdom: str = "root", lan_iface: str = "any", wan_iface: str = "any"):
        try:
            import paramiko as _paramiko  # noqa: F401
        except ImportError:
            raise RuntimeError("Instale paramiko para usar transporte SSH: pip install paramiko")
        import paramiko
        self.host      = host
        self.user      = user
        self.password  = password
        self.port      = port
        self.vdom      = vdom
        self.lan_iface = lan_iface
        self.wan_iface = wan_iface
        self._ssh   = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._ssh.connect(host, port=port, username=user, password=password,
                          timeout=15, look_for_keys=False, allow_agent=False)
        self._shell = self._ssh.invoke_shell(width=300, height=200)
        time.sleep(1.5)
        self._drain()

    def _drain(self, timeout: float = 3.0, idle: float = 0.8) -> str:
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._shell.recv_ready():
                buf += self._shell.recv(8192)
                deadline = time.time() + idle
            else:
                time.sleep(0.2)
        return buf.decode("utf-8", errors="replace")

    def _run(self, cmd: str, wait: float = 0.8) -> str:
        self._shell.send(cmd + "\n")
        time.sleep(wait)
        return self._drain(timeout=3.0, idle=0.6)

    def _exec_block(self, commands: list[str], wait: float = 0.4) -> str:
        return "\n".join(self._run(c, wait) for c in commands)

    def close(self) -> None:
        try:
            self._shell.close()
            self._ssh.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> dict:
        out = self._run("get system status", wait=3)
        info: dict = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                info[k.strip()] = v.strip()
        return {
            "status": "success",
            "version": info.get("Version", ""),
            "serial": info.get("Serial-Number", ""),
            "hostname": info.get("Hostname", ""),
        }

    # ------------------------------------------------------------------
    # Endereços
    # ------------------------------------------------------------------

    def _ensure_address_ipmask(self, name: str, ip: str, mask: str, comment: str = "") -> None:
        cmds = [
            "config firewall address",
            f'    edit "{name}"',
            f'        set type ipmask',
            f'        set subnet {ip} {mask}',
        ]
        if comment:
            cmds.append(f'        set comment "{comment[:63]}"')
        cmds += ["    next", "end"]
        self._exec_block(cmds)

    def _ensure_address_iprange(self, name: str, start: str, end: str, comment: str = "") -> None:
        cmds = [
            "config firewall address",
            f'    edit "{name}"',
            f'        set type iprange',
            f'        set start-ip {start}',
            f'        set end-ip {end}',
        ]
        if comment:
            cmds.append(f'        set comment "{comment[:63]}"')
        cmds += ["    next", "end"]
        self._exec_block(cmds)

    def _ensure_address_geography(self, name: str, country: str, comment: str = "") -> None:
        cmds = [
            "config firewall address",
            f'    edit "{name}"',
            f'        set type geography',
            f'        set country "{country}"',
        ]
        if comment:
            cmds.append(f'        set comment "{comment[:63]}"')
        cmds += ["    next", "end"]
        self._exec_block(cmds)

    def _delete_address(self, name: str) -> None:
        self._exec_block([
            "config firewall address",
            f'    delete "{name}"',
            "end",
        ])

    def _address_exists(self, name: str) -> bool:
        out = self._run(f'show firewall address "{name}"', wait=1.5)
        return f'edit "{name}"' in out

    # ------------------------------------------------------------------
    # Grupos de endereços
    # ------------------------------------------------------------------

    def _ensure_addrgrp(self, name: str, comment: str = "") -> None:
        out = self._run(f'show firewall addrgrp "{name}"', wait=1.5)
        if f'edit "{name}"' in out:
            return
        cmds = [
            "config firewall addrgrp",
            f'    edit "{name}"',
            f'        set member "none"',
        ]
        if comment:
            cmds.append(f'        set comment "{comment[:63]}"')
        cmds += ["    next", "end"]
        self._exec_block(cmds)

    def _append_to_addrgrp(self, grp: str, member: str) -> None:
        self._exec_block([
            "config firewall addrgrp",
            f'    edit "{grp}"',
            f'        append member "{member}"',
            "    next",
            "end",
        ])

    def _remove_from_addrgrp(self, grp: str, member: str) -> None:
        out = self._run(f'show firewall addrgrp "{grp}"', wait=2)
        m = re.search(r'set member(.*?)(?=set |next|$)', out, re.DOTALL | re.IGNORECASE)
        if not m:
            return
        raw = m.group(1)
        members = re.findall(r'"([^"]+)"', raw)
        members = [x for x in members if x != member and x != "none"]
        if not members:
            members = ["none"]
        member_str = " ".join(f'"{x}"' for x in members)
        self._exec_block([
            "config firewall addrgrp",
            f'    edit "{grp}"',
            f'        set member {member_str}',
            "    next",
            "end",
        ])

    def _list_addrgrp_members(self, grp: str) -> list[str]:
        out = self._run(f'show firewall addrgrp "{grp}"', wait=2)
        m = re.search(r'set member(.*?)(?=set |next|$)', out, re.DOTALL | re.IGNORECASE)
        if not m:
            return []
        return [x for x in re.findall(r'"([^"]+)"', m.group(1)) if x != "none"]

    # ------------------------------------------------------------------
    # DNS filter
    # ------------------------------------------------------------------

    def _ensure_dns_filter(self) -> None:
        out = self._run(f'show dnsfilter domain-filter {self.DNS_FILTER_ID}', wait=2)
        if f'edit {self.DNS_FILTER_ID}' in out:
            return
        self._exec_block([
            "config dnsfilter domain-filter",
            f'    edit {self.DNS_FILTER_ID}',
            f'        set name "{DNS_FILTER_NAME}"',
            "    next",
            "end",
        ])

    def _domain_in_dns_filter(self, domain: str) -> bool:
        out = self._run(f'show dnsfilter domain-filter {self.DNS_FILTER_ID}', wait=2)
        return f'"{domain}"' in out

    def _add_domain_to_dns_filter(self, domain: str) -> None:
        out = self._run(f'show dnsfilter domain-filter {self.DNS_FILTER_ID}', wait=2)
        ids = [int(x) for x in re.findall(r'edit (\d+)', out)]
        # The outer edit IDs include the filter itself (id=DNS_FILTER_ID)
        entry_ids = [x for x in ids if x != self.DNS_FILTER_ID]
        next_id = max(entry_ids) + 1 if entry_ids else 1
        self._exec_block([
            "config dnsfilter domain-filter",
            f'    edit {self.DNS_FILTER_ID}',
            "        config entries",
            f'            edit {next_id}',
            f'                set domain "{domain}"',
            '                set type wildcard',
            '                set action block',
            "            next",
            "        end",
            "    next",
            "end",
        ], wait=0.4)

    def _remove_domain_from_dns_filter(self, domain: str) -> None:
        out = self._run(f'show dnsfilter domain-filter {self.DNS_FILTER_ID}', wait=2)
        m = re.search(rf'edit (\d+)\s+set domain "{re.escape(domain)}"', out)
        if not m:
            return
        entry_id = m.group(1)
        self._exec_block([
            "config dnsfilter domain-filter",
            f'    edit {self.DNS_FILTER_ID}',
            "        config entries",
            f'            delete {entry_id}',
            "        end",
            "    next",
            "end",
        ])

    # ------------------------------------------------------------------
    # URL filter
    # ------------------------------------------------------------------

    def _ensure_url_filter(self) -> None:
        out = self._run(f'show webfilter urlfilter {self.URL_FILTER_ID}', wait=2)
        if f'edit {self.URL_FILTER_ID}' in out:
            return
        self._exec_block([
            "config webfilter urlfilter",
            f'    edit {self.URL_FILTER_ID}',
            f'        set name "{URLFILTER_NAME}"',
            "    next",
            "end",
        ])

    def _url_in_filter(self, url: str) -> bool:
        out = self._run(f'show webfilter urlfilter {self.URL_FILTER_ID}', wait=2)
        return f'"{url}"' in out

    def _add_url_to_filter(self, url: str) -> None:
        out = self._run(f'show webfilter urlfilter {self.URL_FILTER_ID}', wait=2)
        ids = [int(x) for x in re.findall(r'edit (\d+)', out)]
        entry_ids = [x for x in ids if x != self.URL_FILTER_ID]
        next_id = max(entry_ids) + 1 if entry_ids else 1
        self._exec_block([
            "config webfilter urlfilter",
            f'    edit {self.URL_FILTER_ID}',
            "        config entries",
            f'            edit {next_id}',
            f'                set url "{url}"',
            '                set type wildcard',
            '                set action block',
            "            next",
            "        end",
            "    next",
            "end",
        ], wait=0.4)

    # ------------------------------------------------------------------
    # Políticas
    # ------------------------------------------------------------------

    def _get_policy_id(self, name: str) -> int | None:
        out = self._run("show firewall policy", wait=4)
        # Find edit block containing the name
        for block in re.split(r'\bedit\b', out):
            if f'set name "{name}"' in block:
                m = re.match(r'\s*(\d+)', block)
                if m:
                    return int(m.group(1))
        return None

    def _next_policy_id(self) -> int:
        out = self._run("show firewall policy", wait=4)
        ids = [int(x) for x in re.findall(r'edit (\d+)', out)]
        return max(ids) + 1 if ids else 1

    def _ensure_deny_policy(self, name: str, src_addrs: list[str],
                             dst_addrs: list[str], comment: str = "") -> int:
        pol_id = self._get_policy_id(name)
        if pol_id:
            return pol_id
        pol_id = self._next_policy_id()
        src_str = " ".join(f'"{s}"' for s in src_addrs)
        dst_str = " ".join(f'"{d}"' for d in dst_addrs)
        cmds = [
            "config firewall policy",
            f'    edit {pol_id}',
            f'        set name "{name}"',
            f'        set srcintf "{self.wan_iface}"',
            f'        set dstintf "{self.lan_iface}"',
            f'        set srcaddr {src_str}',
            f'        set dstaddr {dst_str}',
            '        set action deny',
            '        set schedule "always"',
            '        set service "ALL"',
        ]
        if comment:
            cmds.append(f'        set comments "{comment}"')
        cmds += ["    next", "end"]
        self._exec_block(cmds, wait=0.5)
        return pol_id

    def _ensure_accept_policy(self, name: str, src_grp: str, comment: str = "") -> int:
        pol_id = self._get_policy_id(name)
        if pol_id:
            return pol_id
        pol_id = self._next_policy_id()
        cmds = [
            "config firewall policy",
            f'    edit {pol_id}',
            f'        set name "{name}"',
            f'        set srcintf "{self.wan_iface}"',
            f'        set dstintf "{self.lan_iface}"',
            f'        set srcaddr "{src_grp}"',
            '        set dstaddr "all"',
            '        set action accept',
            '        set schedule "always"',
            '        set service "ALL"',
        ]
        if comment:
            cmds.append(f'        set comments "{comment}"')
        cmds += ["    next", "end"]
        self._exec_block(cmds, wait=0.5)
        return pol_id

    def _move_policy_before(self, pol_id: int, before_id: int) -> None:
        self._exec_block([
            "config firewall policy",
            f'    move {pol_id} before {before_id}',
            "end",
        ])

    # ------------------------------------------------------------------
    # High-level operations (mesma interface que o resto do playbook usa)
    # ------------------------------------------------------------------

    def ensure_infrastructure(self) -> None:
        """
        Garante infraestrutura base SafeLabs.
        Ordem: address groups → DNS/URL filter objects → security profiles
        → aplica profiles à policy principal → tenta políticas deny (tolerante a limites).
        """
        # 1. Address groups
        for grp, cmt in [
            (GRP_IP,         POLICY_COMMENT),
            (GRP_GEO,        POLICY_COMMENT),
            (GRP_ISOLATED,   POLICY_COMMENT),
            (GRP_EXCEPTIONS, EXCEPTION_COMMENT),
        ]:
            self._ensure_addrgrp(grp, cmt)

        # 2. DNS / URL filter objects
        self._ensure_dns_filter()
        self._ensure_url_filter()

        # 3. Security profiles (DNS filter profile + Web filter profile)
        self._ensure_dns_filter_profile()
        self._ensure_web_filter_profile()

        # 4. Aplica profiles à política principal ACCEPT+NAT
        main_pol = self._discover_main_accept_policy()
        if main_pol:
            self.apply_security_profiles(main_pol, {
                "dns-filter": DNS_FILTER_NAME,
                "web-filter": URLFILTER_NAME,
            })
            print(f"[OK] Profiles aplicados à política '{main_pol}'")
        else:
            print("[AVISO] Política principal ACCEPT+NAT não encontrada — crie manualmente e use --action apply-profile")

        # 5. Políticas deny de IOCs (best-effort: FortiGate-VM64-OPC tem limite de 3 políticas
        #    e action deny pode não estar disponível em todas as licenças)
        try:
            self._ensure_deny_policy(
                POLICY_INBOUND,
                src_addrs=[GRP_IP, GRP_GEO],
                dst_addrs=["all"],
                comment=POLICY_COMMENT,
            )
            self._ensure_deny_policy(
                POLICY_OUTBOUND,
                src_addrs=["all"],
                dst_addrs=[GRP_IP, GRP_GEO],
                comment=POLICY_COMMENT,
            )
            exc_id = self._ensure_accept_policy(
                POLICY_EXCEPTIONS, GRP_EXCEPTIONS, EXCEPTION_COMMENT
            )
            for deny_name in _DENY_POLICIES_ORDERED:
                deny_id = self._get_policy_id(deny_name)
                if deny_id and deny_id != exc_id:
                    self._move_policy_before(exc_id, deny_id)
                    break
        except Exception as e:
            print(f"[AVISO] Políticas deny/exception não criadas: {e}")
            print("[AVISO] Content filtering via security profiles continua ativo.")

    def block_ip(self, ip: str, comment: str = POLICY_COMMENT) -> dict:
        name = addr_name("ip", ip)
        rng = parse_ip_range(ip)
        if rng:
            self._ensure_address_iprange(name, rng[0], rng[1], comment)
        else:
            net_str = ip_to_subnet(ip)
            net_ip, net_mask = net_str.split()
            self._ensure_address_ipmask(name, net_ip, net_mask, comment)
        self._ensure_addrgrp(GRP_IP)
        self._append_to_addrgrp(GRP_IP, name)
        return {"ok": True, "name": name}

    def unblock_ip(self, ip: str) -> dict:
        name = addr_name("ip", ip)
        self._remove_from_addrgrp(GRP_IP, name)
        if self._address_exists(name):
            self._delete_address(name)
        return {"ok": True}

    def block_domain(self, domain: str) -> dict:
        self._ensure_dns_filter()
        if self._domain_in_dns_filter(domain):
            return {"ok": True, "already": True}
        self._add_domain_to_dns_filter(domain)
        return {"ok": True}

    def block_domains_batch(self, domains: list[str]) -> dict:
        """
        Adiciona lista de domínios ao DNS filter em uma única sessão CLI (muito mais rápido).
        Ignora domínios já presentes. Retorna contagem de ok/skip.
        """
        self._ensure_dns_filter()
        # Verifica existentes para não duplicar
        existing_out = self._run(
            f"show dnsfilter domain-filter {self.DNS_FILTER_ID}", wait=2
        )
        existing = set(re.findall(r'set domain "([^"]+)"', existing_out))

        # Calcula próximo ID
        ids = [int(x) for x in re.findall(r'edit (\d+)', existing_out)]
        entry_ids = [x for x in ids if x != self.DNS_FILTER_ID]
        next_id = max(entry_ids) + 1 if entry_ids else 1

        new_domains = [d for d in domains if d not in existing]
        if not new_domains:
            return {"ok": 0, "skip": len(domains)}

        # Monta script CLI completo de uma vez
        lines = ["config dnsfilter domain-filter", f"    edit {self.DNS_FILTER_ID}", "    config entries"]
        for i, domain in enumerate(new_domains):
            eid = next_id + i
            lines += [
                f'        edit {eid}',
                f'            set domain "{domain}"',
                '            set type wildcard',
                '            set action block',
                '        next',
            ]
        lines += ["    end", "    next", "end"]

        # Envia tudo em blocos de 100 para evitar buffer overflow
        chunk_size = 100
        total_added = 0
        for chunk_start in range(0, len(lines), chunk_size):
            chunk = lines[chunk_start:chunk_start + chunk_size]
            for cmd in chunk:
                self._shell.send(cmd + "\n")
            time.sleep(0.5)
            self._drain(timeout=3, idle=0.5)
            total_added += min(chunk_size, len(lines) - chunk_start)

        return {"ok": len(new_domains), "skip": len(domains) - len(new_domains)}

    def block_urls_batch(self, urls: list[str]) -> dict:
        """Adiciona lista de URLs ao URL filter em uma única sessão CLI."""
        self._ensure_url_filter()
        existing_out = self._run(
            f"show webfilter urlfilter {self.URL_FILTER_ID}", wait=2
        )
        existing = set(re.findall(r'set url "([^"]+)"', existing_out))
        ids = [int(x) for x in re.findall(r'edit (\d+)', existing_out)]
        entry_ids = [x for x in ids if x != self.URL_FILTER_ID]
        next_id = max(entry_ids) + 1 if entry_ids else 1

        new_urls = [u for u in urls if u not in existing]
        if not new_urls:
            return {"ok": 0, "skip": len(urls)}

        lines = ["config webfilter urlfilter", f"    edit {self.URL_FILTER_ID}", "    config entries"]
        for i, url in enumerate(new_urls):
            eid = next_id + i
            lines += [
                f'        edit {eid}',
                f'            set url "{url}"',
                '            set type wildcard',
                '            set action block',
                '        next',
            ]
        lines += ["    end", "    next", "end"]

        chunk_size = 100
        for chunk_start in range(0, len(lines), chunk_size):
            chunk = lines[chunk_start:chunk_start + chunk_size]
            for cmd in chunk:
                self._shell.send(cmd + "\n")
            time.sleep(0.5)
            self._drain(timeout=3, idle=0.5)

        return {"ok": len(new_urls), "skip": len(urls) - len(new_urls)}

    def unblock_domain(self, domain: str) -> dict:
        self._remove_domain_from_dns_filter(domain)
        return {"ok": True}

    def block_url(self, url: str) -> dict:
        self._ensure_url_filter()
        if self._url_in_filter(url):
            return {"ok": True, "already": True}
        self._add_url_to_filter(url)
        return {"ok": True}

    def block_country(self, country: str, comment: str = POLICY_COMMENT) -> dict:
        name = addr_name("geo", country)
        self._ensure_address_geography(name, country, comment)
        self._ensure_addrgrp(GRP_GEO)
        self._append_to_addrgrp(GRP_GEO, name)
        return {"ok": True, "name": name}

    def isolate_host(self, ioc: str, comment: str = POLICY_COMMENT) -> dict:
        name = addr_name("isolated", ioc)
        rng = parse_ip_range(ioc)
        if rng:
            self._ensure_address_iprange(name, rng[0], rng[1], comment)
        else:
            net_str = ip_to_subnet(ioc)
            net_ip, net_mask = net_str.split()
            self._ensure_address_ipmask(name, net_ip, net_mask, comment)
        self._ensure_addrgrp(GRP_ISOLATED)
        self._append_to_addrgrp(GRP_ISOLATED, name)
        # Políticas de isolamento
        self._ensure_deny_policy(
            POLICY_ISOLATE_EGRESS,
            src_addrs=[GRP_ISOLATED],
            dst_addrs=["all"],
            comment=POLICY_COMMENT,
        )
        self._ensure_deny_policy(
            POLICY_ISOLATE_INGRESS,
            src_addrs=["all"],
            dst_addrs=[GRP_ISOLATED],
            comment=POLICY_COMMENT,
        )
        return {"ok": True, "name": name}

    def deisolate_host(self, ioc: str) -> dict:
        name = addr_name("isolated", ioc)
        self._remove_from_addrgrp(GRP_ISOLATED, name)
        if self._address_exists(name):
            self._delete_address(name)
        return {"ok": True}

    def add_exception(self, ioc: str) -> dict:
        name = f"{PFX}-exc-{sanitize_name(ioc)}"
        rng = parse_ip_range(ioc)
        if rng:
            self._ensure_address_iprange(name, rng[0], rng[1], EXCEPTION_COMMENT)
        else:
            net_str = ip_to_subnet(ioc)
            net_ip, net_mask = net_str.split()
            self._ensure_address_ipmask(name, net_ip, net_mask, EXCEPTION_COMMENT)
        self._ensure_addrgrp(GRP_EXCEPTIONS, EXCEPTION_COMMENT)
        self._append_to_addrgrp(GRP_EXCEPTIONS, name)
        return {"ok": True, "name": name}

    def remove_exception(self, ioc: str) -> dict:
        name = f"{PFX}-exc-{sanitize_name(ioc)}"
        self._remove_from_addrgrp(GRP_EXCEPTIONS, name)
        if self._address_exists(name):
            self._delete_address(name)
        return {"ok": True}

    def list_iocs(self) -> dict:
        return {
            "ips":  self._list_addrgrp_members(GRP_IP),
            "geos": self._list_addrgrp_members(GRP_GEO),
        }

    def list_exceptions(self) -> dict:
        return {"exceptions": self._list_addrgrp_members(GRP_EXCEPTIONS)}

    # ------------------------------------------------------------------
    # Security Profiles
    # ------------------------------------------------------------------

    def _ensure_dns_filter_profile(self) -> None:
        """Cria DNS filter profile ligando o domain-filter safelabs."""
        out = self._run(f'show dnsfilter profile "{DNS_FILTER_NAME}"', wait=2)
        if DNS_FILTER_NAME in out and "domain-filter-table" in out:
            return
        self._exec_block([
            "config dnsfilter profile",
            f'    edit "{DNS_FILTER_NAME}"',
            '        set comment "SafeLabs N2 - Custom domain blocking"',
            "        config domain-filter",
            f"            set domain-filter-table {self.DNS_FILTER_ID}",
            "        end",
            "    next",
            "end",
        ], wait=0.5)

    def _ensure_web_filter_profile(self) -> None:
        """Cria web filter profile ligando o URL filter safelabs."""
        out = self._run(f'show webfilter profile "{URLFILTER_NAME}"', wait=2)
        if URLFILTER_NAME in out and "urlfilter-table" in out:
            return
        self._exec_block([
            "config webfilter profile",
            f'    edit "{URLFILTER_NAME}"',
            '        set comment "SafeLabs N2 - Custom URL blocking"',
            "        config web",
            f"            set urlfilter-table {self.URL_FILTER_ID}",
            "        end",
            "    next",
            "end",
        ], wait=0.5)

    def _discover_main_accept_policy(self) -> str | None:
        """Descobre o nome da política principal de ACCEPT+NAT para aplicar profiles."""
        out = self._run("show firewall policy", wait=4)
        for block in re.split(r'\bedit\b', out)[1:]:
            if "nat enable" in block and "action accept" in block:
                m = re.search(r'set name "([^"]+)"', block)
                if m:
                    return m.group(1)
            # Fallback: qualquer policy com nat enable
            elif "nat enable" in block:
                m = re.search(r'set name "([^"]+)"', block)
                if m:
                    return m.group(1)
        return None

    def apply_security_profiles(self, policy_name: str, profiles: dict[str, str]) -> dict:
        """
        Aplica security profiles a uma política pelo nome.
        profiles: {'dns-filter': 'nome', 'web-filter': 'nome', 'app-control': 'nome',
                   'ips': 'nome', 'av': 'nome'}
        """
        pol_id = self._get_policy_id(policy_name)
        if not pol_id:
            return {"ok": False, "error": f"Política '{policy_name}' não encontrada"}

        cmds = ["config firewall policy", f"    edit {pol_id}", "        set utm-status enable"]
        profile_map = {
            "dns-filter":  "dnsfilter-profile",
            "web-filter":  "webfilter-profile",
            "app-control": "application-list",
            "ips":         "ips-sensor",
            "av":          "av-profile",
        }
        for ptype, pname in profiles.items():
            cli_key = profile_map.get(ptype)
            if cli_key:
                cmds.append(f'        set {cli_key} "{pname}"')
        cmds += ["    next", "end"]
        self._exec_block(cmds, wait=0.5)

        out = self._run(f"show firewall policy {pol_id}", wait=3)
        applied = {k: v for k, v in profiles.items() if v in out}
        return {"ok": True, "policy": policy_name, "policy_id": pol_id, "applied": applied}

    def list_security_profiles(self, profile_type: str = "all") -> dict:
        """Lista security profiles disponíveis por tipo."""
        _cmds = {
            "dns-filter":  "show dnsfilter profile",
            "web-filter":  "show webfilter profile",
            "app-control": "show application list",
            "ips":         "show ips sensor",
            "av":          "show antivirus profile",
        }
        result: dict[str, list[str]] = {}
        types = list(_cmds.keys()) if profile_type == "all" else [profile_type]
        for pt in types:
            if pt not in _cmds:
                continue
            out = self._run(_cmds[pt], wait=3)
            result[pt] = re.findall(r'edit "([^"]+)"', out)
        return result

    def list_policies(self) -> list[dict]:
        """Lista todas as firewall policies com resumo."""
        out = self._run("show firewall policy", wait=4)
        policies: list[dict] = []
        for block in re.split(r'\bedit\b', out)[1:]:
            m = re.match(r'\s*(\d+)', block)
            if not m:
                continue
            pid = int(m.group(1))
            name  = re.search(r'set name "([^"]+)"', block)
            action = re.search(r'set action (\S+)', block)
            srcaddr = re.search(r'set srcaddr ([^\n]+)', block)
            dstaddr = re.search(r'set dstaddr ([^\n]+)', block)
            profiles: dict[str, str] = {}
            for cli_key in ["webfilter-profile", "dnsfilter-profile", "application-list", "ips-sensor", "av-profile"]:
                m2 = re.search(rf'set {cli_key} "([^"]+)"', block)
                if m2:
                    profiles[cli_key] = m2.group(1)
            policies.append({
                "id":      pid,
                "name":    name.group(1) if name else f"policy_{pid}",
                "action":  action.group(1) if action else "accept",
                "srcaddr": (srcaddr.group(1).strip() if srcaddr else ""),
                "dstaddr": (dstaddr.group(1).strip() if dstaddr else ""),
                "profiles": profiles,
            })
        return policies

    def setup_content_filtering(self) -> dict:
        """
        Setup completo de content filtering:
        1. Garante DNS/URL filter objects
        2. Cria DNS/Web filter profiles
        3. Aplica profiles à política principal de ACCEPT+NAT
        Robusto contra limitações de licença (policy limit, action deny).
        """
        results: dict[str, Any] = {}

        # DNS/URL filter objects
        self._ensure_dns_filter()
        self._ensure_url_filter()
        results["dns_filter_object"] = True
        results["url_filter_object"] = True

        # Security profiles
        self._ensure_dns_filter_profile()
        self._ensure_web_filter_profile()
        results["dns_filter_profile"] = DNS_FILTER_NAME
        results["web_filter_profile"] = URLFILTER_NAME

        # Encontra e aplica à policy principal
        main_pol = self._discover_main_accept_policy()
        if main_pol:
            r = self.apply_security_profiles(main_pol, {
                "dns-filter": DNS_FILTER_NAME,
                "web-filter": URLFILTER_NAME,
            })
            results["profiles_applied_to"] = main_pol
            results["profiles_applied"] = r.get("applied", {})
        else:
            results["warning"] = "Nenhuma política principal ACCEPT+NAT encontrada para aplicar profiles"

        return results


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def ip_to_subnet(ip: str) -> str:
    """Converte IP ou CIDR em formato FortiGate (ex: '1.2.3.4 255.255.255.255')."""
    net = ipaddress.ip_network(ip, strict=False)
    return f"{net.network_address} {net.netmask}"


def parse_ip_range(ioc: str) -> tuple[str, str] | None:
    """Detecta range IP no formato A.B.C.D-E.F.G.H. Retorna (start, end) ou None."""
    if "-" in ioc:
        parts = ioc.split("-", 1)
        try:
            ipaddress.ip_address(parts[0].strip())
            ipaddress.ip_address(parts[1].strip())
            return parts[0].strip(), parts[1].strip()
        except ValueError:
            pass
    return None


def sanitize_name(value: str) -> str:
    """Gera nome seguro para objeto FortiGate."""
    return value.replace("/", "_").replace(":", "_").replace(".", "_").replace("*", "WILD")[:63]


def addr_name(ioc_type: str, value: str) -> str:
    return f"{PFX}-{ioc_type}-{sanitize_name(value)}"


def print_result(action: str, ioc_type: str, ioc: str, status: str, detail: str = "") -> None:
    line = f"[{status.upper()}] {action} | {ioc_type} | {ioc}"
    if detail:
        line += f" | {detail}"
    print(line)


# ---------------------------------------------------------------------------
# Address group helpers
# ---------------------------------------------------------------------------

def ensure_addr_group(api: FortiGateAPI, name: str) -> list[dict]:
    """Garante que o grupo de endereços existe; retorna membros atuais."""
    try:
        r = api.get(f"firewall/addrgrp/{urllib.parse.quote(name)}")
        results = r.get("results", [])
        if results:
            return results[0].get("member", [])
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise

    # Criar grupo vazio com membro placeholder (FG exige >=1 membro)
    api.post("firewall/addrgrp", {
        "name": name,
        "member": [{"name": "none"}],
        "comment": POLICY_COMMENT,
    })
    print(f"  [CRIADO] Grupo de endereços: {name}")
    return []


def group_add_member(api: FortiGateAPI, grp_name: str, member_name: str) -> None:
    members = ensure_addr_group(api, grp_name)
    names = {m["name"] for m in members}
    if member_name in names:
        return
    names.discard("none")
    names.add(member_name)
    api.put(f"firewall/addrgrp/{urllib.parse.quote(grp_name)}", {
        "member": [{"name": n} for n in names],
    })


def group_remove_member(api: FortiGateAPI, grp_name: str, member_name: str) -> bool:
    try:
        r = api.get(f"firewall/addrgrp/{urllib.parse.quote(grp_name)}")
        results = r.get("results", [])
        if not results:
            return False
        members = {m["name"] for m in results[0].get("member", [])}
        if member_name not in members:
            return False
        members.discard(member_name)
        if not members:
            members = {"none"}
        api.put(f"firewall/addrgrp/{urllib.parse.quote(grp_name)}", {
            "member": [{"name": n} for n in members],
        })
        return True
    except urllib.error.HTTPError:
        return False


# ---------------------------------------------------------------------------
# Policy helpers
# ---------------------------------------------------------------------------

def ensure_deny_policies(api: FortiGateAPI) -> None:
    """Garante que as políticas de bloqueio SafeLabs existem."""
    for policy_name, src, dst in [
        (POLICY_INBOUND,  [GRP_IP, GRP_GEO], ["all"]),
        (POLICY_OUTBOUND, ["all"],            [GRP_IP, GRP_GEO]),
    ]:
        try:
            r = api.get("firewall/policy", f"name=={policy_name}")
            if r.get("results"):
                continue
        except urllib.error.HTTPError:
            pass

        api.post("firewall/policy", {
            "name": policy_name,
            "action": "deny",
            "logtraffic": "all",
            "srcintf": [{"name": "any"}],
            "dstintf": [{"name": "any"}],
            "srcaddr": [{"name": n} for n in src],
            "dstaddr": [{"name": n} for n in dst],
            "schedule": "always",
            "service": [{"name": "ALL"}],
            "comments": POLICY_COMMENT,
            "status": "enable",
        })
        print(f"  [CRIADO] Política de bloqueio: {policy_name}")


# ---------------------------------------------------------------------------
# DNS Filter helpers
# ---------------------------------------------------------------------------

def ensure_dns_filter(api: FortiGateAPI) -> tuple[int, list[dict]]:
    """Garante que o DNS filter SafeLabs existe; retorna (filter_id, entries)."""
    try:
        r = api.get(f"dnsfilter/domain-filter/{urllib.parse.quote(DNS_FILTER_NAME)}")
        results = r.get("results", [])
        if results:
            obj = results[0]
            return obj.get("id", 0), obj.get("entries", [])
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise

    r = api.post("dnsfilter/domain-filter", {
        "name": DNS_FILTER_NAME,
        "comment": POLICY_COMMENT,
        "entries": [],
    })
    filter_id = r.get("mkey", 0)
    print(f"  [CRIADO] DNS filter list: {DNS_FILTER_NAME} (id={filter_id})")
    return filter_id, []


def dns_filter_add(api: FortiGateAPI, domain: str) -> None:
    fid, entries = ensure_dns_filter(api)
    existing = {e["domain"] for e in entries}
    wildcard = domain if domain.startswith("*.") else f"*.{domain}"
    for d in (domain, wildcard):
        if d not in existing:
            max_id = max((e.get("id", 0) for e in entries), default=0)
            entries.append({
                "id": max_id + 1,
                "domain": d,
                "type": "wildcard" if "*" in d else "simple",
                "action": "block",
                "status": "enable",
            })
    api.put(f"dnsfilter/domain-filter/{urllib.parse.quote(DNS_FILTER_NAME)}", {"entries": entries})


def dns_filter_remove(api: FortiGateAPI, domain: str) -> bool:
    fid, entries = ensure_dns_filter(api)
    original = len(entries)
    entries = [e for e in entries if domain not in e.get("domain", "")]
    if len(entries) == original:
        return False
    api.put(f"dnsfilter/domain-filter/{urllib.parse.quote(DNS_FILTER_NAME)}", {"entries": entries})
    return True


# ---------------------------------------------------------------------------
# URL / Web filter helpers
# ---------------------------------------------------------------------------

def ensure_url_filter(api: FortiGateAPI) -> tuple[int, list[dict]]:
    try:
        r = api.get(f"webfilter/urlfilter/{urllib.parse.quote(URLFILTER_NAME)}")
        results = r.get("results", [])
        if results:
            obj = results[0]
            return obj.get("id", 0), obj.get("entries", [])
    except urllib.error.HTTPError as e:
        if e.code != 404:
            raise

    r = api.post("webfilter/urlfilter", {
        "name": URLFILTER_NAME,
        "comment": POLICY_COMMENT,
        "entries": [],
    })
    uid = r.get("mkey", 0)
    print(f"  [CRIADO] URL filter list: {URLFILTER_NAME} (id={uid})")
    return uid, []


def url_filter_add(api: FortiGateAPI, url: str) -> None:
    uid, entries = ensure_url_filter(api)
    existing = {e["url"] for e in entries}
    if url in existing:
        return
    max_id = max((e.get("id", 0) for e in entries), default=0)
    entries.append({
        "id": max_id + 1,
        "url": url,
        "type": "wildcard" if "*" in url else "simple",
        "action": "block",
        "status": "enable",
    })
    api.put(f"webfilter/urlfilter/{urllib.parse.quote(URLFILTER_NAME)}", {"entries": entries})


def url_filter_remove(api: FortiGateAPI, url: str) -> bool:
    uid, entries = ensure_url_filter(api)
    original = len(entries)
    entries = [e for e in entries if e.get("url") != url]
    if len(entries) == original:
        return False
    api.put(f"webfilter/urlfilter/{urllib.parse.quote(URLFILTER_NAME)}", {"entries": entries})
    return True


# ---------------------------------------------------------------------------
# Ações principais
# ---------------------------------------------------------------------------

def block_ip(api: FortiGateAPI, ip: str) -> None:
    name = addr_name("ip", ip)
    subnet = ip_to_subnet(ip)

    # Criar objeto de endereço se não existir
    if not api.exists(f"firewall/address/{urllib.parse.quote(name)}"):
        api.post("firewall/address", {
            "name": name,
            "type": "ipmask",
            "subnet": subnet,
            "comment": POLICY_COMMENT,
        })
        print(f"  [CRIADO] Endereço: {name} ({subnet})")

    # Adicionar ao grupo + garantir políticas
    group_add_member(api, GRP_IP, name)
    ensure_deny_policies(api)
    print_result("BLOCK", "ip", ip, "ok", f"grupo={GRP_IP}")


def unblock_ip(api: FortiGateAPI, ip: str) -> None:
    name = addr_name("ip", ip)
    removed = group_remove_member(api, GRP_IP, name)
    # Tentar remover objeto de endereço
    try:
        api.delete(f"firewall/address/{urllib.parse.quote(name)}")
    except Exception:
        pass
    status = "ok" if removed else "not_found"
    print_result("UNBLOCK", "ip", ip, status)


def block_domain(api: FortiGateAPI, domain: str) -> None:
    dns_filter_add(api, domain)
    url_filter_add(api, f"*.{domain.lstrip('*.')}")
    print_result("BLOCK", "domain", domain, "ok", f"dns={DNS_FILTER_NAME} url={URLFILTER_NAME}")


def unblock_domain(api: FortiGateAPI, domain: str) -> None:
    d1 = dns_filter_remove(api, domain)
    d2 = url_filter_remove(api, f"*.{domain.lstrip('*.')}")
    print_result("UNBLOCK", "domain", domain, "ok" if (d1 or d2) else "not_found")


def block_url(api: FortiGateAPI, url: str) -> None:
    url_filter_add(api, url)
    print_result("BLOCK", "url", url, "ok", f"filter={URLFILTER_NAME}")


def unblock_url(api: FortiGateAPI, url: str) -> None:
    removed = url_filter_remove(api, url)
    print_result("UNBLOCK", "url", url, "ok" if removed else "not_found")


def block_country(api: FortiGateAPI, country_code: str) -> None:
    cc = country_code.upper()
    name = addr_name("geo", cc)
    if not api.exists(f"firewall/address/{urllib.parse.quote(name)}"):
        api.post("firewall/address", {
            "name": name,
            "type": "geography",
            "country": cc,
            "comment": POLICY_COMMENT,
        })
        print(f"  [CRIADO] Endereço geográfico: {name} ({cc})")
    group_add_member(api, GRP_GEO, name)
    ensure_deny_policies(api)
    print_result("BLOCK", "country", cc, "ok", f"grupo={GRP_GEO}")


def unblock_country(api: FortiGateAPI, country_code: str) -> None:
    cc = country_code.upper()
    name = addr_name("geo", cc)
    removed = group_remove_member(api, GRP_GEO, name)
    try:
        api.delete(f"firewall/address/{urllib.parse.quote(name)}")
    except Exception:
        pass
    print_result("UNBLOCK", "country", cc, "ok" if removed else "not_found")


# ---------------------------------------------------------------------------
# Host Isolation — isola host interno do acesso externo (WAN)
# ---------------------------------------------------------------------------

def ensure_isolation_policies(api: FortiGateAPI, lan_iface: str, wan_iface: str) -> None:
    """
    Garante as políticas de isolamento de host interno.

    Modo com interfaces configuradas (recomendado):
      EGRESS : host isolado → WAN → DENY  (impede saída para internet)
      INGRESS: WAN → host isolado → DENY  (impede entrada externa redirecionada)

    Modo any/any (fallback — isola host de tudo, inclusive LAN):
      Ambas as políticas usam srcintf=any, dstintf=any.
    """
    for policy_name, srcaddr, dstaddr, src_iface, dst_iface in [
        (POLICY_ISOLATE_EGRESS,
         [GRP_ISOLATED], ["all"],
         lan_iface, wan_iface),
        (POLICY_ISOLATE_INGRESS,
         ["all"], [GRP_ISOLATED],
         wan_iface, lan_iface),
    ]:
        try:
            r = api.get("firewall/policy", f"name=={policy_name}")
            if r.get("results"):
                continue
        except urllib.error.HTTPError:
            pass

        api.post("firewall/policy", {
            "name":      policy_name,
            "action":    "deny",
            "logtraffic": "all",
            "srcintf":   [{"name": src_iface}],
            "dstintf":   [{"name": dst_iface}],
            "srcaddr":   [{"name": n} for n in srcaddr],
            "dstaddr":   [{"name": n} for n in dstaddr],
            "schedule":  "always",
            "service":   [{"name": "ALL"}],
            "comments":  POLICY_COMMENT,
            "status":    "enable",
        })
        print(f"  [CRIADO] Política de isolamento: {policy_name} "
              f"(srcintf={src_iface} dstintf={dst_iface})")


def _create_host_addr(api: FortiGateAPI, ioc: str) -> str:
    """
    Cria objeto de endereço para o host/subnet/range isolado.
    Suporta: IP simples, CIDR, range A.B.C.D-E.F.G.H.
    Retorna o nome do objeto criado.
    """
    rng = parse_ip_range(ioc)
    if rng:
        start_ip, end_ip = rng
        name = addr_name("host", f"{start_ip}-{end_ip}")
        if not api.exists(f"firewall/address/{urllib.parse.quote(name)}"):
            api.post("firewall/address", {
                "name":     name,
                "type":     "iprange",
                "start-ip": start_ip,
                "end-ip":   end_ip,
                "comment":  POLICY_COMMENT,
            })
            print(f"  [CRIADO] Endereço (range): {name} ({start_ip} – {end_ip})")
    else:
        subnet = ip_to_subnet(ioc)
        name = addr_name("host", ioc)
        if not api.exists(f"firewall/address/{urllib.parse.quote(name)}"):
            api.post("firewall/address", {
                "name":    name,
                "type":    "ipmask",
                "subnet":  subnet,
                "comment": POLICY_COMMENT,
            })
            print(f"  [CRIADO] Endereço (host/subnet): {name} ({subnet})")
    return name


def isolate_host(api: FortiGateAPI, ioc: str, lan_iface: str, wan_iface: str) -> None:
    """
    Isola um host/subnet/range interno:
    - Bloqueia todo tráfego de saída para internet (egress)
    - Bloqueia toda entrada externa redirecionada ao host (ingress)
    - Host mantém acesso à rede interna (se lan_iface e wan_iface configurados)
    """
    addr_obj = _create_host_addr(api, ioc)
    group_add_member(api, GRP_ISOLATED, addr_obj)
    ensure_isolation_policies(api, lan_iface, wan_iface)

    mode = "parcial (LAN ok)" if lan_iface != "any" else "total (LAN bloqueada)"
    print_result("ISOLATE", "host", ioc, "ok",
                 f"grupo={GRP_ISOLATED} modo={mode} "
                 f"lan={lan_iface} wan={wan_iface}")


def deisolate_host(api: FortiGateAPI, ioc: str) -> None:
    """Remove o host do grupo de isolamento (restaura acesso)."""
    rng = parse_ip_range(ioc)
    name = addr_name("host", f"{rng[0]}-{rng[1]}" if rng else ioc)
    removed = group_remove_member(api, GRP_ISOLATED, name)
    try:
        api.delete(f"firewall/address/{urllib.parse.quote(name)}")
    except Exception:
        pass
    print_result("DEISOLATE", "host", ioc, "ok" if removed else "not_found")


# ---------------------------------------------------------------------------
# Exceptions — bypass para hosts específicos (TI, Kali, etc.)
# ---------------------------------------------------------------------------

def _get_policy_id_by_name(api: FortiGateAPI, name: str) -> int | None:
    """Retorna policyid pelo nome ou None se não encontrado."""
    try:
        r = api.get("firewall/policy", f"name=={name}")
        results = r.get("results", [])
        if results:
            return results[0].get("policyid")
    except Exception:
        pass
    return None


def ensure_exceptions_bypass_policy(api: FortiGateAPI) -> None:
    """
    Garante que a política de bypass para exceções existe e está ANTES das
    políticas de deny SafeLabs.

    Estratégia de ordenação:
      - Após criar (ou ao confirmar existência), tenta mover POLICY_EXCEPTIONS
        para imediatamente ANTES da primeira política deny safelabs encontrada.
      - Se não há deny policies ainda, o bypass fica no final — será reposicionado
        automaticamente na próxima chamada (ex: ao executar block).
      - Se o move falhar (permissão, versão), avisa para reposicionar manualmente.
    """
    ensure_addr_group(api, GRP_EXCEPTIONS)

    bypass_id = _get_policy_id_by_name(api, POLICY_EXCEPTIONS)
    if not bypass_id:
        r = api.post("firewall/policy", {
            "name":      POLICY_EXCEPTIONS,
            "action":    "accept",
            "logtraffic": "utm",
            "srcintf":   [{"name": "any"}],
            "dstintf":   [{"name": "any"}],
            "srcaddr":   [{"name": GRP_EXCEPTIONS}],
            "dstaddr":   [{"name": "all"}],
            "schedule":  "always",
            "service":   [{"name": "ALL"}],
            "comments":  EXCEPTION_COMMENT,
            "status":    "enable",
        })
        bypass_id = r.get("mkey")
        print(f"  [CRIADO] Política bypass para exceções: {POLICY_EXCEPTIONS} (id={bypass_id})")

    if not bypass_id:
        return

    # Tenta mover bypass para antes da primeira deny policy safelabs
    for deny_name in _DENY_POLICIES_ORDERED:
        deny_id = _get_policy_id_by_name(api, deny_name)
        if deny_id and deny_id != bypass_id:
            try:
                api.move("firewall/policy", bypass_id, "before", deny_id)
                print(f"  [POSIÇÃO] {POLICY_EXCEPTIONS} → antes de {deny_name}")
            except Exception as e:
                print(f"  AVISO: move automático falhou ({e}). "
                      f"Mova '{POLICY_EXCEPTIONS}' manualmente para ANTES de '{deny_name}' no GUI.",
                      file=sys.stderr)
            break


def add_exception(api: FortiGateAPI, ioc: str) -> None:
    """
    Adiciona host/subnet/range ao grupo de exceções (bypass de todas as deny policies).
    O objeto de endereço é criado com prefixo safelabs-exc-.
    """
    rng = parse_ip_range(ioc)
    if rng:
        start_ip, end_ip = rng
        name = f"{PFX}-exc-{sanitize_name(f'{start_ip}-{end_ip}')}"
        if not api.exists(f"firewall/address/{urllib.parse.quote(name)}"):
            api.post("firewall/address", {
                "name": name, "type": "iprange",
                "start-ip": start_ip, "end-ip": end_ip,
                "comment": EXCEPTION_COMMENT,
            })
            print(f"  [CRIADO] Endereço exceção (range): {name}")
    else:
        subnet = ip_to_subnet(ioc)
        name = f"{PFX}-exc-{sanitize_name(ioc)}"
        if not api.exists(f"firewall/address/{urllib.parse.quote(name)}"):
            api.post("firewall/address", {
                "name": name, "type": "ipmask",
                "subnet": subnet,
                "comment": EXCEPTION_COMMENT,
            })
            print(f"  [CRIADO] Endereço exceção: {name} ({subnet})")

    group_add_member(api, GRP_EXCEPTIONS, name)
    ensure_exceptions_bypass_policy(api)
    print_result("ADD-EXCEPTION", "host", ioc, "ok",
                 f"grupo={GRP_EXCEPTIONS} policy={POLICY_EXCEPTIONS}")


def remove_exception(api: FortiGateAPI, ioc: str) -> None:
    """Remove host do grupo de exceções."""
    rng = parse_ip_range(ioc)
    if rng:
        name = f"{PFX}-exc-{sanitize_name(f'{rng[0]}-{rng[1]}')}"
    else:
        name = f"{PFX}-exc-{sanitize_name(ioc)}"
    removed = group_remove_member(api, GRP_EXCEPTIONS, name)
    try:
        api.delete(f"firewall/address/{urllib.parse.quote(name)}")
    except Exception:
        pass
    print_result("REMOVE-EXCEPTION", "host", ioc, "ok" if removed else "not_found")


def list_exceptions(api: FortiGateAPI) -> None:
    print(f"\n[ Hosts com bypass (exceções) — grupo: {GRP_EXCEPTIONS} ]")
    try:
        r = api.get(f"firewall/addrgrp/{urllib.parse.quote(GRP_EXCEPTIONS)}")
        members = (r.get("results") or [{}])[0].get("member", [])
        found = False
        for m in members:
            if m["name"] == "none":
                continue
            found = True
            try:
                ar = api.get(f"firewall/address/{urllib.parse.quote(m['name'])}")
                addr = (ar.get("results") or [{}])[0]
                if addr.get("type") == "iprange":
                    detail = f"{addr.get('start-ip')} – {addr.get('end-ip')}"
                else:
                    detail = addr.get("subnet", "?")
                print(f"  {addr.get('name')} → {detail}")
            except Exception:
                print(f"  {m['name']}")
        if not found:
            print("  (nenhum)")
    except Exception:
        print("  (grupo não existe)")

    bypass_id = _get_policy_id_by_name(api, POLICY_EXCEPTIONS)
    if bypass_id:
        print(f"  [Política bypass: {POLICY_EXCEPTIONS} id={bypass_id}  ativo]")
    else:
        print(f"  [Política bypass {POLICY_EXCEPTIONS}: não criada]")


def list_iocs(api: FortiGateAPI) -> None:
    print(f"\n{'='*60}")
    print(f"  SafeLabs IOC Blocklist — FortiGate")
    print(f"{'='*60}")

    # IPs
    print(f"\n[ IPs bloqueados — grupo: {GRP_IP} ]")
    try:
        r = api.get(f"firewall/addrgrp/{urllib.parse.quote(GRP_IP)}")
        for m in (r.get("results") or [{}])[0].get("member", []):
            if m["name"] == "none":
                continue
            try:
                ar = api.get(f"firewall/address/{urllib.parse.quote(m['name'])}")
                addr = (ar.get("results") or [{}])[0]
                print(f"  {addr.get('name')} → {addr.get('subnet', addr.get('country', '?'))}")
            except Exception:
                print(f"  {m['name']}")
    except Exception:
        print("  (nenhum / grupo não existe)")

    # Países
    print(f"\n[ Países bloqueados — grupo: {GRP_GEO} ]")
    try:
        r = api.get(f"firewall/addrgrp/{urllib.parse.quote(GRP_GEO)}")
        for m in (r.get("results") or [{}])[0].get("member", []):
            if m["name"] == "none":
                continue
            print(f"  {m['name']}")
    except Exception:
        print("  (nenhum / grupo não existe)")

    # Domínios (DNS filter)
    print(f"\n[ Domínios bloqueados — DNS filter: {DNS_FILTER_NAME} ]")
    try:
        _, entries = ensure_dns_filter(api)
        for e in entries:
            print(f"  {e.get('domain')} [{e.get('action')}]")
        if not entries:
            print("  (nenhum)")
    except Exception:
        print("  (não configurado)")

    # URLs
    print(f"\n[ URLs bloqueadas — URL filter: {URLFILTER_NAME} ]")
    try:
        _, entries = ensure_url_filter(api)
        for e in entries:
            print(f"  {e.get('url')} [{e.get('action')}]")
        if not entries:
            print("  (nenhum)")
    except Exception:
        print("  (não configurado)")

    # Hosts isolados
    print(f"\n[ Hosts internos isolados — grupo: {GRP_ISOLATED} ]")
    try:
        r = api.get(f"firewall/addrgrp/{urllib.parse.quote(GRP_ISOLATED)}")
        members = (r.get("results") or [{}])[0].get("member", [])
        found = False
        for m in members:
            if m["name"] == "none":
                continue
            found = True
            try:
                ar = api.get(f"firewall/address/{urllib.parse.quote(m['name'])}")
                addr = (ar.get("results") or [{}])[0]
                addr_type = addr.get("type", "?")
                if addr_type == "iprange":
                    detail = f"{addr.get('start-ip')} – {addr.get('end-ip')}"
                else:
                    detail = addr.get("subnet", "?")
                print(f"  {addr.get('name')} ({addr_type}) → {detail}")
            except Exception:
                print(f"  {m['name']}")
        if not found:
            print("  (nenhum)")
    except Exception:
        print("  (nenhum / grupo não existe)")

    list_exceptions(api)
    print()


def status(api: FortiGateAPI) -> None:
    r = api.get("system/status")
    results = (r.get("results") or {})
    print(f"FortiGate: {results.get('Hostname', '?')} | "
          f"Version: {results.get('Version', '?')} | "
          f"Serial: {results.get('Serial-Number', '?')}")


# ---------------------------------------------------------------------------
# CSV batch processing
# ---------------------------------------------------------------------------

_FW_DISPATCH = {
    ("block",           "ip"):      block_ip,
    ("unblock",         "ip"):      unblock_ip,
    ("block",           "domain"):  block_domain,
    ("unblock",         "domain"):  unblock_domain,
    ("block",           "url"):     block_url,
    ("unblock",         "url"):     unblock_url,
    ("block",           "country"): block_country,
    ("unblock",         "country"): unblock_country,
    ("add-exception",   "host"):    add_exception,
    ("remove-exception","host"):    remove_exception,
}


def read_list_values(list_path: Path) -> list[str]:
    """
    Lê arquivo de lista de valores (um por linha).
    Ignora linhas vazias e linhas que iniciam com # (comentários).
    Ignora texto após # inline (ex: 'domain.com  # comentário').
    """
    values = []
    for line in list_path.read_text(encoding="utf-8-sig").splitlines():
        line = line.split("#")[0].strip()  # remove comentários inline
        if line:
            values.append(line)
    return values


def run_list(list_path: Path, action: str, ioc_type: str,
             api: FortiGateAPI, lan_iface: str, wan_iface: str,
             exception_set: set[str] | None = None) -> int:
    """
    Processa arquivo de lista (um valor por linha).
    Ação e tipo definidos pelos argumentos CLI — aplicados a todos os itens.
    exception_set: conjunto de valores a ignorar (loaded via --exception-list).
    """
    values = read_list_values(list_path)
    if not values:
        print(f"AVISO: lista vazia ou sem entradas válidas em {list_path}")
        return 0

    # Validação antecipada da lista antes de aplicar
    validation = validate_list_file(list_path, ioc_type, stop_on_error=False)
    valid_set = set(validation["valid"])
    # Filtra apenas entradas válidas
    original_count = len(values)
    values = [v for v in values if v in valid_set]
    skipped_invalid = original_count - len(values)
    if skipped_invalid:
        print(f"[AVISO] {skipped_invalid} entradas inválidas ignoradas (use --validate para ver detalhes)")

    exc = exception_set or set()
    total = len(values)
    print(f"Processando {total} itens de '{list_path.name}' "
          f"[action={action} type={ioc_type}]"
          + (f" | {len(exc)} exceções" if exc else ""))
    ok = fail = skip = 0

    if isinstance(api, FortiGateCLI):
        # Operações batch para domínios e URLs (muito mais rápido)
        exc = exception_set or set()
        values_filtered = [v for v in values if v not in exc]
        skip_count = len(values) - len(values_filtered)

        if action == "block" and ioc_type == "domain" and values_filtered:
            print(f"Usando batch DNS filter ({len(values_filtered)} domínios)...")
            r = api.block_domains_batch(values_filtered)
            print(f"\nLista concluída: {len(values)} itens | {r['ok']} ok | {skip_count} exceções | {r['skip']} já existentes | 0 falhas")
            return 0
        if action == "block" and ioc_type == "url" and values_filtered:
            print(f"Usando batch URL filter ({len(values_filtered)} URLs)...")
            r = api.block_urls_batch(values_filtered)
            print(f"\nLista concluída: {len(values)} itens | {r['ok']} ok | {skip_count} exceções | {r['skip']} já existentes | 0 falhas")
            return 0

        dispatch = {
            ("block",           "ip"):      lambda v: api.block_ip(v),
            ("unblock",         "ip"):      lambda v: api.unblock_ip(v),
            ("block",           "domain"):  lambda v: api.block_domain(v),
            ("unblock",         "domain"):  lambda v: api.unblock_domain(v),
            ("block",           "url"):     lambda v: api.block_url(v),
            ("block",           "country"): lambda v: api.block_country(v),
            ("isolate",         "host"):    lambda v: api.isolate_host(v),
            ("deisolate",       "host"):    lambda v: api.deisolate_host(v),
            ("add-exception",   "host"):    lambda v: api.add_exception(v),
            ("remove-exception","host"):    lambda v: api.remove_exception(v),
        }
    else:
        dispatch = {
            ("block",           "ip"):      lambda v: block_ip(api, v),
            ("unblock",         "ip"):      lambda v: unblock_ip(api, v),
            ("block",           "domain"):  lambda v: block_domain(api, v),
            ("unblock",         "domain"):  lambda v: unblock_domain(api, v),
            ("block",           "url"):     lambda v: block_url(api, v),
            ("unblock",         "url"):     lambda v: unblock_url(api, v),
            ("block",           "country"): lambda v: block_country(api, v),
            ("unblock",         "country"): lambda v: unblock_country(api, v),
            ("isolate",         "host"):    lambda v: isolate_host(api, v, lan_iface, wan_iface),
            ("deisolate",       "host"):    lambda v: deisolate_host(api, v),
            ("add-exception",   "host"):    lambda v: add_exception(api, v),
            ("remove-exception","host"):    lambda v: remove_exception(api, v),
        }
    fn = dispatch.get((action, ioc_type))
    if not fn:
        print(f"ERRO: combinação action={action} type={ioc_type} não suportada", file=sys.stderr)
        return 2

    for i, value in enumerate(values, 1):
        if value in exc:
            print(f"[SKIP] #{i} {value}  ← exceção")
            skip += 1
            continue
        try:
            fn(value)
            ok += 1
        except Exception as e:
            print(f"[FALHA] #{i} {value}: {e}", file=sys.stderr)
            fail += 1

    print(f"\nLista concluída: {total} itens | {ok} ok | {skip} exceções | {fail} falhas")
    return 1 if fail else 0


def run_csv(csv_path: Path, api: FortiGateAPI,
            default_lan: str, default_wan: str,
            exception_set: set[str] | None = None) -> int:
    """
    Processa CSV linha a linha.
    Formato: action,type,ioc[,lan_iface,wan_iface]
    Linhas iniciadas com # são ignoradas.
    exception_set: valores de ioc a ignorar.
    """
    exc = exception_set or set()
    total = ok = fail = skip = 0
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(
            (ln for ln in f if not ln.strip().startswith("#"))
        )
        for row in reader:
            row = {k.strip(): (v.strip() if v else "") for k, v in row.items() if k}
            total += 1
            action   = row.get("action",    "").lower()
            ioc_type = row.get("type",      "").lower()
            ioc      = row.get("ioc",       "").strip()
            lan      = row.get("lan_iface", "").strip() or default_lan
            wan      = row.get("wan_iface", "").strip() or default_wan

            if not action or not ioc_type or not ioc:
                print(f"[SKIP] linha {total}: campos obrigatórios faltando → {row}")
                skip += 1
                continue
            if ioc in exc:
                print(f"[SKIP] linha {total}: {ioc}  ← exceção")
                skip += 1
                continue
            try:
                if isinstance(api, FortiGateCLI):
                    method_map = {
                        ("block",  "ip"):       api.block_ip,
                        ("unblock","ip"):       api.unblock_ip,
                        ("block",  "domain"):   api.block_domain,
                        ("unblock","domain"):   api.unblock_domain,
                        ("block",  "url"):      api.block_url,
                        ("block",  "country"):  api.block_country,
                        ("isolate","host"):      api.isolate_host,
                        ("deisolate","host"):   api.deisolate_host,
                        ("add-exception","host"):    api.add_exception,
                        ("remove-exception","host"): api.remove_exception,
                    }
                    fn_cli = method_map.get((action, ioc_type))
                    if not fn_cli:
                        raise ValueError(f"action={action} type={ioc_type} não suportado (CLI)")
                    fn_cli(ioc)
                elif action == "isolate" and ioc_type == "host":
                    isolate_host(api, ioc, lan, wan)
                elif action == "deisolate" and ioc_type == "host":
                    deisolate_host(api, ioc)
                else:
                    fn = _FW_DISPATCH.get((action, ioc_type))
                    if not fn:
                        raise ValueError(f"action={action} type={ioc_type} não suportado")
                    fn(api, ioc)
                ok += 1
            except Exception as e:
                print(f"[FALHA] linha {total} ({action}/{ioc_type}/{ioc}): {e}",
                      file=sys.stderr)
                fail += 1

    print(f"\nCSV concluído: {total} linhas | {ok} ok | {skip} exceções/skip | {fail} falhas")
    return 1 if fail else 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="N2 Playbook — FortiGate Firewall Containment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
IOC Blocking (ameaças externas):
  python3 pb_fw_fortigate.py --action block   --type ip      --ioc 1.2.3.4
  python3 pb_fw_fortigate.py --action block   --type ip      --ioc 10.0.0.0/8
  python3 pb_fw_fortigate.py --action block   --type domain  --ioc malicious.com
  python3 pb_fw_fortigate.py --action block   --type url     --ioc "https://evil.com/payload"
  python3 pb_fw_fortigate.py --action block   --type country --ioc CN
  python3 pb_fw_fortigate.py --action unblock --type ip      --ioc 1.2.3.4

Host Isolation (hosts internos comprometidos):
  python3 pb_fw_fortigate.py --action isolate   --type host --ioc 10.0.0.50
  python3 pb_fw_fortigate.py --action isolate   --type host --ioc 10.0.0.0/24
  python3 pb_fw_fortigate.py --action isolate   --type host --ioc 10.0.0.10-10.0.0.20
  python3 pb_fw_fortigate.py --action deisolate --type host --ioc 10.0.0.50

  Com interfaces explícitas (mantém acesso LAN, bloqueia só WAN):
  python3 pb_fw_fortigate.py --action isolate --type host --ioc 10.0.0.50 \\
      --lan-iface internal --wan-iface wan1

Exceções (hosts que bypassam TODOS os bloqueios SafeLabs):
  python3 pb_fw_fortigate.py --action add-exception    --type host --ioc 10.254.3.10
  python3 pb_fw_fortigate.py --action add-exception    --type host --ioc 10.254.3.0/24
  python3 pb_fw_fortigate.py --action remove-exception --type host --ioc 10.254.3.10
  # Adicionar lista inteira de Kalis como exceção:
  python3 pb_fw_fortigate.py --action add-exception --type host --list lists/exceptions/kali_hosts.txt

Modo lista (--list): ação/tipo fixos, valores lidos do arquivo (1 por linha, # = comentário)
  python3 pb_fw_fortigate.py --action block --type domain --list lists/social_media_domains.txt
  python3 pb_fw_fortigate.py --action block --type domain --list lists/proxy_bypass_domains.txt \\
      --exception-list lists/exceptions/ti_department_ips.txt
  python3 pb_fw_fortigate.py --action block --type domain --list lists/antipiracy_p2p_domains.txt
  python3 pb_fw_fortigate.py --action block --type ip     --list minha_lista_ips.txt
  python3 pb_fw_fortigate.py --action isolate --type host --list hosts_comprometidos.txt
  python3 pb_fw_fortigate.py --action unblock --type domain --list dominios_liberar.txt

Modo CSV (--csv): cada linha tem action,type,ioc diferentes
  python3 pb_fw_fortigate.py --csv lists/examples/fw_ioc_block.csv \\
      --exception-list lists/exceptions/kali_hosts.txt

Gerais:
  python3 pb_fw_fortigate.py --action list
  python3 pb_fw_fortigate.py --action status
""")
    p.add_argument("--action",  required=True,
                   choices=["block", "unblock", "isolate", "deisolate",
                            "add-exception", "remove-exception",
                            "apply-profile", "list", "list-profiles",
                            "list-policies", "validate", "setup", "status"])
    p.add_argument("--type",    choices=["ip", "domain", "url", "country", "host"],
                   help="Tipo do IOC/alvo (obrigatório para block/unblock/isolate/deisolate)")
    p.add_argument("--object-type",
                   choices=["dns-filter", "url-filter", "address", "address-group",
                            "app-control", "ips", "av", "security-profile", "policy"],
                   default=None,
                   help="Tipo de objeto FortiGate a operar (ex: dns-filter, web-filter, policy, app-control, ips)")
    p.add_argument("--target",  default=None,
                   help="Nome da política ou perfil alvo (para --action apply-profile)")
    p.add_argument("--profile", default=None,
                   help="Nome do security profile a aplicar (para --action apply-profile)")
    p.add_argument("--ioc",     help="Valor do IOC ou IP/CIDR/range do host")
    p.add_argument("--env",     default=None, help="Caminho alternativo para .env")
    p.add_argument("--vdom",    default=None, help="VDOM do FortiGate (padrão: root)")
    p.add_argument("--lan-iface", default=None,
                   help="Interface LAN do FortiGate (ex: internal, port2). Padrão: any")
    p.add_argument("--wan-iface", default=None,
                   help="Interface WAN do FortiGate (ex: wan1, port1). Padrão: any")
    p.add_argument("--csv",  default=None, metavar="ARQUIVO.CSV",
                   help="Arquivo CSV com múltiplos IOCs/ações (colunas: action,type,ioc[,lan_iface,wan_iface])")
    p.add_argument("--list", default=None, metavar="ARQUIVO.TXT",
                   help="Arquivo de lista (um valor por linha). Requer --action e --type. "
                        "Linhas com # são ignoradas. Aceita qualquer lista da pasta lists/")
    p.add_argument("--exception-list", default=None, metavar="ARQUIVO.TXT",
                   help="Lista de valores a IGNORAR ao processar --list ou --csv. "
                        "Ex: lists/exceptions/kali_hosts.txt")
    p.add_argument("--no-ssl-verify", action="store_true", help="Desabilitar verificação SSL")
    return p


def main() -> int:
    args = build_parser().parse_args()

    # Carregar env
    env_path = Path(args.env) if args.env else Path(__file__).parent / ".env"
    if not env_path.is_file():
        # Fallback para poc-harpia/.env
        env_path = Path(__file__).parent.parent.parent / "laboratory" / "poc-harpia" / ".env"
    env = load_env(env_path)

    host      = env.get("FORTIGATE_WEB_IP") or env.get("VM_FORTIGATE_IP", "")
    transport = env.get("FORTIGATE_TRANSPORT", "api").lower()   # "api" ou "ssh"
    protocol  = env.get("FORTIGATE_WEB_PROTOCOL", "http").lower()
    port      = int(env.get("FORTIGATE_WEB_PORT", "80" if protocol == "http" else "443"))
    api_key   = env.get("FORTIGATE_RESTFUL_API_KEY", "")
    vdom      = args.vdom or env.get("FORTIGATE_VDOM", "root")
    lan_iface = args.lan_iface or env.get("FORTIGATE_LAN_IFACE", "any")
    wan_iface = args.wan_iface or env.get("FORTIGATE_WAN_IFACE", "any")

    if not host:
        print("ERRO: FORTIGATE_WEB_IP precisa estar no .env", file=sys.stderr)
        return 2

    # Cria cliente conforme transporte configurado
    if transport == "ssh":
        ssh_user     = env.get("FORTIGATE_SSH_USER") or env.get("VM_FORTIGATE_USER", "admin")
        ssh_password = env.get("FORTIGATE_SSH_PASSWORD") or env.get("VM_FORTIGATE_PASSWORD", "")
        ssh_port     = int(env.get("FORTIGATE_SSH_PORT", "22"))
        if not ssh_user or not ssh_password:
            print("ERRO: FORTIGATE_SSH_USER e FORTIGATE_SSH_PASSWORD precisam estar no .env",
                  file=sys.stderr)
            return 2
        print(f"[SSH CLI] Conectando a {host}:{ssh_port} como {ssh_user}...")
        api: FortiGateAPI | FortiGateCLI = FortiGateCLI(
            host, ssh_user, ssh_password, ssh_port, vdom, lan_iface, wan_iface
        )
    else:
        if not api_key:
            print("ERRO: FORTIGATE_RESTFUL_API_KEY precisa estar no .env (ou use FORTIGATE_TRANSPORT=ssh)",
                  file=sys.stderr)
            return 2
        verify_ssl = (protocol == "https" and not args.no_ssl_verify
                      and env.get("FORTIGATE_VERIFY_SSL", "false").lower() != "false")
        api = FortiGateAPI(host, api_key, port, vdom, protocol=protocol, verify_ssl=verify_ssl)

    # Carrega lista de exceções (--exception-list) — usado em --list e --csv
    exception_set: set[str] = set()
    if getattr(args, "exception_list", None):
        exc_path = Path(args.exception_list)
        if not exc_path.is_file():
            print(f"ERRO: --exception-list não encontrado: {exc_path}", file=sys.stderr)
            return 2
        exception_set = set(read_list_values(exc_path))
        print(f"Exceções carregadas: {len(exception_set)} itens de '{exc_path.name}'")

    try:
        # Modo CSV — processa arquivo em lote com ação/tipo por linha
        if args.csv:
            csv_path = Path(args.csv)
            if not csv_path.is_file():
                print(f"ERRO: arquivo CSV não encontrado: {csv_path}", file=sys.stderr)
                return 2
            return run_csv(csv_path, api, lan_iface, wan_iface, exception_set)

        # Modo VALIDATE — valida lista sem aplicar (deve ser antes do modo LIST)
        if args.action == "validate":
            if not args.list or not args.type:
                print("ERRO: --action validate requer --list e --type", file=sys.stderr)
                return 2
            list_path = Path(args.list)
            if not list_path.is_file():
                print(f"ERRO: arquivo não encontrado: {list_path}", file=sys.stderr)
                return 2
            result = validate_list_file(list_path, args.type)
            return 0 if result["stats"]["invalid"] == 0 else 1

        # Modo LIST — processa lista de valores com ação/tipo fixos via CLI
        if args.list:
            list_path = Path(args.list)
            if not list_path.is_file():
                print(f"ERRO: arquivo de lista não encontrado: {list_path}", file=sys.stderr)
                return 2
            if not args.action or not args.type:
                print("ERRO: --action e --type são obrigatórios com --list", file=sys.stderr)
                return 2
            return run_list(list_path, args.action, args.type, api, lan_iface, wan_iface,
                            exception_set)

        if args.action == "status":
            if isinstance(api, FortiGateCLI):
                info = api.status()
                print(f"FortiGate: {info.get('hostname')} | {info.get('version')} | serial={info.get('serial')}")
            else:
                status(api)
            return 0

        if args.action == "setup":
            if not isinstance(api, FortiGateCLI):
                print("ERRO: --action setup requer FORTIGATE_TRANSPORT=ssh", file=sys.stderr)
                return 2
            print("[SETUP] Configurando infraestrutura SafeLabs...")
            api.ensure_infrastructure()
            r = api.setup_content_filtering()
            print(f"[SETUP] Resultado: {r}")
            return 0

        if args.action == "list-profiles":
            if not isinstance(api, FortiGateCLI):
                print("ERRO: requer FORTIGATE_TRANSPORT=ssh", file=sys.stderr)
                return 2
            ptype = args.object_type or "all"
            profiles = api.list_security_profiles(ptype)
            for pt, names in profiles.items():
                print(f"\n{pt}:")
                for n in names:
                    safelabs = " ← SafeLabs" if "safelabs" in n else ""
                    print(f"  - {n}{safelabs}")
            return 0

        if args.action == "list-policies":
            if not isinstance(api, FortiGateCLI):
                print("ERRO: requer FORTIGATE_TRANSPORT=ssh", file=sys.stderr)
                return 2
            policies = api.list_policies()
            print(f"\n{'ID':<4} {'Nome':<40} {'Ação':<8} Profiles")
            print("-" * 80)
            for p in policies:
                pnames = ", ".join(f"{k.replace('-profile','').replace('application-list','app-control')}={v}"
                                   for k, v in p["profiles"].items())
                print(f"{p['id']:<4} {p['name']:<40} {p['action']:<8} {pnames or '(nenhum)'}")
            return 0

        if args.action == "apply-profile":
            if not isinstance(api, FortiGateCLI):
                print("ERRO: requer FORTIGATE_TRANSPORT=ssh", file=sys.stderr)
                return 2
            target = args.target
            if not target:
                # Descobre automaticamente a política principal
                target = api._discover_main_accept_policy()
                if not target:
                    print("ERRO: --target não informado e política principal não encontrada", file=sys.stderr)
                    return 2
                print(f"[INFO] Aplicando profiles à política detectada: '{target}'")

            obj_type = args.object_type or "dns-filter"
            profile_name = args.profile or (
                DNS_FILTER_NAME if obj_type == "dns-filter" else
                URLFILTER_NAME  if obj_type in ("url-filter", "web-filter") else
                args.profile
            )
            if not profile_name:
                print("ERRO: --profile ou --object-type obrigatório para apply-profile", file=sys.stderr)
                return 2

            profiles_to_apply = {obj_type: profile_name}
            r = api.apply_security_profiles(target, profiles_to_apply)
            if r.get("ok"):
                print(f"[OK] Profiles aplicados à política '{target}': {r.get('applied')}")
            else:
                print(f"[ERRO] {r.get('error')}", file=sys.stderr)
                return 1
            return 0

        if args.action == "list":
            if isinstance(api, FortiGateCLI):
                r = api.list_iocs()
                print(f"IPs bloqueados ({len(r['ips'])}): {r['ips']}")
                print(f"Países bloqueados ({len(r['geos'])}): {r['geos']}")
                r2 = api.list_exceptions()
                print(f"Exceções ({len(r2['exceptions'])}): {r2['exceptions']}")
            else:
                list_iocs(api)
            return 0

        if not args.type or not args.ioc:
            print("ERRO: --type e --ioc são obrigatórios para esta ação", file=sys.stderr)
            return 2

        ioc = args.ioc.strip()

        if isinstance(api, FortiGateCLI):
            cli_dispatch = {
                ("block",           "ip"):      lambda: api.block_ip(ioc),
                ("unblock",         "ip"):      lambda: api.unblock_ip(ioc),
                ("block",           "domain"):  lambda: api.block_domain(ioc),
                ("unblock",         "domain"):  lambda: api.unblock_domain(ioc),
                ("block",           "url"):     lambda: api.block_url(ioc),
                ("block",           "country"): lambda: api.block_country(ioc),
                ("isolate",         "host"):    lambda: api.isolate_host(ioc),
                ("deisolate",       "host"):    lambda: api.deisolate_host(ioc),
                ("add-exception",   "host"):    lambda: api.add_exception(ioc),
                ("remove-exception","host"):    lambda: api.remove_exception(ioc),
            }
            fn = cli_dispatch.get((args.action, args.type))
            if fn:
                result = fn()
                if isinstance(result, dict):
                    print(f"[OK] {result}")
            else:
                print(f"ERRO: combinação --action {args.action} --type {args.type} não suportada",
                      file=sys.stderr)
                return 2
        else:
            dispatch = {
                ("block",           "ip"):      lambda: block_ip(api, ioc),
                ("unblock",         "ip"):      lambda: unblock_ip(api, ioc),
                ("block",           "domain"):  lambda: block_domain(api, ioc),
                ("unblock",         "domain"):  lambda: unblock_domain(api, ioc),
                ("block",           "url"):     lambda: block_url(api, ioc),
                ("unblock",         "url"):     lambda: unblock_url(api, ioc),
                ("block",           "country"): lambda: block_country(api, ioc),
                ("unblock",         "country"): lambda: unblock_country(api, ioc),
                ("isolate",         "host"):    lambda: isolate_host(api, ioc, lan_iface, wan_iface),
                ("deisolate",       "host"):    lambda: deisolate_host(api, ioc),
                ("add-exception",   "host"):    lambda: add_exception(api, ioc),
                ("remove-exception","host"):    lambda: remove_exception(api, ioc),
            }
            fn = dispatch.get((args.action, args.type))
            if fn:
                fn()
            else:
                print(f"ERRO: combinação --action {args.action} --type {args.type} não suportada",
                      file=sys.stderr)
                return 2

        return 0

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")[:500]
        print(f"FortiGate API HTTP {e.code}: {body}", file=sys.stderr)
        return 1
    except urllib.error.URLError as e:
        print(f"Erro de rede: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Erro: {e}", file=sys.stderr)
        return 1
    finally:
        if isinstance(api, FortiGateCLI):
            api.close()


if __name__ == "__main__":
    raise SystemExit(main())
