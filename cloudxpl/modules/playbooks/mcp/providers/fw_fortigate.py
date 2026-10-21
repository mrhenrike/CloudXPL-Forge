"""
Provider — FortiGate (SSH CLI)
================================
Implementação concreta de FirewallProvider para FortiGate via SSH.
Toda lógica de CLI extraída de server_fw.py — mesmo comportamento,
agora encapsulada em classe reutilizável.

Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""
from __future__ import annotations

import ipaddress
import re
import time
from typing import Any

from .base import FirewallProvider


class FortiGateProvider(FirewallProvider):
    """FortiGate firewall via sessão SSH interativa (paramiko)."""

    def __init__(
        self,
        host: str,
        ssh_user: str,
        ssh_password: str,
        vdom: str = "root",
        prefix: str = "safelabs",
        ssh_port: int = 22,
        connect_timeout: int = 15,
    ) -> None:
        """Inicializa provider e abre conexão SSH.

        Args:
            host: IP ou hostname do FortiGate.
            ssh_user: Usuário SSH.
            ssh_password: Senha SSH.
            vdom: VDOM alvo (padrão "root").
            prefix: Prefixo para objetos criados no FW.
            ssh_port: Porta SSH (padrão 22).
            connect_timeout: Timeout de conexão em segundos.
        """
        self._host = host
        self._vdom = vdom
        self._prefix = prefix

        self._grp_ip = f"{prefix}-blocklist-ip"
        self._grp_geo = f"{prefix}-blocklist-geo"
        self._grp_iso = f"{prefix}-isolated-hosts"
        self._dns_flt = f"{prefix}-dns-block"
        self._url_flt = f"{prefix}-url-block"

        try:
            import paramiko
        except ImportError:
            raise RuntimeError("pip install paramiko")

        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._ssh.connect(
            host,
            port=ssh_port,
            username=ssh_user,
            password=ssh_password,
            timeout=connect_timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        self._sh = self._ssh.invoke_shell(width=300, height=200)
        time.sleep(1.5)
        self._drain()

    # ------------------------------------------------------------------
    # Transporte SSH — baixo nível
    # ------------------------------------------------------------------

    def _drain(self, timeout: float = 3.0, idle: float = 0.8) -> str:
        """Drena buffer do shell até silêncio."""
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._sh.recv_ready():
                buf += self._sh.recv(8192)
                deadline = time.time() + idle
            else:
                time.sleep(0.2)
        return buf.decode("utf-8", errors="replace")

    def _run(self, cmd: str, wait: float = 0.8) -> str:
        """Envia um comando e retorna a saída."""
        self._sh.send(cmd + "\n")
        time.sleep(wait)
        return self._drain(timeout=3.0, idle=0.6)

    def _exec_block(self, cmds: list[str], wait: float = 0.4) -> str:
        """Executa bloco de comandos sequencialmente."""
        return "\n".join(self._run(c, wait) for c in cmds)

    # ------------------------------------------------------------------
    # FirewallProvider — métodos públicos
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """Retorna status do FortiGate (versão, hostname, serial)."""
        out = self._run("get system status", wait=3)
        info: dict[str, str] = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                info[k.strip()] = v.strip()
        return {
            "host": self._host,
            "version": info.get("Version", "?"),
            "serial": info.get("Serial-Number", "?"),
            "hostname": info.get("Hostname", "?"),
        }

    def block_ip(self, ip: str, comment: str = "SafeLabs MCP") -> str:
        """Bloqueia IP/CIDR criando address object e adicionando ao grupo."""
        name = f"{self._prefix}-ip-{ip.replace('/', '_').replace('.', '_')}"
        net = ipaddress.ip_network(ip, strict=False)
        mask = str(net.netmask)
        addr = str(net.network_address)
        self._exec_block([
            "config firewall address",
            f'  edit "{name}"',
            f'    set type ipmask',
            f'    set subnet {addr} {mask}',
            f'    set comment "{comment[:63]}"',
            "  next", "end",
        ])
        self._ensure_group(self._grp_ip)
        self._exec_block([
            "config firewall addrgrp",
            f'  edit "{self._grp_ip}"',
            f'    append member "{name}"',
            "  next", "end",
        ])
        return f"BLOCKED_IP:{ip}:{name}"

    def unblock_ip(self, ip: str) -> str:
        """Remove bloqueio de IP/CIDR."""
        name = f"{self._prefix}-ip-{ip.replace('/', '_').replace('.', '_')}"
        self._remove_from_group(self._grp_ip, name)
        self._exec_block(["config firewall address", f'  delete "{name}"', "end"])
        return f"UNBLOCKED_IP:{ip}"

    def block_domain(self, domain: str) -> str:
        """Bloqueia domínio via DNS filter (wildcard)."""
        self._ensure_dns_filter()
        out = self._run("show dnsfilter domain-filter 1", wait=2)
        ids = [int(x) for x in re.findall(r"edit (\d+)", out)]
        next_id = max((x for x in ids if x != 1), default=0) + 1
        self._exec_block([
            "config dnsfilter domain-filter",
            "  edit 1",
            "  config entries",
            f'    edit {next_id}',
            f'      set domain "{domain}"',
            '      set type wildcard',
            '      set action block',
            "    next",
            "  end",
            "  next", "end",
        ], wait=0.4)
        return f"BLOCKED_DOMAIN:{domain}"

    def block_url(self, url: str) -> str:
        """Bloqueia URL específica via web filter."""
        self._ensure_url_filter()
        out = self._run("show webfilter urlfilter 1", wait=2)
        ids = [int(x) for x in re.findall(r"edit (\d+)", out)]
        next_id = max((x for x in ids if x != 1), default=0) + 1
        self._exec_block([
            "config webfilter urlfilter",
            "  edit 1",
            "  config entries",
            f'    edit {next_id}',
            f'      set url "{url}"',
            '      set type wildcard',
            '      set action block',
            "    next",
            "  end",
            "  next", "end",
        ], wait=0.4)
        return f"BLOCKED_URL:{url}"

    def isolate_host(self, ip: str, reason: str = "SafeLabs MCP — host isolation") -> str:
        """Isola host interno via address group de isolamento."""
        name = f"{self._prefix}-isolated-{ip.replace('.', '_')}"
        net = ipaddress.ip_network(ip, strict=False)
        self._exec_block([
            "config firewall address",
            f'  edit "{name}"',
            '    set type ipmask',
            f'    set subnet {net.network_address} {net.netmask}',
            f'    set comment "{reason[:63]}"',
            "  next", "end",
        ])
        self._ensure_group(self._grp_iso)
        self._exec_block([
            "config firewall addrgrp",
            f'  edit "{self._grp_iso}"',
            f'    append member "{name}"',
            "  next", "end",
        ])
        return f"ISOLATED:{ip}:{name}"

    def deisolate_host(self, ip: str) -> str:
        """Remove isolamento de host."""
        name = f"{self._prefix}-isolated-{ip.replace('.', '_')}"
        self._remove_from_group(self._grp_iso, name)
        self._exec_block(["config firewall address", f'  delete "{name}"', "end"])
        return f"DEISOLATED:{ip}"

    def list_iocs(self) -> dict:
        """Lista IOCs atualmente bloqueados (IPs, geos, hosts isolados)."""
        ips = self._list_group(self._grp_ip)
        geos = self._list_group(self._grp_geo)
        iso = self._list_group(self._grp_iso)
        return {"blocked_ips": ips, "blocked_geos": geos, "isolated_hosts": iso}

    def close(self) -> None:
        """Encerra sessão SSH."""
        try:
            self._sh.close()
            self._ssh.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helpers internos
    # ------------------------------------------------------------------

    def _ensure_group(self, name: str) -> None:
        """Cria address group se não existir."""
        out = self._run(f'show firewall addrgrp "{name}"', wait=1.5)
        if f'edit "{name}"' in out:
            return
        self._exec_block([
            "config firewall addrgrp",
            f'  edit "{name}"',
            '    set member "none"',
            f'    set comment "SafeLabs MCP — managed group"',
            "  next", "end",
        ])

    def _remove_from_group(self, grp: str, member: str) -> None:
        """Remove membro de address group, preservando demais."""
        out = self._run(f'show firewall addrgrp "{grp}"', wait=2)
        m = re.search(r'set member(.*?)(?=set |next|$)', out, re.DOTALL | re.IGNORECASE)
        if not m:
            return
        members = [x for x in re.findall(r'"([^"]+)"', m.group(1)) if x not in (member, "none")]
        mstr = " ".join(f'"{x}"' for x in members) if members else '"none"'
        self._exec_block([
            "config firewall addrgrp",
            f'  edit "{grp}"',
            f'    set member {mstr}',
            "  next", "end",
        ])

    def _list_group(self, grp: str) -> list[str]:
        """Lista membros de um address group."""
        out = self._run(f'show firewall addrgrp "{grp}"', wait=2)
        m = re.search(r'set member(.*?)(?=set |next|$)', out, re.DOTALL | re.IGNORECASE)
        if not m:
            return []
        return [x for x in re.findall(r'"([^"]+)"', m.group(1)) if x != "none"]

    def _ensure_dns_filter(self) -> None:
        """Cria DNS domain-filter se não existir."""
        out = self._run("show dnsfilter domain-filter 1", wait=2)
        if "edit 1" in out:
            return
        self._exec_block([
            "config dnsfilter domain-filter",
            "  edit 1",
            f'    set name "{self._dns_flt}"',
            "  next", "end",
        ])

    def _ensure_url_filter(self) -> None:
        """Cria URL filter se não existir."""
        out = self._run("show webfilter urlfilter 1", wait=2)
        if "edit 1" in out:
            return
        self._exec_block([
            "config webfilter urlfilter",
            "  edit 1",
            f'    set name "{self._url_flt}"',
            "  next", "end",
        ])
