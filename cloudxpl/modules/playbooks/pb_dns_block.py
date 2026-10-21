#!/usr/bin/env python3
"""
Playbook N2 — DNS Server Block (Windows DNS)
=============================================
Bloqueia resolução DNS de domínios e IPs no Windows DNS Server via WinRM/PowerShell.
Cria zona primária local "rpz.safelabs" que sobrepõe resolução dos domínios bloqueados.

Uso:
  python3 pb_dns_block.py --action block   --type domain --ioc malicious.com
  python3 pb_dns_block.py --action block   --type ip     --ioc 1.2.3.4
  python3 pb_dns_block.py --action unblock --type domain --ioc malicious.com
  python3 pb_dns_block.py --action flush                            # flush cache completo
  python3 pb_dns_block.py --action flush   --type domain --ioc malicious.com
  python3 pb_dns_block.py --action list
  python3 pb_dns_block.py --action status
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
import textwrap
from pathlib import Path

import socket
import threading
import time

try:
    import winrm
    from winrm.exceptions import WinRMError, WinRMTransportError
except ImportError:
    print("ERRO: pywinrm não instalado. Execute: pip install pywinrm", file=sys.stderr)
    sys.exit(2)

try:
    import paramiko
    _PARAMIKO_OK = True
except ImportError:
    _PARAMIKO_OK = False

# ---------------------------------------------------------------------------
# Constantes
# ---------------------------------------------------------------------------
RPZ_ZONE       = "rpz.safelabs"       # Zona de Response Policy local
SINKHOLE_IP    = "0.0.0.0"            # IP de sinkhole para domínios bloqueados
SAFELABS_COMMENT = "SafeLabs N2 Playbook"


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
    for k in list(env):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


# ---------------------------------------------------------------------------
# SSH Bastion Tunnel (para acessar WinRM em VMs internas)
# ---------------------------------------------------------------------------

class BastionTunnel:
    """Cria um port-forward local -> bastion -> target_host:target_port via paramiko."""

    def __init__(self, bastion_ip: str, bastion_user: str, bastion_pass: str,
                 target_host: str, target_port: int,
                 bastion_port: int = 22, local_port: int = 0):
        if not _PARAMIKO_OK:
            raise RuntimeError("paramiko não instalado. Execute: pip install paramiko")
        self._bastion_ip   = bastion_ip
        self._bastion_user = bastion_user
        self._bastion_pass = bastion_pass
        self._bastion_port = bastion_port
        self._target_host  = target_host
        self._target_port  = target_port
        self._local_port   = local_port
        self._ssh: paramiko.SSHClient | None = None
        self._srv: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._actual_port: int = 0

    def _handler(self, local_sock: socket.socket, transport: paramiko.Transport):
        try:
            chan = transport.open_channel(
                "direct-tcpip",
                (self._target_host, self._target_port),
                local_sock.getpeername(),
            )
        except Exception:
            local_sock.close()
            return
        try:
            while True:
                r = select_socks([local_sock, chan], [], [], 5.0)[0]
                if local_sock in r:
                    data = local_sock.recv(4096)
                    if not data:
                        break
                    chan.send(data)
                if chan in r:
                    data = chan.recv(4096)
                    if not data:
                        break
                    local_sock.send(data)
        finally:
            chan.close()
            local_sock.close()

    def start(self) -> int:
        """Inicia o tunnel; retorna a porta local utilizada."""
        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._ssh.connect(
            self._bastion_ip,
            port=self._bastion_port,
            username=self._bastion_user,
            password=self._bastion_pass,
            timeout=20,
            look_for_keys=False,
            allow_agent=False,
        )
        transport = self._ssh.get_transport()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(("127.0.0.1", self._local_port))
        self._srv.listen(10)
        self._actual_port = self._srv.getsockname()[1]
        self._srv.settimeout(1.0)

        def serve():
            while getattr(self, "_running", True):
                try:
                    conn, _ = self._srv.accept()
                    t = threading.Thread(target=self._handler, args=(conn, transport), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
                except Exception:
                    break

        self._running = True
        self._thread = threading.Thread(target=serve, daemon=True)
        self._thread.start()
        print(f"[Bastion Tunnel] {self._bastion_ip} -> {self._target_host}:{self._target_port} via 127.0.0.1:{self._actual_port}")
        return self._actual_port

    def stop(self):
        self._running = False
        if self._srv:
            try:
                self._srv.close()
            except Exception:
                pass
        if self._ssh:
            try:
                self._ssh.close()
            except Exception:
                pass


def select_socks(rlist, wlist, xlist, timeout):
    """Wrapper para select.select."""
    import select as _select
    return _select.select(rlist, wlist, xlist, timeout)


# ---------------------------------------------------------------------------
# WinRM client (direto — funciona quando DC01 é acessível via rede)
# ---------------------------------------------------------------------------

class DNSClient:
    def __init__(self, host: str, user: str, password: str, transport: str = "ntlm", port: int = 5985):
        self.session = winrm.Session(
            f"http://{host}:{port}/wsman",
            auth=(user, password),
            transport=transport,
            server_cert_validation="ignore",
        )
        self.host = host

    def run_ps(self, script: str) -> tuple[str, str, int]:
        """Executa PowerShell; retorna (stdout, stderr, returncode)."""
        result = self.session.run_ps(script)
        stdout = result.std_out.decode("utf-8", errors="replace").strip()
        stderr = result.std_err.decode("utf-8", errors="replace").strip()
        return stdout, stderr, result.status_code

    def check(self, script: str, context: str = "") -> str:
        """Executa script e lança exceção em caso de erro."""
        out, err, rc = self.run_ps(script)
        if rc != 0:
            raise RuntimeError(f"PowerShell falhou [{context}] rc={rc}:\n{err or out}")
        return out


# ---------------------------------------------------------------------------
# DNS Client via Bastion SSH (para DCs sem acesso externo direto)
# ---------------------------------------------------------------------------

_PWSH = r"C:\Program Files\PowerShell\7\pwsh.exe"

class BastionDNSClient:
    """
    Executa PowerShell DNS commands no DC01 via SSH no Bastion Windows + Invoke-Command.
    Não precisa de WinRM acessível externamente — apenas SSH ao bastion.
    """

    def __init__(self, bastion_ip: str, bastion_user: str, bastion_pass: str,
                 dc_ip: str, dc_user: str, dc_pass: str,
                 bastion_port: int = 22):
        if not _PARAMIKO_OK:
            raise RuntimeError("paramiko não instalado. Execute: pip install paramiko")
        self.bastion_ip   = bastion_ip
        self.bastion_user = bastion_user
        self.bastion_pass = bastion_pass
        self.dc_ip        = dc_ip
        self.dc_user      = dc_user
        self.dc_pass      = dc_pass
        self.bastion_port = bastion_port
        self._ssh: paramiko.SSHClient | None = None
        self.host = dc_ip

    def connect(self):
        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._ssh.connect(
            self.bastion_ip,
            port=self.bastion_port,
            username=self.bastion_user,
            password=self.bastion_pass,
            timeout=20,
            look_for_keys=False,
            allow_agent=False,
        )
        print(f"[BastionDNS] SSH conectado ao bastion {self.bastion_ip}")

    def close(self):
        if self._ssh:
            try:
                self._ssh.close()
            except Exception:
                pass
            self._ssh = None

    def _escape_ps(self, s: str) -> str:
        """Escapa aspas simples para embutir em string PS."""
        return s.replace("'", "''")

    def _ensure_connected(self):
        """Reconecta SSH ao bastion se a sessão estiver fechada."""
        try:
            if self._ssh and self._ssh.get_transport() and self._ssh.get_transport().is_active():
                return
        except Exception:
            pass
        self.connect()

    def run_ps(self, script: str) -> tuple[str, str, int]:
        """
        Executa script PowerShell no DC via Invoke-Command no bastion.
        Usa SFTP para enviar o script como arquivo temporário (evita limite de tamanho de cmd).
        """
        import re as _re
        import uuid as _uuid
        self._ensure_connected()

        dc_user_esc = self._escape_ps(self.dc_user)
        dc_pass_esc = self._escape_ps(self.dc_pass)
        tmp_name = f"sl_dns_{_uuid.uuid4().hex[:8]}.ps1"
        tmp_remote = f"C:\\Windows\\Temp\\{tmp_name}"

        # Wrapper: carrega o script do arquivo temp e executa no DC
        wrapper_script = (
            f"$pass = ConvertTo-SecureString '{dc_pass_esc}' -AsPlainText -Force\n"
            f"$cred = New-Object System.Management.Automation.PSCredential('{dc_user_esc}', $pass)\n"
            f"$sb = [ScriptBlock]::Create((Get-Content -Path '{tmp_remote}' -Raw))\n"
            f"Invoke-Command -ComputerName {self.dc_ip} -Credential $cred "
            f"-Authentication Negotiate -ScriptBlock $sb\n"
            f"Remove-Item -Path '{tmp_remote}' -Force -ErrorAction SilentlyContinue\n"
        )

        # Envia os dois arquivos via SFTP
        wrapper_name = f"sl_wrap_{_uuid.uuid4().hex[:8]}.ps1"
        wrapper_remote = f"C:\\Windows\\Temp\\{wrapper_name}"

        try:
            sftp = self._ssh.open_sftp()
            # Windows Temp via sftp usa /C:/Windows/Temp no OpenSSH
            sftp_base = "/C:/Windows/Temp"
            with sftp.open(f"{sftp_base}/{tmp_name}", "w") as f:
                f.write(script)
            with sftp.open(f"{sftp_base}/{wrapper_name}", "w") as f:
                f.write(wrapper_script)
            sftp.close()
        except Exception as e:
            # Fallback: tenta path unix-style
            try:
                sftp = self._ssh.open_sftp()
                import io as _io
                with sftp.open(f"/tmp/{tmp_name}", "w") as f:
                    f.write(script)
                sftp.close()
            except Exception as e2:
                raise RuntimeError(f"SFTP falhou: {e} / {e2}")

        cmd = f'"{_PWSH}" -NoProfile -NonInteractive -File "{wrapper_remote}"'
        try:
            stdin, stdout, stderr = self._ssh.exec_command(cmd, timeout=120)
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            rc  = stdout.channel.recv_exit_status()
        except Exception as ex:
            # Tenta reconectar e reraise
            self._ensure_connected()
            raise RuntimeError(f"exec_command falhou: {ex}")

        # Remove sequências ANSI do pwsh
        out = _re.sub(r'\x1b\[[0-9;]*m', '', out)
        err = _re.sub(r'\x1b\[[0-9;]*m', '', err)
        return out, err, rc

    def check(self, script: str, context: str = "") -> str:
        """Executa script e lança exceção em caso de erro."""
        out, err, rc = self.run_ps(script)
        if rc != 0:
            raise RuntimeError(f"PowerShell falhou [{context}] rc={rc}:\n{err or out}")
        return out


# ---------------------------------------------------------------------------
# DNS Zone (RPZ local)
# ---------------------------------------------------------------------------

_ENSURE_ZONE_SCRIPT = f"""
$zone = "{RPZ_ZONE}"
$existing = Get-DnsServerZone -Name $zone -ErrorAction SilentlyContinue
if (-not $existing) {{
    Add-DnsServerPrimaryZone -Name $zone -ZoneFile "$($zone).dns" -DynamicUpdate None
    Write-Output "CRIADA"
}} else {{
    Write-Output "EXISTE"
}}
"""

_ENSURE_SOA_SCRIPT = f"""
$zone = "{RPZ_ZONE}"
# Garante registro SOA adequado (já existe ao criar a zona primária)
$soa = Get-DnsServerResourceRecord -ZoneName $zone -RRType Soa -ErrorAction SilentlyContinue
Write-Output ($soa | Out-String)
"""


def ensure_rpz_zone(dns: DNSClient) -> None:
    out = dns.check(_ENSURE_ZONE_SCRIPT, "ensure_zone")
    if "CRIADA" in out:
        print(f"  [CRIADA] Zona DNS RPZ: {RPZ_ZONE}")


# ---------------------------------------------------------------------------
# Bloqueio de domínios
# ---------------------------------------------------------------------------

def _ps_block_domain(domain: str) -> str:
    domain = domain.lstrip("*.")  # normaliza wildcard
    sinkhole = SINKHOLE_IP
    zone = RPZ_ZONE
    return textwrap.dedent(f"""
        $zone = "{zone}"
        $domain = "{domain}"
        $sinkhole = "{sinkhole}"

        # Bloqueia via zona primária sobreposta (RPZ approach):
        # 1. Cria zona primária para o domínio se não existir
        $zoneExists = Get-DnsServerZone -Name $domain -ErrorAction SilentlyContinue
        if (-not $zoneExists) {{
            Add-DnsServerPrimaryZone -Name $domain -ZoneFile "$domain.dns" -DynamicUpdate None
            Write-Output "ZONA_CRIADA:$domain"
        }}

        # 2. Adiciona/garante registro A apontando para sinkhole
        $recApex = Get-DnsServerResourceRecord -ZoneName $domain -RRType A -Name "@" -ErrorAction SilentlyContinue
        if (-not $recApex) {{
            Add-DnsServerResourceRecord -ZoneName $domain -A -Name "@" -IPv4Address $sinkhole
            Write-Output "RECORD_A_CRIADO:@.$domain -> $sinkhole"
        }}

        # 3. Wildcard (* para subdomínios)
        $recWild = Get-DnsServerResourceRecord -ZoneName $domain -RRType A -Name "*" -ErrorAction SilentlyContinue
        if (-not $recWild) {{
            Add-DnsServerResourceRecord -ZoneName $domain -A -Name "*" -IPv4Address $sinkhole
            Write-Output "RECORD_A_CRIADO:*.$domain -> $sinkhole"
        }}

        Write-Output "OK:$domain"
    """)


def block_domain(dns: DNSClient, domain: str) -> None:
    out = dns.check(_ps_block_domain(domain), "block_domain")
    print(f"[OK] block | domain | {domain} | sinkhole={SINKHOLE_IP}")
    for line in out.splitlines():
        if line.strip():
            print(f"     {line}")


def block_domains_batch(dns, domains: list[str], chunk_size: int = 20) -> dict:
    """
    Bloqueia uma lista de domínios no DNS Windows em lotes (uma chamada PS por chunk).
    Muito mais eficiente que chamar block_domain() individual para cada domínio.
    Retorna {'ok': N, 'skip': N, 'fail': N}.
    """
    ensure_rpz_zone(dns)

    # Primeiro verifica quais zonas já existem (uma única consulta)
    check_script = """
$zones = Get-DnsServerZone | Select-Object -ExpandProperty ZoneName
$zones -join ","
"""
    try:
        out = dns.check(check_script, "list_zones")
        existing_zones = set(z.strip().lower() for z in out.split(",") if z.strip())
    except Exception:
        existing_zones = set()

    sinkhole = SINKHOLE_IP
    ok = skip = fail = 0
    total = len(domains)

    for chunk_start in range(0, total, chunk_size):
        chunk = domains[chunk_start:chunk_start + chunk_size]
        chunk_end = min(chunk_start + chunk_size, total)
        print(f"  Processando {chunk_start+1}-{chunk_end}/{total}...", end=" ", flush=True)

        # Gera script PS para o chunk inteiro
        lines = ["$sinkhole = '0.0.0.0'"]
        new_domains = []
        for domain in chunk:
            domain_norm = domain.lstrip("*.")
            if domain_norm.lower() in existing_zones:
                skip += 1
                continue
            new_domains.append(domain_norm)

        if not new_domains:
            print(f"já existentes ({len(chunk)} skip)")
            continue

        for domain_norm in new_domains:
            lines.append(textwrap.dedent(f"""
                try {{
                    $d = '{domain_norm}'
                    $zoneExists = Get-DnsServerZone -Name $d -ErrorAction SilentlyContinue
                    if (-not $zoneExists) {{
                        Add-DnsServerPrimaryZone -Name $d -ZoneFile "$($d).dns" -DynamicUpdate None -ErrorAction Stop
                    }}
                    $recApex = Get-DnsServerResourceRecord -ZoneName $d -RRType A -Name "@" -ErrorAction SilentlyContinue
                    if (-not $recApex) {{
                        Add-DnsServerResourceRecord -ZoneName $d -A -Name "@" -IPv4Address $sinkhole -ErrorAction Stop
                    }}
                    $recWild = Get-DnsServerResourceRecord -ZoneName $d -RRType A -Name "*" -ErrorAction SilentlyContinue
                    if (-not $recWild) {{
                        Add-DnsServerResourceRecord -ZoneName $d -A -Name "*" -IPv4Address $sinkhole -ErrorAction Stop
                    }}
                    Write-Output "OK:$($d)"
                }} catch {{
                    $msg = $_.Exception.Message -replace "\\n"," "
                    Write-Output "FAIL:$($d):$msg"
                }}
            """))

        script = "\n".join(lines)
        try:
            out = dns.check(script, f"batch_{chunk_start}")
            chunk_ok = out.count("OK:")
            chunk_fail = out.count("FAIL:")
            ok += chunk_ok
            fail += chunk_fail
            # Atualiza cache de zones existentes
            for domain_norm in new_domains:
                existing_zones.add(domain_norm.lower())
            print(f"{chunk_ok} ok, {chunk_fail} fail")
            if chunk_fail:
                for line in out.splitlines():
                    if line.startswith("FAIL:"):
                        print(f"    [FALHA] {line}", file=sys.stderr)
        except Exception as e:
            print(f"FALHA no chunk: {e}", file=sys.stderr)
            fail += len(new_domains)

    return {"ok": ok, "skip": skip, "fail": fail}


def _ps_unblock_domain(domain: str) -> str:
    domain = domain.lstrip("*.")
    return textwrap.dedent(f"""
        $domain = "{domain}"
        $zoneExists = Get-DnsServerZone -Name $domain -ErrorAction SilentlyContinue
        if ($zoneExists) {{
            Remove-DnsServerZone -Name $domain -Force
            Write-Output "ZONA_REMOVIDA:$domain"
        }} else {{
            Write-Output "NAO_ENCONTRADO:$domain"
        }}
    """)


def unblock_domain(dns: DNSClient, domain: str) -> None:
    out = dns.check(_ps_unblock_domain(domain), "unblock_domain")
    found = "ZONA_REMOVIDA" in out
    print(f"[{'OK' if found else 'SKIP'}] unblock | domain | {domain}")


# ---------------------------------------------------------------------------
# Bloqueio de IPs (via RPZ zone com PTR sinkhole)
# ---------------------------------------------------------------------------

def _ip_to_ptr_zone(ip: str) -> str:
    """Converte IP em nome de zona PTR reversa (ex: 1.2.3.4 → 4.3.2.1.in-addr.arpa)."""
    parts = ip.split(".")
    return ".".join(reversed(parts)) + ".in-addr.arpa"


def _ps_block_ip(ip: str) -> str:
    ptr_zone = _ip_to_ptr_zone(ip)
    sinkhole = SINKHOLE_IP
    # Bloqueia via firewall DNS response: cria registro A na zona RPZ
    # e bloqueia PTR reverso para dificultar identificação
    return textwrap.dedent(f"""
        $ip = "{ip}"
        $ptrZone = "{ptr_zone}"
        $sinkhole = "{sinkhole}"
        $rpzZone = "{RPZ_ZONE}"

        # Adiciona à zona RPZ um registro para este IP (custom record)
        $existing = Get-DnsServerResourceRecord -ZoneName $rpzZone -RRType A -Name "ip-block-$($ip.Replace('.', '-'))" -ErrorAction SilentlyContinue
        if (-not $existing) {{
            Add-DnsServerResourceRecord -ZoneName $rpzZone -A -Name "ip-block-$($ip.Replace('.', '-'))" -IPv4Address $sinkhole
            Write-Output "RECORD_CRIADO:$ip"
        }} else {{
            Write-Output "JA_EXISTE:$ip"
        }}

        # NOTA: bloqueio de IP por DNS tem efeito limitado (não impede conexões diretas).
        # Para bloqueio efetivo de IP, use o playbook FortiGate: pb_fw_fortigate.py
        Write-Output "AVISO: bloqueio de IP via DNS é limitado. Use pb_fw_fortigate.py para bloquear no firewall."
        Write-Output "OK:$ip"
    """)


def block_ip(dns: DNSClient, ip: str) -> None:
    ensure_rpz_zone(dns)
    out = dns.check(_ps_block_ip(ip), "block_ip")
    print(f"[OK] block | ip | {ip} (via RPZ zone {RPZ_ZONE})")
    for line in out.splitlines():
        if line.strip():
            print(f"     {line}")


def _ps_unblock_ip(ip: str) -> str:
    return textwrap.dedent(f"""
        $ip = "{ip}"
        $rpzZone = "{RPZ_ZONE}"
        $recName = "ip-block-$($ip.Replace('.', '-'))"
        $existing = Get-DnsServerResourceRecord -ZoneName $rpzZone -RRType A -Name $recName -ErrorAction SilentlyContinue
        if ($existing) {{
            Remove-DnsServerResourceRecord -ZoneName $rpzZone -RRType A -Name $recName -Force
            Write-Output "REMOVIDO:$ip"
        }} else {{
            Write-Output "NAO_ENCONTRADO:$ip"
        }}
    """)


def unblock_ip(dns: DNSClient, ip: str) -> None:
    try:
        ensure_rpz_zone(dns)
    except Exception:
        pass
    out = dns.check(_ps_unblock_ip(ip), "unblock_ip")
    found = "REMOVIDO" in out
    print(f"[{'OK' if found else 'SKIP'}] unblock | ip | {ip}")


# ---------------------------------------------------------------------------
# Bloqueio de prefixos CIDR via RPZ IP triggers
# ---------------------------------------------------------------------------

def _cidr_to_rpz_name(cidr: str) -> str | None:
    """
    Converte prefixo CIDR para nome de registro RPZ IP trigger.
    RFC 5782 / BIND RPZ format:
      IPv4: <prefix_len>.<reversed_octets>  ex: 157.240.0.0/16 -> 16.0.0.240.157
      IPv6: <prefix_len>.<reversed_nibbles> ex: 2607:f8b0::/32 -> 32.0.b.8.f.7.0.6.2
    """
    import ipaddress
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if isinstance(net, ipaddress.IPv4Network):
            # Reverte octetos e adiciona prefixo
            octets = str(net.network_address).split(".")
            reversed_octets = ".".join(reversed(octets))
            return f"{net.prefixlen}.{reversed_octets}"
        else:
            # IPv6: expande para nibbles
            exploded = net.network_address.exploded.replace(":", "")
            nibbles = ".".join(reversed(list(exploded)))
            return f"{net.prefixlen}.{nibbles}"
    except ValueError:
        return None


def _ps_block_prefixes_batch(prefixes: list[str], rpz_zone: str, sinkhole: str = "0.0.0.0") -> str:
    """
    Gera script PowerShell para criar RPZ IP trigger entries para múltiplos prefixos CIDR.
    Usa CNAME apontando para wildcard do sinkhole (padrão Windows DNS RPZ).
    """
    entries = []
    for cidr in prefixes:
        rpz_name = _cidr_to_rpz_name(cidr)
        if rpz_name:
            # Escapa cidr para PS
            cidr_esc = cidr.replace("/", "_").replace(":", "_").replace(".", "_")
            entries.append((rpz_name, cidr, cidr_esc))

    if not entries:
        return "Write-Output 'NENHUM_PREFIXO_VALIDO'"

    lines = [
        f'$rpzZone = "{rpz_zone}"',
        f'$sinkhole = "{sinkhole}"',
        "$ok = 0; $skip = 0; $fail = 0",
        "",
        "# Garante que zona RPZ existe",
        "if (-not (Get-DnsServerZone -Name $rpzZone -ErrorAction SilentlyContinue)) {",
        f'    Add-DnsServerPrimaryZone -Name $rpzZone -ZoneFile "{rpz_zone}.dns" -ErrorAction Stop',
        "}",
        "",
        "# Adiciona IP triggers como registros A apontando para sinkhole",
        "# Nome no formato: <prefixlen>.<reversed-octets> dentro da zona rpz-ip da zona RPZ",
    ]

    for rpz_name, cidr, cidr_esc in entries:
        lines += [
            f'$recName = "{rpz_name}"',
            f'$cidr = "{cidr}"',
            '$existing = Get-DnsServerResourceRecord -ZoneName $rpzZone -Name $recName -ErrorAction SilentlyContinue',
            'if (-not $existing) {',
            '    try {',
            '        Add-DnsServerResourceRecord -ZoneName $rpzZone -A -Name $recName -IPv4Address $sinkhole -ErrorAction Stop',
            '        $ok++',
            '    } catch {',
            '        $fail++',
            '        Write-Warning "FALHA: $cidr -> $_"',
            '    }',
            '} else { $skip++ }',
        ]

    lines += [
        '',
        'Write-Output "RESULTADO: ok=$ok skip=$skip fail=$fail total=' + str(len(entries)) + '"',
    ]
    return "\n".join(lines)


def block_prefixes_batch(dns, prefixes: list[str], chunk_size: int = 50) -> dict:
    """
    Bloqueia lista de prefixos CIDR via DNS RPZ IP triggers em lotes.
    Retorna dict com ok/skip/fail/total.
    """
    ensure_rpz_zone(dns)
    total_ok = total_skip = total_fail = 0
    chunks = [prefixes[i:i+chunk_size] for i in range(0, len(prefixes), chunk_size)]
    print(f"  Bloqueando {len(prefixes)} prefixos em {len(chunks)} lotes de {chunk_size}...")

    for idx, chunk in enumerate(chunks, 1):
        script = _ps_block_prefixes_batch(chunk, RPZ_ZONE, SINKHOLE_IP)
        try:
            out, err, rc = dns.run_ps(script)
            # Parseia resultado
            import re
            m = re.search(r'ok=(\d+).*?skip=(\d+).*?fail=(\d+)', out)
            if m:
                total_ok   += int(m.group(1))
                total_skip += int(m.group(2))
                total_fail += int(m.group(3))
            if err.strip() and "WARNING" not in err.upper():
                print(f"    Lote {idx}/{len(chunks)} STDERR: {err.strip()[:200]}")
            else:
                print(f"    Lote {idx}/{len(chunks)}: ok={m.group(1) if m else '?'} skip={m.group(2) if m else '?'} fail={m.group(3) if m else '?'}", end="\r")
        except Exception as e:
            print(f"    [ERRO] Lote {idx}: {e}")
            total_fail += len(chunk)

    print()
    return {"ok": total_ok, "skip": total_skip, "fail": total_fail, "total": len(prefixes)}


# ---------------------------------------------------------------------------
# Flush de cache
# ---------------------------------------------------------------------------

def flush_cache(dns: DNSClient, domain: str | None = None) -> None:
    if domain:
        domain = domain.lstrip("*.")
        script = textwrap.dedent(f"""
            $domain = "{domain}"
            # Remove registros em cache para o domínio específico
            $cache = Get-DnsServerCache | Where-Object {{ $_.HostName -like "*$domain*" }}
            if ($cache) {{
                $cache | ForEach-Object {{ Remove-DnsServerResourceRecord -ZoneName "..Cache" -InputObject $_ -Force -ErrorAction SilentlyContinue }}
                Write-Output "FLUSH_PARCIAL:$domain"
            }} else {{
                Write-Output "NAO_ENCONTRADO_CACHE:$domain"
            }}
            # Clear-DnsClientCache no servidor também
            Clear-DnsClientCache -ErrorAction SilentlyContinue
        """)
        out, err, rc = dns.run_ps(script)
        print(f"[OK] flush | domain | {domain}")
        if out.strip():
            print(f"     {out.strip()}")
    else:
        script = "Clear-DnsServerCache -Force; Write-Output 'FLUSH_COMPLETO'"
        dns.check(script, "flush_all")
        print("[OK] flush | cache completo do servidor DNS limpo")


# ---------------------------------------------------------------------------
# List
# ---------------------------------------------------------------------------

_LIST_SCRIPT = f"""
$rpzZone = "{RPZ_ZONE}"

# Zonas de bloqueio de domínio (excluindo zonas padrão do sistema)
$systemZones = @(".", "localhost", "0.in-addr.arpa", "127.in-addr.arpa", "255.in-addr.arpa",
                 "{RPZ_ZONE}", "_msdcs", "TrustAnchors")
$blocked = Get-DnsServerZone | Where-Object {{
    $z = $_.ZoneName
    ($systemZones -notcontains $z) -and
    (-not $z.EndsWith(".in-addr.arpa")) -and
    ($z -notlike "*safelabs*") -and
    ($z -notlike "*.arpa")
}}

Write-Output "=== Domínios bloqueados (zonas primárias de sinkhole) ==="
if ($blocked) {{
    $blocked | ForEach-Object {{ Write-Output "  $($_.ZoneName)" }}
}} else {{
    Write-Output "  (nenhum)"
}}

# IPs bloqueados na zona RPZ
Write-Output "`n=== IPs bloqueados (zona {RPZ_ZONE}) ==="
$rpzExists = Get-DnsServerZone -Name $rpzZone -ErrorAction SilentlyContinue
if ($rpzExists) {{
    $records = Get-DnsServerResourceRecord -ZoneName $rpzZone -RRType A -ErrorAction SilentlyContinue
    $ipBlocks = $records | Where-Object {{ $_.HostName -like "ip-block-*" }}
    if ($ipBlocks) {{
        $ipBlocks | ForEach-Object {{
            $ip = $_.HostName -replace "ip-block-", "" -replace "-", "."
            Write-Output "  $ip"
        }}
    }} else {{
        Write-Output "  (nenhum)"
    }}
}} else {{
    Write-Output "  (zona RPZ não existe)"
}}
"""


def list_blocks(dns: DNSClient) -> None:
    out, err, rc = dns.run_ps(_LIST_SCRIPT)
    print(out)
    if err.strip():
        print(f"  (avisos: {err[:200]})", file=sys.stderr)


# ---------------------------------------------------------------------------
# Status do servidor DNS
# ---------------------------------------------------------------------------

def status(dns: DNSClient) -> None:
    out = dns.check("""
        $info = Get-DnsServer -ErrorAction SilentlyContinue
        $zones = (Get-DnsServerZone).Count
        $hostname = $env:COMPUTERNAME
        Write-Output "Servidor: $hostname"
        Write-Output "Zonas: $zones"
        if ($info.ServerSetting) {
            Write-Output "Version: $($info.ServerSetting.MajorVersion).$($info.ServerSetting.MinorVersion)"
        }
    """, "status")
    print(out)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def read_list_values(list_path: Path) -> list[str]:
    """
    Lê arquivo de lista (um valor por linha).
    Ignora linhas vazias e comentários (# — inclusive inline).
    """
    values = []
    for line in list_path.read_text(encoding="utf-8-sig").splitlines():
        line = line.split("#")[0].strip()
        if line:
            values.append(line)
    return values


def run_list(list_path: Path, action: str, ioc_type: str, dns: DNSClient,
             exception_set: set[str] | None = None) -> int:
    """
    Processa arquivo de lista (um valor por linha).
    Ação e tipo definidos pelos argumentos CLI — aplicados a todos os itens.
    exception_set: domínios/IPs a ignorar.
    """
    values = read_list_values(list_path)
    if not values:
        print(f"AVISO: lista vazia ou sem entradas válidas em {list_path}")
        return 0

    if action not in ("block", "unblock") or ioc_type not in ("domain", "ip"):
        print(f"ERRO: combinação action={action} type={ioc_type} não suportada. "
              "Use block/unblock com domain/ip", file=sys.stderr)
        return 2

    exc = exception_set or set()
    values_filtered = [v for v in values if v not in exc]
    skip_exc = len(values) - len(values_filtered)
    total = len(values)
    print(f"Processando {total} itens de '{list_path.name}' [action={action} type={ioc_type}]"
          + (f" | {len(exc)} exceções" if exc else ""))

    # Batch para bloqueio de domínios (muito mais eficiente via bastion)
    if action == "block" and ioc_type == "domain" and values_filtered:
        r = block_domains_batch(dns, values_filtered)
        print(f"\nLista concluída: {total} itens | {r['ok']} ok | {skip_exc} exceções | {r['skip']} já existentes | {r['fail']} falhas")
        return 1 if r['fail'] else 0

    if action == "block" and ioc_type == "domain":
        ensure_rpz_zone(dns)

    ok = fail = 0
    skip = skip_exc

    for i, ioc in enumerate(values_filtered, 1):
        try:
            if action == "block":
                if ioc_type == "domain":
                    block_domain(dns, ioc)
                else:
                    block_ip(dns, ioc)
            else:
                if ioc_type == "domain":
                    unblock_domain(dns, ioc)
                else:
                    unblock_ip(dns, ioc)
            ok += 1
        except Exception as e:
            print(f"[FALHA] #{i} {ioc}: {e}", file=sys.stderr)
            fail += 1

    print(f"\nLista concluída: {total} itens | {ok} ok | {skip} exceções | {fail} falhas")
    return 1 if fail else 0


def run_csv(csv_path: Path, dns: DNSClient) -> int:
    """
    Processa CSV linha a linha.
    Formato: action,type,ioc
    Linhas iniciadas com # são ignoradas.
    """
    total = ok = fail = 0
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(
            (ln for ln in f if not ln.strip().startswith("#"))
        )
        for row in reader:
            row = {k.strip(): (v.strip() if v else "") for k, v in row.items() if k}
            total += 1
            action   = row.get("action", "").lower()
            ioc_type = row.get("type",   "").lower()
            ioc      = row.get("ioc",    "").strip()

            if not action or not ioc_type or not ioc:
                print(f"[SKIP] linha {total}: campos obrigatórios faltando → {row}")
                fail += 1
                continue
            try:
                if action == "block":
                    if ioc_type == "domain":
                        ensure_rpz_zone(dns)
                        block_domain(dns, ioc)
                    elif ioc_type == "ip":
                        block_ip(dns, ioc)
                    else:
                        raise ValueError(f"type '{ioc_type}' não suportado")
                elif action == "unblock":
                    if ioc_type == "domain":
                        unblock_domain(dns, ioc)
                    elif ioc_type == "ip":
                        unblock_ip(dns, ioc)
                    else:
                        raise ValueError(f"type '{ioc_type}' não suportado")
                else:
                    raise ValueError(f"action '{action}' não suportada no modo CSV")
                ok += 1
            except Exception as e:
                print(f"[FALHA] linha {total} ({action}/{ioc_type}/{ioc}): {e}",
                      file=sys.stderr)
                fail += 1

    print(f"\nCSV concluído: {total} linhas | {ok} ok | {fail} falhas")
    return 1 if fail else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="N2 Playbook — DNS Server Block (Windows DNS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python3 pb_dns_block.py --action block   --type domain --ioc malicious.com
  python3 pb_dns_block.py --action block   --type domain --ioc "*.evil.com"
  python3 pb_dns_block.py --action block   --type ip     --ioc 1.2.3.4
  python3 pb_dns_block.py --action unblock --type domain --ioc malicious.com
  python3 pb_dns_block.py --action flush
  python3 pb_dns_block.py --action flush   --type domain --ioc malicious.com
  python3 pb_dns_block.py --action list
  python3 pb_dns_block.py --action status

NOTA: Bloqueio de IP via DNS tem efeito limitado.
      Para bloqueio efetivo de IP, use pb_fw_fortigate.py.

Modo lista (--list): ação/tipo fixos, valores lidos do arquivo (1 por linha, # = comentário)
  python3 pb_dns_block.py --action block   --type domain --list lists/social_media_domains.txt
  python3 pb_dns_block.py --action block   --type domain --list lists/proxy_bypass_domains.txt
  python3 pb_dns_block.py --action block   --type domain --list lists/paste_sites_domains.txt
  python3 pb_dns_block.py --action unblock --type domain --list dominios_liberar.txt

Modo CSV (--csv): cada linha pode ter action/type/ioc diferentes
  python3 pb_dns_block.py --csv lists/examples/dns_block.csv
""")
    p.add_argument("--action", required=True,
                   choices=["block", "unblock", "flush", "list", "status", "block-asn"])
    p.add_argument("--type",   choices=["domain", "ip"],
                   help="Tipo do IOC (obrigatório para block/unblock)")
    p.add_argument("--ioc",    help="Valor do IOC")
    p.add_argument("--env",    default=None, help="Caminho alternativo para .env")
    p.add_argument("--dns-ip", default=None, help="IP do servidor DNS (sobrescreve .env)")
    p.add_argument("--transport", default=None, choices=["ntlm", "kerberos", "basic"],
                   help="Transporte WinRM (padrão: ntlm)")
    p.add_argument("--csv",  default=None, metavar="ARQUIVO.CSV",
                   help="Arquivo CSV com múltiplos IOCs/ações (colunas: action,type,ioc)")
    p.add_argument("--list", default=None, metavar="ARQUIVO.TXT",
                   help="Arquivo de lista (um valor por linha). Requer --action e --type. "
                        "Linhas com # são ignoradas. Ideal para aplicar lists/ de domínios.")
    p.add_argument("--exception-list", default=None, metavar="ARQUIVO.TXT",
                   help="Lista de domínios/IPs a IGNORAR ao processar --list ou --csv.")
    return p


def main() -> int:
    args = build_parser().parse_args()

    env_path = Path(args.env) if args.env else Path(__file__).parent / ".env"
    if not env_path.is_file():
        env_path = Path(__file__).parent.parent.parent / "laboratory" / "poc-harpia" / ".env"
    env = load_env(env_path)

    dns_ip    = args.dns_ip or env.get("VM_DNS_IP") or env.get("VM_DC01_IP", "")
    winrm_user = env.get("DOMAIN_ADMIN", "") or env.get("VM_DC01_DOMAIN_USER", "")
    winrm_pass = env.get("DOMAIN_ADMIN_PASSWORD", "") or env.get("VM_DC01_DOMAIN_PASS", "")
    transport  = args.transport or env.get("WINRM_TRANSPORT", "ntlm")
    winrm_port = int(env.get("WINRM_PORT", "5985"))

    if not dns_ip or not winrm_user or not winrm_pass:
        print("ERRO: VM_DC01_IP (ou VM_DNS_IP), DOMAIN_ADMIN e DOMAIN_ADMIN_PASSWORD precisam estar no .env",
              file=sys.stderr)
        return 2

    # Bastion SSH se DNS_USE_BASTION=true (para DCs sem acesso externo via WinRM)
    tunnel: BastionTunnel | None = None
    use_bastion = env.get("DNS_USE_BASTION", "false").lower() in ("true", "1", "yes")

    if use_bastion:
        bastion_ip   = env.get("BASTION_IP", "")
        bastion_user = env.get("BASTION_USER", "")
        bastion_pass = env.get("BASTION_PASS", "")
        bastion_port = int(env.get("BASTION_SSH_PORT", "22"))
        if not bastion_ip or not bastion_user:
            print("ERRO: BASTION_IP e BASTION_USER precisam estar no .env quando DNS_USE_BASTION=true",
                  file=sys.stderr)
            return 2
        try:
            dns = BastionDNSClient(
                bastion_ip, bastion_user, bastion_pass,
                dns_ip, winrm_user, winrm_pass,
                bastion_port=bastion_port,
            )
            dns.connect()
        except Exception as e:
            print(f"ERRO ao conectar via bastion SSH: {e}", file=sys.stderr)
            return 1
    else:
        try:
            dns = DNSClient(dns_ip, winrm_user, winrm_pass, transport=transport, port=winrm_port)
        except (WinRMError, WinRMTransportError, Exception) as e:
            print(f"ERRO ao conectar via WinRM ({dns_ip}): {e}", file=sys.stderr)
            return 1

    # Carrega lista de exceções
    exception_set: set[str] = set()
    if getattr(args, "exception_list", None):
        exc_path = Path(args.exception_list)
        if not exc_path.is_file():
            print(f"ERRO: --exception-list não encontrado: {exc_path}", file=sys.stderr)
            return 2
        exception_set = set(read_list_values(exc_path))
        print(f"Exceções carregadas: {len(exception_set)} itens de '{exc_path.name}'")

    try:
        if args.csv:
            csv_path = Path(args.csv)
            if not csv_path.is_file():
                print(f"ERRO: arquivo CSV não encontrado: {csv_path}", file=sys.stderr)
                return 2
            return run_csv(csv_path, dns)

        if args.list:
            list_path = Path(args.list)
            if not list_path.is_file():
                print(f"ERRO: arquivo de lista não encontrado: {list_path}", file=sys.stderr)
                return 2
            if not args.action or not args.type:
                print("ERRO: --action e --type são obrigatórios com --list", file=sys.stderr)
                return 2
            return run_list(list_path, args.action, args.type, dns, exception_set)

        if args.action == "status":
            status(dns)
            return 0

        if args.action == "list":
            list_blocks(dns)
            return 0

        if args.action == "flush":
            flush_cache(dns, args.ioc)
            return 0

        if args.action == "block-asn":
            # Bloqueia prefixos CIDR de ASNs de redes sociais via RPZ IP triggers
            import json as _json
            asn_json = Path(__file__).parent / "lists" / "social_media_asn_data.json"
            if not asn_json.is_file():
                print(f"ERRO: {asn_json} não encontrado. Execute coleta de ASNs primeiro.", file=sys.stderr)
                return 2
            with open(asn_json, encoding="utf-8") as f:
                asn_data = _json.load(f)

            all_prefixes_v4 = []
            all_prefixes_v6 = []
            for platform, info in asn_data.items():
                v4 = info.get("v4", [])
                v6 = info.get("v6", [])
                all_prefixes_v4.extend(v4)
                all_prefixes_v6.extend(v6)

            # Remove duplicatas
            all_prefixes_v4 = sorted(set(all_prefixes_v4))
            all_prefixes_v6 = sorted(set(all_prefixes_v6))

            print(f"[block-asn] Total: {len(all_prefixes_v4)} prefixos IPv4 | {len(all_prefixes_v6)} IPv6")
            print(f"[block-asn] Plataformas: {', '.join(asn_data.keys())}")
            print()

            # Bloqueia IPv4 primeiro
            print(f"=== Bloqueando {len(all_prefixes_v4)} prefixos IPv4 via RPZ IP triggers ===")
            r4 = block_prefixes_batch(dns, all_prefixes_v4, chunk_size=50)
            print(f"IPv4: {r4['ok']} ok | {r4['skip']} já existentes | {r4['fail']} falhas")

            # IPv6 (skip se sem suporte)
            if all_prefixes_v6:
                print(f"\n=== Bloqueando {len(all_prefixes_v6)} prefixos IPv6 via RPZ IP triggers ===")
                r6 = block_prefixes_batch(dns, all_prefixes_v6, chunk_size=50)
                print(f"IPv6: {r6['ok']} ok | {r6['skip']} já existentes | {r6['fail']} falhas")
            else:
                r6 = {"ok": 0, "skip": 0, "fail": 0, "total": 0}

            total_fail = r4["fail"] + r6["fail"]
            print(f"\n[block-asn] Concluído: {r4['ok']+r6['ok']} ok | {r4['skip']+r6['skip']} skip | {total_fail} fail")
            return 1 if total_fail else 0

        if not args.type or not args.ioc:
            print("ERRO: --type e --ioc são obrigatórios para block/unblock", file=sys.stderr)
            return 2

        ioc = args.ioc.strip()

        if args.action == "block":
            if args.type == "domain":
                ensure_rpz_zone(dns)
                block_domain(dns, ioc)
            elif args.type == "ip":
                block_ip(dns, ioc)

        elif args.action == "unblock":
            if args.type == "domain":
                unblock_domain(dns, ioc)
            elif args.type == "ip":
                unblock_ip(dns, ioc)

        return 0

    except (WinRMError, WinRMTransportError) as e:
        print(f"ERRO WinRM: {e}", file=sys.stderr)
        return 1
    except RuntimeError as e:
        print(f"ERRO: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERRO inesperado: {e}", file=sys.stderr)
        return 1
    finally:
        if tunnel:
            tunnel.stop()
        if use_bastion and isinstance(dns, BastionDNSClient):
            dns.close()


if __name__ == "__main__":
    raise SystemExit(main())
