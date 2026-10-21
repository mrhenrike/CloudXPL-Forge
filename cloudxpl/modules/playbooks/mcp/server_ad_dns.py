#!/usr/bin/env python3
"""
MCP Server — Active Directory + DNS Containment
=================================================
Expõe ferramentas de gestão de usuários AD e bloqueio DNS via MCP.
Suporte: Windows DNS (via bastion SSH + WinRM) + Active Directory (via LDAP / WinRM).

Inicie com:
  python server_ad_dns.py
  mcp dev server_ad_dns.py
"""
from __future__ import annotations

import json
import os
import re
import textwrap
import uuid
from pathlib import Path

from mcp.server.fastmcp import FastMCP

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

DC_IP       = ENV.get("VM_DC01_IP",             "10.254.2.243")
DOMAIN      = ENV.get("DOMAIN_NAME",            "safelabs.lab")
AD_USER     = ENV.get("DOMAIN_ADMIN",           ENV.get("VM_DC01_DOMAIN_USER", "Administrator"))
AD_PASS     = ENV.get("DOMAIN_ADMIN_PASSWORD",  ENV.get("VM_DC01_DOMAIN_PASS", ""))
BASTION_IP  = ENV.get("BASTION_IP",             ENV.get("BASTION_IP_PUBLIC", "204.216.179.29"))
BASTION_USER= ENV.get("BASTION_USER",           "opc")
BASTION_PASS= ENV.get("BASTION_PASS",           "")
# DNS_USE_BASTION=false → use WinRM directly (HIN has direct access to DC)
USE_BASTION = ENV.get("DNS_USE_BASTION", "true").lower() in ("true", "1", "yes")
WINRM_PORT  = int(ENV.get("WINRM_PORT", "5985"))
WINRM_TRNS  = ENV.get("WINRM_TRANSPORT", "ntlm")
RPZ_ZONE    = "rpz.safelabs"
SINKHOLE    = "0.0.0.0"
IOC_LISTS_DIR = Path(__file__).parent / "ioc_lists"


# ---------------------------------------------------------------------------
# AD client — LDAP direto
# ---------------------------------------------------------------------------

def _get_ad_client():
    try:
        import ldap3
        from ldap3 import Server, Connection, ALL, SUBTREE, NTLM, SIMPLE
    except ImportError:
        raise RuntimeError("pip install ldap3")

    server = ldap3.Server(DC_IP, port=389, get_info=ALL)
    # Use SIMPLE auth UPN (user@domain) — avoids NTLM/MD4 dependency on Oracle Linux
    # NTLM requires MD4 which is disabled in modern OpenSSL
    bind_formats = [
        (f"{AD_USER}@{DOMAIN}", ldap3.SIMPLE),    # UPN — works on all platforms
        (AD_USER,               ldap3.SIMPLE),     # plain SAM fallback
    ]
    last_err = None
    for bind_user, auth_type in bind_formats:
        try:
            conn = ldap3.Connection(
                server,
                user=bind_user,
                password=AD_PASS,
                authentication=auth_type,
                auto_bind=True,
            )
            return conn
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"LDAP bind failed (tried SIMPLE UPN + NTLM): {last_err}")


def _find_user(sam: str) -> dict | None:
    try:
        import ldap3
        from ldap3 import SUBTREE
        conn    = _get_ad_client()
        base_dn = "DC=" + DOMAIN.replace(".", ",DC=")
        esc = ldap3.utils.conv.escape_filter_chars(sam)
        conn.search(
            base_dn,
            f"(|(sAMAccountName={esc})(userPrincipalName={esc}@{DOMAIN})(userPrincipalName={esc}))",
            SUBTREE,
            attributes=["*"],
        )
        if not conn.entries:
            return None
        e    = conn.entries[0]
        raw  = e.entry_attributes_as_dict  # normalized lowercase dict

        def _v(key, default=None):
            """Get attribute value from entry, case-insensitive."""
            # Try direct attribute access first
            key_lower = key.lower()
            # ldap3 stores attributes case-insensitively
            val = raw.get(key_lower, raw.get(key, [default]))
            if isinstance(val, list):
                val = val[0] if val else default
            return val if val is not None else default

        def _int_v(key):
            v = _v(key, 0)
            if v is None or v == []:
                return 0
            try:
                return int(v)
            except (ValueError, TypeError):
                return 0

        def _str_v(key):
            v = _v(key, "")
            return str(v) if v else ""

        def _list_v(key):
            v = raw.get(key.lower(), raw.get(key, []))
            if not v:
                return []
            if isinstance(v, list):
                return [str(x) for x in v]
            return [str(v)]

        uac = _int_v("userAccountControl")
        dn  = e.entry_dn  # always available in ldap3

        return {
            "dn":          dn or "",
            "sam":         _str_v("sAMAccountName"),
            "displayName": _str_v("displayName"),
            "mail":        _str_v("mail"),
            "upn":         _str_v("userPrincipalName"),
            "uac":         uac,
            "disabled":    bool(uac & 0x0002),
            "lockout":     bool(uac & 0x0010),
            "lockoutTime": _int_v("lockoutTime"),
            "badPwdCount": _int_v("badPwdCount"),
            "groups":      _list_v("memberOf"),
        }
    except Exception as e:
        raise RuntimeError(f"LDAP error: {e}")


def _modify_user(dn: str, changes: dict) -> None:
    import ldap3
    from ldap3 import MODIFY_REPLACE
    conn = _get_ad_client()
    conn.modify(dn, {k: [(MODIFY_REPLACE, [v])] for k, v in changes.items()})
    if conn.result["result"] != 0:
        raise RuntimeError(f"LDAP modify failed: {conn.result['description']}")


def _parse_user_input(user: str) -> str:
    """Extrai sAMAccountName de user@domain ou DOMAIN\\user ou user."""
    if "\\" in user:
        return user.split("\\", 1)[1].strip()
    if "@" in user:
        return user.split("@", 1)[0].strip()
    return user.strip()


# ---------------------------------------------------------------------------
# DNS client — via bastion SSH → DC01 WinRM / PowerShell
# ---------------------------------------------------------------------------

def _run_ps_on_dc(script: str, timeout: int = 60) -> tuple[str, str, int]:
    """Executa PowerShell no DC via WinRM direto (HIN) ou SSH bastion (externo)."""
    if not USE_BASTION:
        return _run_ps_winrm_direct(script, timeout)
    try:
        import paramiko
    except ImportError:
        raise RuntimeError("pip install paramiko")

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(
        BASTION_IP, port=22, username=BASTION_USER, password=BASTION_PASS,
        timeout=20, look_for_keys=False, allow_agent=False,
    )
    sftp     = ssh.open_sftp()
    tmp_name = f"sl_mcp_{uuid.uuid4().hex[:8]}.ps1"
    # DC-side script
    sftp_path = f"/C:/Windows/Temp/{tmp_name}"
    with sftp.open(sftp_path, "w") as f:
        f.write(script)
    # Wrapper on bastion
    wrap_name = f"sl_mcp_wrap_{uuid.uuid4().hex[:8]}.ps1"
    wrap_path = f"/C:/Windows/Temp/{wrap_name}"
    wrapper = (
        f"$pass = ConvertTo-SecureString '{AD_PASS.replace(chr(39), chr(39)+chr(39))}'"
        f" -AsPlainText -Force\n"
        f"$cred = New-Object System.Management.Automation.PSCredential('{AD_USER}', $pass)\n"
        f"$sb = [ScriptBlock]::Create((Get-Content -Path 'C:\\Windows\\Temp\\{tmp_name}' -Raw))\n"
        f"Invoke-Command -ComputerName {DC_IP} -Credential $cred "
        f"-Authentication Negotiate -ScriptBlock $sb\n"
        f"Remove-Item 'C:\\Windows\\Temp\\{tmp_name}' -Force -EA SilentlyContinue\n"
    )
    with sftp.open(wrap_path, "w") as f:
        f.write(wrapper)
    sftp.close()

    pwsh = r"C:\Program Files\PowerShell\7\pwsh.exe"
    stdin, stdout, stderr = ssh.exec_command(
        f'"{pwsh}" -NoProfile -NonInteractive -File "C:\\Windows\\Temp\\{wrap_name}"',
        timeout=timeout,
    )
    out = stdout.read().decode("utf-8", errors="replace").strip()
    err = stderr.read().decode("utf-8", errors="replace").strip()
    rc  = stdout.channel.recv_exit_status()
    out = re.sub(r'\x1b\[[0-9;]*m', '', out)
    err = re.sub(r'\x1b\[[0-9;]*m', '', err)
    ssh.close()
    return out, err, rc


def _run_ps_winrm_direct(script: str, timeout: int = 60) -> tuple[str, str, int]:
    """
    Executa PowerShell diretamente no DC via WinRM (sem bastion). Usado da HIN.
    Usa basic auth + EncodedCommand para evitar dependência de NTLM/MD4 e
    problemas com pwsh vs powershell.exe.
    Requer: Set-Item WSMan:\\localhost\\Service\\Auth\\Basic $true no DC.
    Fallback: NTLM via ntlm-auth (se disponível).
    """
    try:
        import winrm as _winrm
    except ImportError:
        raise RuntimeError("pip install pywinrm")
    import re as _re, base64

    # Encode script as UTF-16LE base64 for -EncodedCommand (avoids quoting issues)
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")

    # WinRM on DC may have pwsh as default shell — use cmd.exe to launch powershell.exe explicitly
    # cmd.exe /c "powershell.exe -EncodedCommand <b64>" bypasses the default shell issue
    admin  = f"{DOMAIN}\\{AD_USER}" if "\\" not in AD_USER and "@" not in AD_USER else AD_USER
    transport = WINRM_TRNS if WINRM_TRNS != "ntlm" else "ntlm"

    try:
        from winrm import protocol as _proto
        proto = _proto.Protocol(
            endpoint=f"http://{DC_IP}:{WINRM_PORT}/wsman",
            transport=transport,
            username=admin,
            password=AD_PASS,
            server_cert_validation="ignore",
            read_timeout_sec=timeout,
            operation_timeout_sec=max(timeout - 5, 10),
        )
        shell_id = proto.open_shell()
        # Use full path to Windows PowerShell 5.x (not pwsh/PowerShell 7)
        # DC may have pwsh shimmed as default — explicit path avoids this
        ps_path  = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        cmd_id   = proto.run_command(
            shell_id, "cmd.exe",
            ["/c", f"{ps_path} -NonInteractive -NoProfile -EncodedCommand {encoded}"]
        )
        std_out, std_err, rc = proto.get_command_output(shell_id, cmd_id)
        proto.cleanup_command(shell_id, cmd_id)
        proto.close_shell(shell_id)
        out = std_out.decode("utf-8", errors="replace").strip()
        err = std_err.decode("utf-8", errors="replace").strip()
        out = _re.sub(r'\x1b\[[0-9;]*m', '', out)
        err = _re.sub(r'\x1b\[[0-9;]*m', '', err)
        return out, err, rc
    except Exception as e:
        raise RuntimeError(f"WinRM direct failed: {e}")


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
    "safelabs-ad-dns",
    instructions=(
        "Active Directory user containment + Windows DNS sinkhole tools. "
        "AD operations: disable, enable, reset-password, unlock, status. "
        "DNS operations: block/unblock domain via RPZ sinkhole, flush cache. "
        "Only safe, reversible operations. Never delete users or OUs."
    ),
)

# ============================================================
# AD Tools
# ============================================================

@mcp.tool()
def ad_user_status(username: str) -> str:
    """
    Retorna o status de um usuário no Active Directory.
    Aceita: sAMAccountName, UPN (user@domain) ou DOMAIN\\user.

    Args:
        username: Identificador do usuário
    """
    try:
        sam = _parse_user_input(username)
        u   = _find_user(sam)
        if not u:
            return json.dumps({"found": False, "sam": sam, "domain": DOMAIN})
        return json.dumps({
            "found":       True,
            "sam":         u["sam"],
            "displayName": u["displayName"],
            "upn":         u["upn"],
            "mail":        u["mail"],
            "disabled":    u["disabled"],
            "lockout":     u["lockout"],
            "badPwdCount": u["badPwdCount"],
            "groups_count":len(u["groups"]),
            "groups":      u["groups"][:10],
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return f"[ERRO] {e}"


@mcp.tool()
def ad_disable_user(username: str, reason: str = "SafeLabs MCP — incident response") -> str:
    """
    Desativa uma conta no Active Directory (userAccountControl → DISABLED).
    Operação reversível com ad_enable_user. O usuário não conseguirá mais logar.
    ⚠ Confirme o username antes. Use ad_user_status para verificar primeiro.

    Args:
        username: sAMAccountName, UPN ou DOMAIN\\user
        reason: Motivo da desativação (para auditoria)
    """
    try:
        sam = _parse_user_input(username)
        u   = _find_user(sam)
        if not u:
            return json.dumps({"ok": False, "error": f"Usuário '{sam}' não encontrado no domínio {DOMAIN}"})
        if u["disabled"]:
            return json.dumps({"ok": True, "already": True, "message": f"Conta '{sam}' já está desativada"})
        new_uac = u["uac"] | 0x0002
        _modify_user(u["dn"], {"userAccountControl": new_uac})
        return json.dumps({
            "ok":       True,
            "action":   "disabled",
            "sam":      sam,
            "dn":       u["dn"],
            "uac_from": u["uac"],
            "uac_to":   new_uac,
            "reason":   reason,
        }, ensure_ascii=False)
    except Exception as e:
        return f"[ERRO] disable({username}): {e}"


@mcp.tool()
def ad_enable_user(username: str) -> str:
    """
    Reativa uma conta no Active Directory.

    Args:
        username: sAMAccountName, UPN ou DOMAIN\\user
    """
    try:
        sam = _parse_user_input(username)
        u   = _find_user(sam)
        if not u:
            return json.dumps({"ok": False, "error": f"Usuário '{sam}' não encontrado"})
        if not u["disabled"]:
            return json.dumps({"ok": True, "already": True, "message": f"Conta '{sam}' já está ativa"})
        new_uac = u["uac"] & ~0x0002
        _modify_user(u["dn"], {"userAccountControl": new_uac})
        return json.dumps({"ok": True, "action": "enabled", "sam": sam})
    except Exception as e:
        return f"[ERRO] enable({username}): {e}"


@mcp.tool()
def ad_force_password_reset(username: str) -> str:
    """
    Força o usuário a redefinir a senha no próximo login (pwdLastSet = 0).
    Use quando credenciais foram vazadas mas a conta não precisa ser desativada.

    Args:
        username: sAMAccountName, UPN ou DOMAIN\\user
    """
    try:
        sam = _parse_user_input(username)
        u   = _find_user(sam)
        if not u:
            return json.dumps({"ok": False, "error": f"Usuário '{sam}' não encontrado"})
        _modify_user(u["dn"], {"pwdLastSet": 0})
        return json.dumps({
            "ok":      True,
            "action":  "force_password_reset",
            "sam":     sam,
            "message": "Usuário deverá criar nova senha no próximo login",
        })
    except Exception as e:
        return f"[ERRO] reset_password({username}): {e}"


@mcp.tool()
def ad_unlock_user(username: str) -> str:
    """
    Remove o lockout de uma conta no AD.

    Args:
        username: sAMAccountName, UPN ou DOMAIN\\user
    """
    try:
        sam = _parse_user_input(username)
        u   = _find_user(sam)
        if not u:
            return json.dumps({"ok": False, "error": f"Usuário '{sam}' não encontrado"})
        if u["lockoutTime"] == 0:
            return json.dumps({"ok": True, "already": True, "message": f"Conta '{sam}' não está bloqueada"})
        _modify_user(u["dn"], {"lockoutTime": 0})
        return json.dumps({"ok": True, "action": "unlocked", "sam": sam})
    except Exception as e:
        return f"[ERRO] unlock({username}): {e}"


@mcp.tool()


def ad_list_all_users(include_disabled: bool = False) -> str:
    """Lista usuarios do Active Directory (ativos por default).

    Args:
        include_disabled: Se True, retorna todos (ativos + desabilitados).
    """
    try:
        import ldap3
        from ldap3 import SUBTREE
        conn = _get_ad_client()
        base_dn = "DC=" + DOMAIN.replace(".", ",DC=")
        if include_disabled:
            search_filter = "(objectClass=user)"
        else:
            # Nao eh conta de computador e NAO tem flag userAccountControl desabilitado
            search_filter = "(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(objectClass=computer)))"
        conn.search(
            base_dn,
            search_filter,
            SUBTREE,
            attributes=["sAMAccountName", "displayName", "mail",
                        "userAccountControl", "lastLogonTimestamp",
                        "whenCreated", "memberOf"],
        )
        users = []
        for entry in conn.entries:
            uac = int(getattr(entry, "userAccountControl", 512).value or 512)
            enabled = not bool(uac & 2)
            last_logon = None
            try:
                ll = getattr(entry, "lastLogonTimestamp", None)
                if ll and ll.value:
                    last_logon = str(ll.value)[:19]
            except Exception:
                pass
            users.append({
                "sam": str(entry.sAMAccountName),
                "name": str(getattr(entry, "displayName", "") or ""),
                "mail": str(getattr(entry, "mail", "") or ""),
                "enabled": enabled,
                "last_logon": last_logon,
            })
        users.sort(key=lambda u: u["sam"].lower())
        return json.dumps({"count": len(users), "users": users}, ensure_ascii=False)
    except Exception as e:
        return json.dumps({"error": str(e)})


def ad_list_disabled_users() -> str:
    """Lista todas as contas desativadas no Active Directory."""
    try:
        import ldap3
        from ldap3 import SUBTREE
        conn    = _get_ad_client()
        base_dn = "DC=" + DOMAIN.replace(".", ",DC=")
        conn.search(
            base_dn,
            "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
            SUBTREE,
            attributes=["sAMAccountName","displayName","mail"],
        )
        users = [
            {"sam": str(e.sAMAccountName), "name": str(e.displayName), "mail": str(e.mail)}
            for e in conn.entries
        ]
        return json.dumps({"count": len(users), "disabled_users": users}, ensure_ascii=False, indent=2)
    except Exception as e:
        return f"[ERRO] {e}"


@mcp.tool()
def ad_containment_from_leak(usernames: list[str], action: str = "reset-password") -> str:
    """
    Aplica ação de contenção em lote para lista de usuários de um vazamento.
    Ideal para resposta rápida a phishing/credential dump.

    Args:
        usernames: Lista de usernames/UPNs/emails
        action: 'disable' | 'reset-password' | 'unlock' | 'status'
    """
    results = []
    for user in usernames:
        try:
            sam = _parse_user_input(user)
            u   = _find_user(sam)
            if not u:
                results.append({"user": user, "found": False})
                continue

            if action == "disable":
                if u["disabled"]:
                    results.append({"user": sam, "action": "skip", "reason": "already_disabled"})
                else:
                    new_uac = u["uac"] | 0x0002
                    _modify_user(u["dn"], {"userAccountControl": new_uac})
                    results.append({"user": sam, "action": "disabled", "ok": True})

            elif action == "reset-password":
                _modify_user(u["dn"], {"pwdLastSet": 0})
                results.append({"user": sam, "action": "password_reset", "ok": True})

            elif action == "unlock":
                if u["lockoutTime"] == 0:
                    results.append({"user": sam, "action": "skip", "reason": "not_locked"})
                else:
                    _modify_user(u["dn"], {"lockoutTime": 0})
                    results.append({"user": sam, "action": "unlocked", "ok": True})

            elif action == "status":
                results.append({
                    "user":      sam,
                    "found":     True,
                    "disabled":  u["disabled"],
                    "lockout":   u["lockout"],
                    "badPwd":    u["badPwdCount"],
                    "mail":      u["mail"],
                })
        except Exception as e:
            results.append({"user": user, "error": str(e)})

    ok   = sum(1 for r in results if r.get("ok") or r.get("found", False))
    return json.dumps({"total": len(usernames), "processed": ok, "results": results},
                      ensure_ascii=False, indent=2)


# ============================================================
# DNS Tools
# ============================================================

@mcp.tool()
def dns_status() -> str:
    """Verifica conectividade com o servidor DNS (DC01) e retorna informações básicas."""
    script = """
$info = Get-DnsServer -ErrorAction SilentlyContinue
$zones = (Get-DnsServerZone | Measure-Object).Count
Write-Output "DC=$env:COMPUTERNAME|zones=$zones"
"""
    try:
        out, err, rc = _run_ps_on_dc(script, timeout=30)
        clean = "\n".join(l for l in out.splitlines() if "WARNING:" not in l).strip()
        return json.dumps({"ok": rc == 0, "output": clean, "dc_ip": DC_IP, "domain": DOMAIN})
    except Exception as e:
        return json.dumps({"ok": False, "error": str(e), "dc_ip": DC_IP, "domain": DOMAIN})


@mcp.tool()
def dns_block_domain(domain: str) -> str:
    """
    Bloqueia resolução de um domínio no Windows DNS via zona RPZ sinkhole (0.0.0.0).
    Afeta todos os clientes usando o DC01 como DNS server.

    Args:
        domain: Domínio a bloquear (ex: 'malicious.com', 'sumbur.net')
    """
    domain = domain.lstrip("*.")
    script = textwrap.dedent(f"""
        $d = '{domain}'
        $sinkhole = '{SINKHOLE}'
        $zoneExists = Get-DnsServerZone -Name $d -ErrorAction SilentlyContinue
        if (-not $zoneExists) {{
            Add-DnsServerPrimaryZone -Name $d -ZoneFile "$d.dns" -DynamicUpdate None
            Write-Output "CREATED_ZONE:$d"
        }}
        $recApex = Get-DnsServerResourceRecord -ZoneName $d -RRType A -Name "@" -EA SilentlyContinue
        if (-not $recApex) {{
            Add-DnsServerResourceRecord -ZoneName $d -A -Name "@" -IPv4Address $sinkhole
            Write-Output "SINKHOLE_A"
        }}
        $recWild = Get-DnsServerResourceRecord -ZoneName $d -RRType A -Name "*" -EA SilentlyContinue
        if (-not $recWild) {{
            Add-DnsServerResourceRecord -ZoneName $d -A -Name "*" -IPv4Address $sinkhole
            Write-Output "SINKHOLE_WILD"
        }}
        Write-Output "OK:$d"
    """)
    try:
        out, err, rc = _run_ps_on_dc(script)
        return json.dumps({"ok": rc == 0 and "OK:" in out, "domain": domain,
                           "output": out.encode('ascii', errors='replace').decode('ascii')})
    except Exception as e:
        return json.dumps({"ok": False, "domain": domain, "error": str(e)})


@mcp.tool()
def dns_unblock_domain(domain: str) -> str:
    """
    Remove o bloqueio de resolução de um domínio (deleta zona de sinkhole).

    Args:
        domain: Domínio a desbloquear
    """
    domain = domain.lstrip("*.")
    script = textwrap.dedent(f"""
        $d = '{domain}'
        $zoneExists = Get-DnsServerZone -Name $d -ErrorAction SilentlyContinue
        if ($zoneExists) {{
            Remove-DnsServerZone -Name $d -Force
            Write-Output "REMOVED:$d"
        }} else {{
            Write-Output "NOT_FOUND:$d"
        }}
    """)
    try:
        out, err, rc = _run_ps_on_dc(script)
        found = "REMOVED:" in out
        return json.dumps({"ok": rc == 0, "found": found, "domain": domain, "output": out})
    except Exception as e:
        return f"[ERRO] dns_unblock({domain}): {e}"


@mcp.tool()
def dns_block_domain_list(list_name: str) -> str:
    """
    Bloqueia todos os domínios de um arquivo de lista via DNS sinkhole.

    Args:
        list_name: Nome da lista em ioc_lists/ (ex: 'apt44_domains')
    """
    list_path = IOC_LISTS_DIR / f"{list_name}.txt"
    if not list_path.is_file():
        available = [f.stem for f in IOC_LISTS_DIR.glob("*.txt")]
        return f"[ERRO] Lista '{list_name}' não encontrada. Disponíveis: {available}"

    domains = _read_list(list_path)
    if not domains:
        return "[AVISO] Lista vazia."

    results = []
    for domain in domains:
        d = domain.lstrip("*.")
        script = textwrap.dedent(f"""
            $d='{d}'; $s='{SINKHOLE}'
            try {{
                if(-not(Get-DnsServerZone -Name $d -EA SilentlyContinue)){{
                    Add-DnsServerPrimaryZone -Name $d -ZoneFile "$d.dns" -DynamicUpdate None -EA Stop
                }}
                if(-not(Get-DnsServerResourceRecord -ZoneName $d -RRType A -Name "@" -EA SilentlyContinue)){{
                    Add-DnsServerResourceRecord -ZoneName $d -A -Name "@" -IPv4Address $s -EA Stop
                }}
                if(-not(Get-DnsServerResourceRecord -ZoneName $d -RRType A -Name "*" -EA SilentlyContinue)){{
                    Add-DnsServerResourceRecord -ZoneName $d -A -Name "*" -IPv4Address $s -EA Stop
                }}
                Write-Output "OK:$d"
            }} catch {{ Write-Output "FAIL:$d:$_" }}
        """)
        try:
            out, _, rc = _run_ps_on_dc(script, timeout=20)
            results.append({"domain": d, "ok": "OK:" in out})
        except Exception as e:
            results.append({"domain": d, "ok": False, "error": str(e)})

    ok   = sum(1 for r in results if r["ok"])
    fail = len(results) - ok
    return json.dumps({
        "list": list_name, "total": len(results), "ok": ok, "fail": fail,
        "results": results,
    }, ensure_ascii=False, indent=2)


@mcp.tool()
def dns_flush_cache(domain: str = "") -> str:
    """
    Limpa o cache DNS do servidor. Útil após bloqueio para forçar resolução imediata.

    Args:
        domain: Domínio específico a limpar (vazio = flush completo)
    """
    if domain:
        script = f"Clear-DnsClientCache -ErrorAction SilentlyContinue; Write-Output 'FLUSH_PARTIAL:{domain}'"
    else:
        script = "Clear-DnsServerCache -Force; Clear-DnsClientCache -EA SilentlyContinue; Write-Output 'FLUSH_COMPLETE'"
    try:
        out, err, rc = _run_ps_on_dc(script, timeout=20)
        return json.dumps({"ok": rc == 0, "output": out})
    except Exception as e:
        return f"[ERRO] flush: {e}"


@mcp.tool()
def dns_list_blocked() -> str:
    """Lista todos os domínios atualmente bloqueados via zonas de sinkhole no DNS."""
    script = textwrap.dedent(f"""
        $sys = @(".",  "localhost", "0.in-addr.arpa", "127.in-addr.arpa",
                 "255.in-addr.arpa", "{RPZ_ZONE}", "TrustAnchors")
        $blocked = Get-DnsServerZone | Where-Object {{
            $z = $_.ZoneName
            ($sys -notcontains $z) -and
            (-not $z.EndsWith(".in-addr.arpa")) -and
            (-not $z.EndsWith(".arpa")) -and
            ($z -notlike "*safelabs*") -and
            ($z -notlike "*{DOMAIN}*")
        }} | Select-Object -ExpandProperty ZoneName
        Write-Output ($blocked -join ",")
    """)
    try:
        out, _, rc = _run_ps_on_dc(script, timeout=30)
        blocked = [d.strip() for d in out.split(",") if d.strip()]
        return json.dumps({"count": len(blocked), "blocked_domains": blocked}, indent=2)
    except Exception as e:
        return f"[ERRO] {e}"


@mcp.tool()
def dns_block_apt44_domains() -> str:
    """
    Bloqueia automaticamente TODOS os domínios C2 conhecidos do APT44 (Sandworm).
    Aplica sinkhole no Windows DNS para: massgrave.link, dontgivefuck.com,
    dontgivedamn.com, kalambur.net, sumbur.net + domínios de payload delivery.
    """
    return dns_block_domain_list("apt44_domains")


@mcp.tool()
def ad_dns_check_certificate_store_modification() -> str:
    """
    Verifica no DC01 se houve modificação recente no Certificate Store do sistema
    (técnica DemiMur do APT44 — injeção de certificado raiz falso).
    Retorna certificados adicionados recentemente ao LocalMachine\\Root.
    """
    script = textwrap.dedent("""
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store(
            "Root","LocalMachine"
        )
        $store.Open("ReadOnly")
        $certs = $store.Certificates | ForEach-Object {
            [PSCustomObject]@{
                Subject    = $_.Subject
                Issuer     = $_.Issuer
                Thumbprint = $_.Thumbprint
                NotBefore  = $_.NotBefore.ToString("yyyy-MM-dd")
                NotAfter   = $_.NotAfter.ToString("yyyy-MM-dd")
                FriendlyName = $_.FriendlyName
            }
        }
        $store.Close()
        # Filtrar certs adicionados recentemente (últimos 90 dias) e não-Microsoft
        $recent = $certs | Where-Object {
            [datetime]$_.NotBefore -gt (Get-Date).AddDays(-90) -and
            $_.Subject -notlike "*Microsoft*" -and
            $_.Subject -notlike "*Windows*" -and
            $_.Issuer -notlike "*Microsoft*"
        }
        Write-Output ($recent | ConvertTo-Json -Depth 3)
    """)
    try:
        out, err, rc = _run_ps_on_dc(script, timeout=30)
        certs = json.loads(out) if out.strip().startswith("[") or out.strip().startswith("{") else []
        if isinstance(certs, dict):
            certs = [certs]
        note = (
            "DemiMur technique: forged root CA injected into LocalMachine\\Root bypasses "
            "signature validation at OS level. Investigate any non-Microsoft cert added recently."
            if certs else "No suspicious recent root certificates found."
        )
        return json.dumps({
            "ok":               rc == 0,
            "suspicious_certs": len(certs),
            "certs":            certs,
            "note":             note,
        }, ensure_ascii=True, indent=2)
    except Exception as e:
        return f"[ERRO] cert_store_check: {e}"


@mcp.tool()
def ad_dns_list_available_lists() -> str:
    """Lista todos os arquivos de IOCs disponíveis na pasta ioc_lists/."""
    lists = []
    for f in sorted(IOC_LISTS_DIR.glob("*.txt")):
        lines = [l.split("#")[0].strip() for l in f.read_text(encoding="utf-8-sig").splitlines()
                 if l.split("#")[0].strip()]
        lists.append(f"  {f.stem} ({len(lines)} entradas)")
    return "Listas disponíveis:\n" + "\n".join(lists) if lists else "Nenhuma lista encontrada"


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

@mcp.resource("ioc://apt44/domains")
def apt44_domains_resource() -> str:
    """Domínios maliciosos do APT44."""
    p = IOC_LISTS_DIR / "apt44_domains.txt"
    return p.read_text(encoding="utf-8") if p.is_file() else "Arquivo não encontrado"


@mcp.resource("ad://domain/info")
def domain_info_resource() -> str:
    """Informações do domínio AD configurado."""
    return json.dumps({"domain": DOMAIN, "dc_ip": DC_IP, "ad_user": AD_USER})


if __name__ == "__main__":
    import sys as _sys
    transport = "stdio"
    port = 8092
    for arg in _sys.argv[1:]:
        if arg == "--sse":
            transport = "sse"
        elif arg.startswith("--port="):
            port = int(arg.split("=")[1])
    if transport == "sse":
        mcp.run(transport="sse", host="0.0.0.0", port=port)
    else:
        mcp.run()
