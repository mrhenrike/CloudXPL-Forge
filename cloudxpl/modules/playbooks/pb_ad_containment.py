#!/usr/bin/env python3
"""
Playbook N2 — Active Directory User Containment
================================================
Gerencia contas de usuário no AD via LDAP para contenção de incidentes.
Operações seguras: só altera userAccountControl, pwdLastSet e lockoutTime.

Uso:
  python3 pb_ad_containment.py --action disable        --user johndoe@safelabs.lab
  python3 pb_ad_containment.py --action enable         --user SAFELABS\\johndoe
  python3 pb_ad_containment.py --action reset-password --user johndoe
  python3 pb_ad_containment.py --action unlock         --user johndoe@safelabs.lab
  python3 pb_ad_containment.py --action status         --user johndoe
  python3 pb_ad_containment.py --action list-disabled
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path

try:
    import ldap3
    from ldap3 import Server, Connection, ALL, MODIFY_REPLACE, SUBTREE
    from ldap3.core.exceptions import LDAPException
except ImportError:
    print("ERRO: ldap3 não instalado. Execute: pip install ldap3", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------------------
# Flags userAccountControl relevantes
# ---------------------------------------------------------------------------
UAC_NORMAL          = 0x0200   # Conta normal ativa
UAC_ACCOUNTDISABLE  = 0x0002   # Conta desativada
UAC_LOCKOUT         = 0x0010   # Conta bloqueada (lockout)
UAC_PASSWD_NOTREQD  = 0x0020
UAC_DONT_EXPIRE_PWD = 0x10000

SAFELABS_PREFIX = "safelabs"   # Para log/auditoria


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
# Parse usuário — aceita user@domain, DOMAIN\user, user
# ---------------------------------------------------------------------------

def parse_user_input(user_input: str) -> tuple[str, str | None]:
    """Retorna (sAMAccountName, domain_ou_None)."""
    user_input = user_input.strip()
    if "\\" in user_input:
        _, sam = user_input.split("\\", 1)
        return sam.strip(), None
    if "@" in user_input:
        sam, _ = user_input.split("@", 1)
        return sam.strip(), None
    return user_input, None


# ---------------------------------------------------------------------------
# AD Client
# ---------------------------------------------------------------------------

class ADClient:
    def __init__(self, dc_ip: str, domain: str, user: str, password: str, port: int = 389, use_ssl: bool = False):
        self.domain = domain
        self.base_dn = "DC=" + domain.replace(".", ",DC=")
        self.bind_user = f"{domain}\\{user}"
        server = Server(dc_ip, port=port, use_ssl=use_ssl, get_info=ALL)
        self.conn = Connection(server, user=self.bind_user, password=password, auto_bind=True)

    def _find_user(self, sam: str) -> dict | None:
        self.conn.search(
            search_base=self.base_dn,
            search_filter=f"(sAMAccountName={ldap3.utils.conv.escape_filter_chars(sam)})",
            search_scope=SUBTREE,
            attributes=[
                "distinguishedName", "sAMAccountName", "userAccountControl",
                "pwdLastSet", "lockoutTime", "displayName", "mail",
                "memberOf", "lastLogonTimestamp", "badPwdCount",
                "userPrincipalName",
            ],
        )
        if not self.conn.entries:
            return None
        entry = self.conn.entries[0]
        return {
            "dn":          str(entry.distinguishedName),
            "sam":         str(entry.sAMAccountName),
            "displayName": str(entry.displayName) if entry.displayName else "",
            "mail":        str(entry.mail) if entry.mail else "",
            "upn":         str(entry.userPrincipalName) if entry.userPrincipalName else "",
            "uac":         int(entry.userAccountControl) if entry.userAccountControl else 0,
            "pwdLastSet":  int(entry.pwdLastSet) if entry.pwdLastSet else 0,
            "lockoutTime": int(entry.lockoutTime) if entry.lockoutTime else 0,
            "badPwdCount": int(entry.badPwdCount) if entry.badPwdCount else 0,
            "memberOf":    [str(g) for g in entry.memberOf] if entry.memberOf else [],
        }

    def _modify(self, dn: str, changes: dict) -> bool:
        self.conn.modify(dn, changes)
        if self.conn.result["result"] == 0:
            return True
        raise LDAPException(f"LDAP modify falhou: {self.conn.result['description']} — {self.conn.result.get('message','')}")

    # --- Ações ---

    def get_status(self, sam: str) -> dict | None:
        return self._find_user(sam)

    def disable_user(self, sam: str) -> dict:
        u = self._find_user(sam)
        if not u:
            return {"ok": False, "error": "Usuário não encontrado"}
        uac = u["uac"]
        new_uac = uac | UAC_ACCOUNTDISABLE
        if uac == new_uac:
            return {"ok": True, "already": True, "message": "Conta já está desativada"}
        self._modify(u["dn"], {"userAccountControl": [(MODIFY_REPLACE, [new_uac])]})
        return {"ok": True, "dn": u["dn"], "uac_before": uac, "uac_after": new_uac}

    def enable_user(self, sam: str) -> dict:
        u = self._find_user(sam)
        if not u:
            return {"ok": False, "error": "Usuário não encontrado"}
        uac = u["uac"]
        new_uac = uac & ~UAC_ACCOUNTDISABLE
        if uac == new_uac:
            return {"ok": True, "already": True, "message": "Conta já está ativa"}
        self._modify(u["dn"], {"userAccountControl": [(MODIFY_REPLACE, [new_uac])]})
        return {"ok": True, "dn": u["dn"], "uac_before": uac, "uac_after": new_uac}

    def force_password_reset(self, sam: str) -> dict:
        """Força o usuário a redefinir senha no próximo login (pwdLastSet=0)."""
        u = self._find_user(sam)
        if not u:
            return {"ok": False, "error": "Usuário não encontrado"}
        self._modify(u["dn"], {"pwdLastSet": [(MODIFY_REPLACE, [0])]})
        return {"ok": True, "dn": u["dn"], "message": "Redefinição de senha obrigatória no próximo login"}

    def unlock_user(self, sam: str) -> dict:
        """Remove lockout da conta."""
        u = self._find_user(sam)
        if not u:
            return {"ok": False, "error": "Usuário não encontrado"}
        if u["lockoutTime"] == 0:
            return {"ok": True, "already": True, "message": "Conta não está bloqueada (lockout)"}
        self._modify(u["dn"], {"lockoutTime": [(MODIFY_REPLACE, [0])]})
        return {"ok": True, "dn": u["dn"], "message": "Lockout removido"}

    def list_disabled(self) -> list[dict]:
        """Lista todas as contas desativadas no domínio."""
        self.conn.search(
            search_base=self.base_dn,
            search_filter="(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))",
            search_scope=SUBTREE,
            attributes=["sAMAccountName", "displayName", "mail", "distinguishedName"],
        )
        result = []
        for entry in self.conn.entries:
            result.append({
                "sam":         str(entry.sAMAccountName),
                "displayName": str(entry.displayName) if entry.displayName else "",
                "mail":        str(entry.mail) if entry.mail else "",
                "dn":          str(entry.distinguishedName),
            })
        return result

    def close(self) -> None:
        self.conn.unbind()


# ---------------------------------------------------------------------------
# AD WinRM Client — acessa AD via PowerShell + WinRM no Domain Controller
# ---------------------------------------------------------------------------

class ADWinRMClient:
    """
    Alternativa ao ADClient (LDAP).
    Executa cmdlets AD do PowerShell remotamente via WinRM no DC.
    Requer: pip install pywinrm  +  AD PowerShell module no DC.
    Configure: AD_TRANSPORT=winrm no .env
    """

    def __init__(self, dc_ip: str, domain: str, user: str, password: str,
                 port: int = 5985, transport: str = "ntlm"):
        try:
            import winrm as _winrm  # noqa: F401
        except ImportError:
            raise RuntimeError("Instale pywinrm: pip install pywinrm requests_ntlm")
        import winrm
        self.domain = domain
        # Usuário no formato DOMAIN\user ou user@domain para NTLM
        admin = user if ("\\" in user or "@" in user) else f"{domain}\\{user}"
        self._sess = winrm.Session(
            target=f"http://{dc_ip}:{port}/wsman",
            auth=(admin, password),
            transport=transport,
        )
        # Verifica conectividade
        self._ps("Write-Host 'WinRM AD OK'")

    def _ps(self, script: str) -> str:
        """Executa script PowerShell no DC via WinRM e retorna stdout."""
        r = self._sess.run_ps(script)
        if r.status_code != 0:
            err = r.std_err.decode("utf-8", errors="replace").strip()
            raise RuntimeError(err or f"PowerShell exit code {r.status_code}")
        return r.std_out.decode("utf-8", errors="replace").strip()

    def _ps_json(self, script: str) -> list | dict:
        """Executa script e converte JSON output para Python."""
        import json
        out = self._ps(script + " | ConvertTo-Json -Depth 3")
        if not out:
            return []
        return json.loads(out)

    # --- Ações (mesma interface que ADClient) ---

    def get_status(self, sam: str) -> dict | None:
        try:
            out = self._ps(
                f"Import-Module ActiveDirectory -ErrorAction Stop; "
                f"$u = Get-ADUser -Identity '{sam}' "
                f"-Properties DisplayName,Mail,LockedOut,Enabled,BadLogonCount,PasswordLastSet; "
                f"Write-Output \"sam=$($u.SamAccountName)|enabled=$($u.Enabled)|"
                f"locked=$($u.LockedOut)|bad=$($u.BadLogonCount)|"
                f"display=$($u.DisplayName)|mail=$($u.Mail)\""
            )
        except Exception:
            return None
        info: dict = {}
        for part in out.strip().split("|"):
            if "=" in part:
                k, _, v = part.partition("=")
                info[k.strip()] = v.strip()
        if not info:
            return None
        return {
            "sam":         info.get("sam", sam),
            "displayName": info.get("display", ""),
            "mail":        info.get("mail", ""),
            "uac":         0,
            "enabled":     info.get("enabled", "").lower() == "true",
            "locked":      info.get("locked", "").lower() == "true",
            "badPwdCount": int(info.get("bad", "0") or "0"),
        }

    def disable_user(self, sam: str) -> dict:
        try:
            status = self.get_status(sam)
            if status and not status.get("enabled"):
                return {"ok": True, "already": True, "message": "Conta já está desativada"}
            self._ps(f"Import-Module ActiveDirectory; Disable-ADAccount -Identity '{sam}'")
            return {"ok": True, "message": "Conta desativada via WinRM"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def enable_user(self, sam: str) -> dict:
        try:
            status = self.get_status(sam)
            if status and status.get("enabled"):
                return {"ok": True, "already": True, "message": "Conta já está ativa"}
            self._ps(f"Import-Module ActiveDirectory; Enable-ADAccount -Identity '{sam}'")
            return {"ok": True, "message": "Conta ativada via WinRM"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def force_password_reset(self, sam: str) -> dict:
        try:
            self._ps(
                f"Import-Module ActiveDirectory; "
                f"Set-ADUser -Identity '{sam}' -ChangePasswordAtLogon $true"
            )
            return {"ok": True, "message": "Redefinição de senha obrigatória no próximo login"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def unlock_user(self, sam: str) -> dict:
        try:
            status = self.get_status(sam)
            if status and not status.get("locked"):
                return {"ok": True, "already": True, "message": "Conta não está bloqueada"}
            self._ps(f"Import-Module ActiveDirectory; Unlock-ADAccount -Identity '{sam}'")
            return {"ok": True, "message": "Lockout removido via WinRM"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def list_disabled(self) -> list[dict]:
        try:
            out = self._ps(
                "Import-Module ActiveDirectory; "
                "Get-ADUser -Filter {Enabled -eq $false} "
                "-Properties DisplayName,Mail "
                "| ForEach-Object { \"$($_.SamAccountName)|$($_.DisplayName)|$($_.Mail)\" }"
            )
            result = []
            for line in out.splitlines():
                parts = line.split("|")
                if parts:
                    result.append({
                        "sam":         parts[0] if len(parts) > 0 else "",
                        "displayName": parts[1] if len(parts) > 1 else "",
                        "mail":        parts[2] if len(parts) > 2 else "",
                    })
            return result
        except Exception as e:
            print(f"AVISO list_disabled (WinRM): {e}", file=sys.stderr)
            return []

    def close(self) -> None:
        pass


# ---------------------------------------------------------------------------
# Formatação de UAC
# ---------------------------------------------------------------------------

def uac_flags(uac: int) -> str:
    flags = []
    if uac & UAC_ACCOUNTDISABLE:  flags.append("DISABLED")
    if uac & UAC_LOCKOUT:          flags.append("LOCKOUT")
    if uac & UAC_DONT_EXPIRE_PWD:  flags.append("NO_PWD_EXPIRY")
    if not flags:                  flags.append("NORMAL")
    return " | ".join(flags)


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


def run_list(list_path: Path, action: str, ad: ADClient,
             exception_set: set[str] | None = None) -> int:
    """
    Processa arquivo de lista (um usuário por linha).
    Ação definida pelo argumento CLI — aplicada a todos os usuários.
    exception_set: sAMAccountNames/UPNs a ignorar.
    """
    _ACTIONS = {
        "disable":        ad.disable_user,
        "enable":         ad.enable_user,
        "reset-password": ad.force_password_reset,
        "unlock":         ad.unlock_user,
    }
    fn = _ACTIONS.get(action)
    if not fn:
        print(f"ERRO: action '{action}' não suportada via --list. "
              "Use: disable, enable, reset-password, unlock", file=sys.stderr)
        return 2

    values = read_list_values(list_path)
    if not values:
        print(f"AVISO: lista vazia ou sem entradas válidas em {list_path}")
        return 0

    exc = exception_set or set()
    total = len(values)
    print(f"Processando {total} usuários de '{list_path.name}' [action={action}]"
          + (f" | {len(exc)} exceções" if exc else ""))
    ok = fail = skip = 0

    for i, user in enumerate(values, 1):
        # verifica exceção tanto pelo valor bruto quanto pelo sAMAccountName
        sam, _ = parse_user_input(user)
        if user in exc or sam in exc:
            print(f"[SKIP] #{i} {user}  ← exceção")
            skip += 1
            continue
        try:
            result = fn(sam)
            if not result.get("ok"):
                raise RuntimeError(result.get("error", "falha"))
            msg = result.get("message", "")
            tag = "SKIP" if result.get("already") else "OK"
            print(f"[{tag}] #{i} {action} | {sam} | {msg}")
            ok += 1
        except Exception as e:
            print(f"[FALHA] #{i} {action} | {user}: {e}", file=sys.stderr)
            fail += 1

    print(f"\nLista concluída: {total} itens | {ok} ok | {skip} exceções | {fail} falhas")
    return 1 if fail else 0


def run_csv(csv_path: Path, ad: ADClient) -> int:
    """
    Processa CSV linha a linha.
    Formato: action,user
    Linhas iniciadas com # são ignoradas.
    """
    _ACTIONS = {
        "disable":        ad.disable_user,
        "enable":         ad.enable_user,
        "reset-password": ad.force_password_reset,
        "unlock":         ad.unlock_user,
    }
    total = ok = fail = 0
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(
            (ln for ln in f if not ln.strip().startswith("#"))
        )
        for row in reader:
            row = {k.strip(): (v.strip() if v else "") for k, v in row.items() if k}
            total += 1
            action = row.get("action", "").lower().strip()
            user   = row.get("user",   "").strip()

            if not action or not user:
                print(f"[SKIP] linha {total}: campos obrigatórios faltando → {row}")
                fail += 1
                continue

            sam, _ = parse_user_input(user)
            fn = _ACTIONS.get(action)
            if not fn:
                print(f"[FALHA] linha {total}: action '{action}' não suportada", file=sys.stderr)
                fail += 1
                continue
            try:
                result = fn(sam)
                if not result.get("ok"):
                    raise RuntimeError(result.get("error", "falha"))
                msg = result.get("message", "")
                tag = "SKIP" if result.get("already") else "OK"
                print(f"[{tag}] {action} | {sam} | {msg}")
                ok += 1
            except Exception as e:
                print(f"[FALHA] linha {total} ({action}/{user}): {e}", file=sys.stderr)
                fail += 1

    print(f"\nCSV concluído: {total} linhas | {ok} ok | {fail} falhas")
    return 1 if fail else 0


def print_user_status(u: dict) -> None:
    print(f"\n  Usuário    : {u.get('sam', '')}")
    print(f"  DisplayName: {u.get('displayName', '')}")
    if "upn" in u:
        print(f"  UPN        : {u['upn']}")
    print(f"  Email      : {u.get('mail', '')}")
    if "uac" in u and u["uac"]:
        print(f"  UAC        : {u['uac']} ({uac_flags(u['uac'])})")
    if "enabled" in u:
        print(f"  Ativa      : {'sim' if u['enabled'] else 'NÃO (desativada)'}")
    if "locked" in u:
        print(f"  Lockout    : {'SIM' if u['locked'] else 'não'}")
    elif "lockoutTime" in u:
        print(f"  Lockout    : {'SIM' if u['lockoutTime'] != 0 else 'não'}")
    print(f"  BadPwdCount: {u.get('badPwdCount', 0)}")
    if "dn" in u:
        print(f"  DN         : {u['dn']}")
    if "memberOf" in u:
        print(f"  Grupos     : {len(u['memberOf'])}")
        for g in u["memberOf"][:5]:
            print(f"    - {g.split(',')[0].replace('CN=','')}")
        if len(u["memberOf"]) > 5:
            print(f"    ... (+{len(u['memberOf'])-5} grupos)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="N2 Playbook — Active Directory User Containment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Formatos de usuário aceitos:
  johndoe
  johndoe@safelabs.lab
  SAFELABS\\johndoe

Exemplos:
  python3 pb_ad_containment.py --action disable        --user johndoe@safelabs.lab
  python3 pb_ad_containment.py --action enable         --user SAFELABS\\johndoe
  python3 pb_ad_containment.py --action reset-password --user johndoe
  python3 pb_ad_containment.py --action unlock         --user johndoe
  python3 pb_ad_containment.py --action status         --user johndoe
  python3 pb_ad_containment.py --action list-disabled

Modo lista (--list): ação fixa, usuários lidos do arquivo (1 por linha, # = comentário)
  python3 pb_ad_containment.py --action disable        --list usuarios_comprometidos.txt
  python3 pb_ad_containment.py --action enable         --list usuarios_reativar.txt
  python3 pb_ad_containment.py --action reset-password --list usuarios_reset_senha.txt
  python3 pb_ad_containment.py --action unlock         --list usuarios_desbloqueio.txt

Modo CSV (--csv): cada linha pode ter action diferente (colunas: action,user)
  python3 pb_ad_containment.py --csv lists/examples/ad_containment.csv
""")
    p.add_argument("--action", required=True,
                   choices=["disable", "enable", "reset-password", "unlock", "status", "list-disabled"])
    p.add_argument("--user",   help="Usuário (obrigatório exceto para list-disabled)")
    p.add_argument("--env",    default=None, help="Caminho alternativo para .env")
    p.add_argument("--dc-ip",  default=None, help="IP do Domain Controller (sobrescreve .env)")
    p.add_argument("--csv",    default=None, metavar="ARQUIVO.CSV",
                   help="Arquivo CSV com múltiplos usuários/ações (colunas: action,user)")
    p.add_argument("--list",   default=None, metavar="ARQUIVO.TXT",
                   help="Arquivo de lista (um usuário por linha). Requer --action. "
                        "Linhas com # são ignoradas.")
    p.add_argument("--exception-list", default=None, metavar="ARQUIVO.TXT",
                   help="Lista de usuários a IGNORAR ao processar --list ou --csv. "
                        "Ex: lists/exceptions/service_accounts.txt")
    p.add_argument("--transport", default=None, choices=["ldap", "winrm"],
                   help="Transporte para operações AD: 'ldap' (padrão) ou 'winrm' (PowerShell via WinRM).")
    return p


def main() -> int:
    args = build_parser().parse_args()

    env_path = Path(args.env) if args.env else Path(__file__).parent / ".env"
    if not env_path.is_file():
        env_path = Path(__file__).parent.parent.parent / "laboratory" / "poc-harpia" / ".env"
    env = load_env(env_path)

    dc_ip     = args.dc_ip or env.get("VM_DC01_IP", "")
    domain    = env.get("DOMAIN_NAME", "")
    ad_user   = env.get("DOMAIN_ADMIN", "")
    ad_pass   = env.get("DOMAIN_ADMIN_PASSWORD", "")
    # Transporte: CLI arg > .env > default ldap
    transport = (args.transport or env.get("AD_TRANSPORT", "ldap")).lower()
    ldap_ssl  = env.get("LDAP_USE_SSL", "false").lower() == "true"
    ldap_port = int(env.get("LDAP_PORT", "636" if ldap_ssl else "389"))
    winrm_port= int(env.get("WINRM_DC_PORT", env.get("WINRM_PORT", "5985")))
    winrm_trn = env.get("WINRM_TRANSPORT", "ntlm")

    if not dc_ip or not domain or not ad_user or not ad_pass:
        print("ERRO: VM_DC01_IP, DOMAIN_NAME, DOMAIN_ADMIN e DOMAIN_ADMIN_PASSWORD precisam estar no .env",
              file=sys.stderr)
        return 2

    if not args.list and args.action != "list-disabled" and not args.user and not args.csv:
        print("ERRO: --user é obrigatório para esta ação (ou use --list / --csv)", file=sys.stderr)
        return 2

    try:
        if transport == "winrm":
            print(f"[WinRM] Conectando ao DC {dc_ip}:{winrm_port} (transport={winrm_trn})...")
            ad: ADClient | ADWinRMClient = ADWinRMClient(
                dc_ip, domain, ad_user, ad_pass, port=winrm_port, transport=winrm_trn
            )
            print("[WinRM] Conectado.")
        else:
            print(f"[LDAP] Conectando ao DC {dc_ip}:{ldap_port}...")
            ad = ADClient(dc_ip, domain, ad_user, ad_pass, port=ldap_port, use_ssl=ldap_ssl)
            print("[LDAP] Conectado.")
    except LDAPException as e:
        print(f"ERRO LDAP ao conectar ao AD ({dc_ip}): {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"ERRO ao conectar ao AD ({dc_ip}): {e}", file=sys.stderr)
        return 1

    # Carrega lista de exceções
    exception_set: set[str] = set()
    if getattr(args, "exception_list", None):
        exc_path = Path(args.exception_list)
        if not exc_path.is_file():
            print(f"ERRO: --exception-list não encontrado: {exc_path}", file=sys.stderr)
            return 2
        exception_set = set(read_list_values(exc_path))
        print(f"Exceções carregadas: {len(exception_set)} usuários de '{exc_path.name}'")

    try:
        if args.csv:
            csv_path = Path(args.csv)
            if not csv_path.is_file():
                print(f"ERRO: arquivo CSV não encontrado: {csv_path}", file=sys.stderr)
                return 2
            return run_csv(csv_path, ad)

        if args.list:
            list_path = Path(args.list)
            if not list_path.is_file():
                print(f"ERRO: arquivo de lista não encontrado: {list_path}", file=sys.stderr)
                return 2
            return run_list(list_path, args.action, ad, exception_set)

        if args.action == "list-disabled":
            users = ad.list_disabled()
            print(f"\n  Contas desativadas no domínio {domain} ({len(users)} encontradas):\n")
            for u in users:
                print(f"  {u['sam']:<30} {u['displayName']:<30} {u['mail']}")
            return 0

        sam, _ = parse_user_input(args.user)

        if args.action == "status":
            u = ad.get_status(sam)
            if not u:
                print(f"ERRO: Usuário '{sam}' não encontrado no AD", file=sys.stderr)
                return 1
            print_user_status(u)
            return 0

        actions = {
            "disable":        ad.disable_user,
            "enable":         ad.enable_user,
            "reset-password": ad.force_password_reset,
            "unlock":         ad.unlock_user,
        }
        result = actions[args.action](sam)

        if not result.get("ok"):
            print(f"[ERRO] {args.action} | {sam} | {result.get('error', 'falha desconhecida')}", file=sys.stderr)
            return 1

        msg = result.get("message", "")
        if result.get("already"):
            print(f"[SKIP] {args.action} | {sam} | {msg}")
        else:
            print(f"[OK]   {args.action} | {sam} | {msg or 'sucesso'}")
            if "uac_before" in result:
                print(f"       UAC: {result['uac_before']} → {result['uac_after']} ({uac_flags(result['uac_after'])})")
        return 0

    except LDAPException as e:
        print(f"ERRO LDAP: {e}", file=sys.stderr)
        return 1
    finally:
        try:
            ad.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
