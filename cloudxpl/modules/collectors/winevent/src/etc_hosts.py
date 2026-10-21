"""
Garantir mapeamento IP -> hostname em /etc/hosts (hosts fora do domínio).
Sempre verifica se a entrada já existe antes de adicionar. Escrita exige root no Linux.
"""
import sys
from typing import Tuple


ETC_HOSTS = "/etc/hosts"
# Formato de linha que inserimos: "IP\thostname" (e opcionalmente "IP\thostname.short")
SEP = "\t"


def _is_ip(s: str) -> bool:
    if not s or not s.strip():
        return False
    # IPv4 dotted decimal
    parts = s.strip().split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or int(p) < 0 or int(p) > 255:
            return False
    return True


def _parse_hosts_line(line: str) -> list:
    """Retorna lista de (ip, hostname) para linhas não comentadas com pelo menos ip e um nome."""
    line = line.strip()
    if not line or line.startswith("#"):
        return []
    parts = line.split()
    if len(parts) < 2:
        return []
    ip = parts[0]
    if not _is_ip(ip):
        return []
    return [(ip, h) for h in parts[1:] if h and not h.startswith("#")]


def etc_hosts_has_mapping(ip: str, hostname: str) -> bool:
    """Verifica se /etc/hosts já contém mapeamento deste IP para este hostname (ou vice-versa)."""
    if sys.platform == "win32":
        return True
    ip = ip.strip()
    hostname = hostname.strip()
    if not ip or not hostname:
        return False
    try:
        with open(ETC_HOSTS, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                for existing_ip, existing_name in _parse_hosts_line(line):
                    if existing_ip == ip and existing_name.lower() == hostname.lower():
                        return True
    except OSError:
        return False
    return False


def ensure_etc_hosts_entry(ip: str, hostname: str) -> Tuple[bool, str]:
    """
    Garante que /etc/hosts contém uma linha com IP e hostname.
    Retorna (True, msg) se já existia ou foi adicionado; (False, msg) em caso de erro.
    Em Windows não altera nada e retorna (True, "skip").
    """
    if sys.platform == "win32":
        return (True, "Windows: /etc/hosts não usado")
    ip = ip.strip()
    hostname = hostname.strip()
    if not ip or not hostname:
        return (False, "IP e hostname são obrigatórios para hosts fora do domínio")
    if not _is_ip(ip):
        return (False, f"IP inválido: {ip}")
    if etc_hosts_has_mapping(ip, hostname):
        return (True, "Entrada já existe em /etc/hosts")
    line = f"{ip}{SEP}{hostname}"
    short = hostname.split(".")[0] if "." in hostname else None
    if short and short != hostname:
        line += f" {short}"
    line += "\n"
    try:
        with open(ETC_HOSTS, "a", encoding="utf-8") as f:
            f.write(line)
        return (True, "Entrada adicionada em /etc/hosts")
    except PermissionError:
        return (
            False,
            "Sem permissão para escrever em /etc/hosts. Execute com sudo ou adicione manualmente: " + line.strip(),
        )
    except OSError as e:
        return (False, str(e))
