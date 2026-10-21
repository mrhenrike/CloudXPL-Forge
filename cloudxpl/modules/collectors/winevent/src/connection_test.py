"""
Teste de conexão WinRM: single host e bulk (NW: Bulk Test Connections).
Retorna Status (Passed/Failed), Host, Error Message por host.
"""
import os
from dataclasses import dataclass, replace
from typing import List, Optional

from .config import TargetHost
from .collector import _session_for_target, _run_ps
from .etc_hosts import ensure_etc_hosts_entry


@dataclass
class ConnectionResult:
    host: str
    passed: bool
    error_message: str = ""


def test_connection(
    target: TargetHost,
    username: str,
    password: str,
    verify_ssl: bool = False,
    operation_timeout_sec: int = 30,
) -> ConnectionResult:
    """
    Testa conectividade WinRM com um host (abre sessão e executa comando trivial).
    """
    if target.ip:
        ok, msg = ensure_etc_hosts_entry(target.ip, target.hostname)
        if not ok:
            # Fallback: conectar pelo IP (sem escrever /etc/hosts)
            target = replace(target, hostname=target.ip)
    verify = target.validate_server if target.validate_server is not None else verify_ssl
    temp_key_path = None
    try:
        session, temp_key_path = _session_for_target(
            target, username, password, verify,
            operation_timeout_sec=operation_timeout_sec,
            read_timeout_sec=operation_timeout_sec + 15,
        )
        r = _run_ps(session, "Write-Output 'OK'")
        if r.status_code != 0:
            err = (r.std_err or b"").decode("utf-8", errors="replace").strip()
            return ConnectionResult(host=target.hostname, passed=False, error_message=err or f"Exit code {r.status_code}")
        return ConnectionResult(host=target.hostname, passed=True)
    except Exception as e:
        return ConnectionResult(host=target.hostname, passed=False, error_message=str(e))
    finally:
        if temp_key_path and os.path.isfile(temp_key_path):
            try:
                os.unlink(temp_key_path)
            except Exception:
                pass


def test_connections_bulk(
    targets: List[TargetHost],
    username: str,
    password: str,
    verify_ssl: bool = False,
    operation_timeout_sec: int = 30,
) -> List[ConnectionResult]:
    """Testa conexão com vários hosts; retorna lista de ConnectionResult (Status, Host, Error Message)."""
    return [
        test_connection(t, username, password, verify_ssl, operation_timeout_sec)
        for t in targets
    ]
