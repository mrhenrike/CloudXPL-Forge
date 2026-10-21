"""CloudXPL-Forge — ESXi Fingerprint (Metasploit Bridge)."""


MANIFEST: dict = {
    "name": "ESXi Fingerprint (Metasploit Bridge)",
    "mitre": ["T1592"],
    "description": "Bridge to Metasploit auxiliary/scanner/vmware/esx_fingerprint for ESXi version identification and enumeration.",
    "references": ["https://www.rapid7.com/db/modules/auxiliary/scanner/vmware/esx_fingerprint/"],
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
        f"use auxiliary/scanner/vmware/esx_fingerprint; "
        + (f"set RHOSTS {target}; " if target else "")
        + "run; exit",
    ]
    if getattr(args, "verbose", False):
        print(f"[*] Running: {' '.join(cmd)}")
    return subprocess.call(cmd)
