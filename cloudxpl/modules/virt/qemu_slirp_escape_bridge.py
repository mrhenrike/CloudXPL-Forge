"""CloudXPL-Forge — QEMU SLiRP Escape PoC (Bridge)."""

from __future__ import annotations

MANIFEST: dict = {
    "name": "QEMU SLiRP Escape PoC (Bridge)",
    "cve": "CVE-2019-6778",
    "mitre": ["T1611"],
    "description": "Bridge to 0xKira/qemu-vm-escape — working QEMU VM escape exploit via SLiRP heap overflow.",
    "references": ["https://github.com/0xKira/qemu-vm-escape"],
}


import os
import subprocess
import sys

REPO = "0xKira/qemu-vm-escape"
REPO_URL = f"https://github.com/{REPO}.git"


def run(args):
    clone_dir = os.path.join(getattr(args, "output", "."), REPO.split("/")[-1])
    if os.path.isdir(clone_dir):
        print(f"[*] Repository already cloned at {clone_dir}")
    else:
        print(f"[*] Cloning {REPO_URL} -> {clone_dir}")
        ret = subprocess.call(["git", "clone", "--depth", "1", REPO_URL, clone_dir])
        if ret != 0:
            print(f"[!] Clone failed (rc={ret})", file=sys.stderr)
            return ret
    print(f"[+] Repository ready at {clone_dir}")
    print("[*] Inspect contents before execution per security policy")
    if getattr(args, "verbose", False):
        for root, dirs, files in os.walk(clone_dir):
            level = root.replace(clone_dir, "").count(os.sep)
            indent = " " * 2 * level
            print(f"{indent}{os.path.basename(root)}/")
            subindent = " " * 2 * (level + 1)
            for f in files[:20]:
                print(f"{subindent}{f}")
    return 0
