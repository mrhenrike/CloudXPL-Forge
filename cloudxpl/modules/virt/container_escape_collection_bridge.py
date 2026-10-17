"""CloudXPL-Forge — Container Escape PoC Collection (Bridge)."""

from __future__ import annotations

MANIFEST: dict = {
    "name": "Container Escape PoC Collection (Bridge)",
    "mitre": ["T1611"],
    "description": "Bridge to Markakd/Container_escape — PoCs for CVE-2026-80521 and CVE-2026-52910.",
    "references": ["https://github.com/Markakd/Container_escape"],
}


import os
import subprocess
import sys

REPO = "Markakd/Container_escape"
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
    return 0
