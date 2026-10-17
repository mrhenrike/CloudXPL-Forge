"""CloudXPL-Forge — Awesome Hyper-V Exploitation (Bridge)."""

from __future__ import annotations

MANIFEST: dict = {
    "name": "Awesome Hyper-V Exploitation (Bridge)",
    "mitre": ["T1611"],
    "description": "Bridge to shogunlab/awesome-hyper-v-exploitation — Hyper-V exploitation resources and PoCs.",
    "references": ["https://github.com/shogunlab/awesome-hyper-v-exploitation"],
}


import os
import subprocess
import sys

REPO = "shogunlab/awesome-hyper-v-exploitation"
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
