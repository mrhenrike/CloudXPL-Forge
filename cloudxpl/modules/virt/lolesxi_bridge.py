"""CloudXPL-Forge — LOLESXi Living Off The Land (Bridge)."""

from __future__ import annotations

MANIFEST: dict = {
    "name": "LOLESXi Living Off The Land (Bridge)",
    "mitre": ["T1059"],
    "description": "Bridge to LOLESXi-Project/LOLESXi — living-off-the-land techniques using native ESXi binaries.",
    "references": ["https://github.com/LOLESXi-Project/LOLESXi"],
}


import os
import subprocess
import sys

REPO = "LOLESXi-Project/LOLESXi"
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
