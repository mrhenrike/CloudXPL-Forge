"""CloudXPL-Forge  -  ESXi Brute Force (Bridge)."""


MANIFEST: dict = {
    "name": "ESXi Brute Force (Bridge)",
    "mitre": ["T1110"],
    "description": "Bridge to Bhanunamikaze/ESXiBrute  -  ESXi credential brute-force tool.",
    "references": ["https://github.com/Bhanunamikaze/ESXiBrute"],
}


import os
import subprocess
import sys

REPO = "Bhanunamikaze/ESXiBrute"
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
