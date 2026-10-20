"""CloudXPL-Forge — Linux Kernel Container Breakout (CVE-2026-52910)."""


MANIFEST: dict = {
    "name": "Linux Kernel Container Breakout (CVE-2026-52910)",
    "cve": "CVE-2026-52910",
    "mitre": ["T1611"],
    "description": "Exploits Linux kernel vulnerability for container-to-host escape. PoC available on GitHub.",
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
    if getattr(args, "verbose", False):
        for root, dirs, files in os.walk(clone_dir):
            level = root.replace(clone_dir, "").count(os.sep)
            indent = " " * 2 * level
            print(f"{indent}{os.path.basename(root)}/")
            subindent = " " * 2 * (level + 1)
            for f in files[:20]:
                print(f"{subindent}{f}")
    return 0
