"""CloudXPL-Forge  -  Hypervisor Resources Collection (Bridge)."""


MANIFEST: dict = {
    "name": "Hypervisor Resources Collection (Bridge)",
    "mitre": ["T1592"],
    "description": "Bridge to husseinmuhaisen/Hypervisor  -  comprehensive hypervisor security resources and research.",
    "references": ["https://github.com/husseinmuhaisen/Hypervisor"],
}


import os
import subprocess
import sys

REPO = "husseinmuhaisen/Hypervisor"
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
