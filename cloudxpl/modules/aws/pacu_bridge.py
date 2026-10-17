"""Bridge para Pacu AWS exploitation framework — execute and import results."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.aws.pacu_bridge.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ['api_calls'],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1078","T1068"],
}


def _save(args: Any, prefix: str, data: Any) -> str:
    out = getattr(args, "output", ".")
    os.makedirs(out, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out, f"{prefix}_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"[+] Results saved to {path}")
    return path


def run(args: Any) -> int:

    print("[*] Pacu Framework Bridge")
    import shutil, subprocess
    pacu_path = shutil.which("pacu")
    if not pacu_path:
        print("[!] Pacu not found in PATH. Install: pip install pacu"); return 1
    print(f"[+] Pacu found: {pacu_path}")
    results = {"pacu_path": pacu_path, "available": True, "note": "Use pacu interactively for exploitation. This bridge verifies availability."}
    _save(args, "aws_pacu_bridge", results)
    print("[+] Pacu bridge ready — launch with: pacu")
    return 0
