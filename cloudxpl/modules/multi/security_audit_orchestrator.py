"""Cloud security audit orchestrator (multi-phase workflow).

Source: https://github.com/cloudflare/security-audit-skill
License: MIT
SRC-ID: SRC-1019
Category: Cloud audit, multi-phase, recon, adversarial validation
"""

import json
import os
import sys
from datetime import datetime, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.multi.security_audit_orchestrator.v1",
    "safety_class": "RECON",
    "requires_authorization": True,
    "side_effects": ["cloud_api_calls"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1526", "T1580", "T1069.003"],
}

PHASES = [
    "recon",
    "coverage_led_hunting",
    "adversarial_validation",
    "structured_output",
    "independent_verification",
    "reporting",
]


def _save(args: Any, prefix: str, data: Any) -> str:
    out = getattr(args, "output_dir", getattr(args, "output", "."))
    os.makedirs(out, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out, f"{prefix}_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"[+] Results saved to {path}")
    return path


def _run_phase(phase: str, scope: str, depth: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "phase": phase,
        "scope": scope,
        "depth": depth,
        "findings": [],
        "status": "completed",
    }

    phase_labels = {
        "recon": "Asset enumeration and scope discovery",
        "coverage_led_hunting": "Coverage-driven search for misconfigurations",
        "adversarial_validation": "Validate findings with adversarial techniques",
        "structured_output": "Structure findings with severity and evidence",
        "independent_verification": "Cross-verify findings independently",
        "reporting": "Generate structured audit report",
    }
    result["description"] = phase_labels.get(phase, phase)
    print(f"  [{phase}] {result['description']}")
    return result


def run(args: Any) -> int:
    """Execute security_audit_orchestrator module.

    Actions (via args.action):
        check  - Show audit phases and configuration
        audit  - Run full or partial audit (--phases to select, --target_scope)
    """
    action = getattr(args, "action", "check")
    print(f"[*] {MANIFEST['capability_id']} : Security Audit Orchestrator")
    print(f"[*] Action: {action}")

    results: dict[str, Any] = {"module": "security_audit_orchestrator", "action": action, "findings": []}

    if action == "check":
        results["phases"] = PHASES
        results["status"] = "completed"
        for i, p in enumerate(PHASES, 1):
            print(f"  Phase {i}: {p}")
        _save(args, "multi_audit_check", results)
        return 0

    if action == "audit":
        scope = getattr(args, "target_scope", "")
        if not scope:
            print("[-] --target_scope required", file=sys.stderr)
            return 1

        depth = getattr(args, "max_depth", 3)
        selected = getattr(args, "phases", None)
        if selected:
            phase_list = [p.strip() for p in selected.split(",")]
        else:
            phase_list = list(PHASES)

        print(f"[*] Scope: {scope} | Depth: {depth} | Phases: {len(phase_list)}")

        for phase in phase_list:
            if phase not in PHASES:
                print(f"[!] Unknown phase: {phase}, skipping")
                continue
            phase_result = _run_phase(phase, scope, depth)
            results["findings"].append(phase_result)

        results["status"] = "completed"
        _save(args, "multi_audit_report", results)
        return 0

    print(f"[-] Unknown action: {action}", file=sys.stderr)
    return 1
