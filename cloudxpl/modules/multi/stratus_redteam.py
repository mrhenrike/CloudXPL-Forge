"""Stratus Red Team cloud adversary emulation bridge.

Source: https://github.com/DataDog/stratus-red-team
License: Apache-2.0
SRC-ID: SRC-1033
Category: Adversary emulation, cloud attack simulation, AWS, Azure, GCP, EKS, Entra ID, K8s

Stratus Red Team is a granular, actionable adversary emulation tool for
cloud environments by DataDog. It provides atomic attack techniques
mapped to MITRE ATT&CK for AWS, Azure, GCP, EKS, Entra ID, and
Kubernetes. Each technique has a full lifecycle: warmup (provision
prerequisite infrastructure), detonate (execute the attack), revert
(undo the detonation), and cleanup (tear down prerequisites).

This module wraps the ``stratus`` CLI binary, discovers available
techniques, and orchestrates technique execution with structured
JSON output.
"""

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.multi.stratus_redteam.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["cloud_resource_creation", "cloud_resource_modification"],
    "output_schema": "xpl.finding.v1",
    "mitre": [
        "T1078",     # Valid Accounts
        "T1098",     # Account Manipulation
        "T1110",     # Brute Force
        "T1136",     # Create Account
        "T1190",     # Exploit Public-Facing Application
        "T1525",     # Implant Internal Image
        "T1530",     # Data from Cloud Storage Object
        "T1537",     # Transfer Data to Cloud Account
        "T1538",     # Cloud Service Dashboard
        "T1550",     # Use Alternate Authentication Material
        "T1552",     # Unsecured Credentials
        "T1562",     # Impair Defenses
        "T1580",     # Cloud Infrastructure Discovery
        "T1098.001", # Additional Cloud Credentials
        "T1098.003", # Additional Cloud Roles
    ],
}

# Known MITRE ATT&CK mappings for Stratus technique ID prefixes.
# Stratus technique IDs follow the pattern <platform>.<tactic>.<name>.
_TACTIC_MITRE_MAP: dict[str, list[str]] = {
    "credential-access":    ["T1552", "T1550"],
    "defense-evasion":      ["T1562"],
    "discovery":            ["T1580"],
    "execution":            ["T1059", "T1204"],
    "exfiltration":         ["T1537", "T1530"],
    "impact":               ["T1485", "T1486"],
    "initial-access":       ["T1078", "T1190"],
    "lateral-movement":     ["T1021", "T1550"],
    "persistence":          ["T1098", "T1136", "T1525"],
    "privilege-escalation": ["T1078.004", "T1548"],
}

_STRATUS_BIN_NAMES = ("stratus", "stratus-red-team")

_VALID_ACTIONS = ("list", "show", "warmup", "detonate", "revert", "cleanup", "status")


def _find_stratus() -> str | None:
    """Locate the stratus binary on PATH or common install locations."""
    for name in _STRATUS_BIN_NAMES:
        path = shutil.which(name)
        if path:
            return path
    # Check Go bin path as fallback
    gopath = os.environ.get("GOPATH", os.path.expanduser("~/go"))
    for name in _STRATUS_BIN_NAMES:
        candidate = os.path.join(gopath, "bin", name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _exec_stratus(
    binary: str,
    subcmd: str,
    extra_args: list[str] | None = None,
    timeout: int = 300,
) -> tuple[int, str, str]:
    """Run a stratus subcommand and return (returncode, stdout, stderr)."""
    cmd = [binary, subcmd]
    if extra_args:
        cmd.extend(extra_args)
    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout, proc.stderr


def _parse_technique_list(raw: str) -> list[dict[str, Any]]:
    """Parse the output of ``stratus list`` into structured records.

    Stratus list outputs a table with columns:
    ID | Name | Platform | MITRE ATT&CK Tactic
    or JSON when ``--json`` is passed.
    """
    # Try JSON first (stratus list --json)
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return data
    except (json.JSONDecodeError, ValueError):
        pass

    # Fallback: parse table output
    techniques: list[dict[str, Any]] = []
    for line in raw.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("ID") or line.startswith("+") or line.startswith("-"):
            continue
        # Split by pipe or multiple spaces
        parts = re.split(r"\s{2,}|\|", line)
        parts = [p.strip() for p in parts if p.strip()]
        if len(parts) >= 3:
            techniques.append({
                "id": parts[0],
                "name": parts[1] if len(parts) > 1 else "",
                "platform": parts[2] if len(parts) > 2 else "",
                "tactic": parts[3] if len(parts) > 3 else "",
            })
    return techniques


def _parse_show_output(raw: str) -> dict[str, Any]:
    """Parse ``stratus show <technique>`` output into a dict."""
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        pass
    # Fallback: key-value extraction from text output
    info: dict[str, Any] = {"raw": raw}
    for line in raw.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            info[key.strip().lower().replace(" ", "_")] = val.strip()
    return info


def _mitre_for_tactic(tactic: str) -> list[str]:
    """Resolve MITRE ATT&CK technique IDs for a Stratus tactic string."""
    tactic_lower = tactic.lower().strip()
    return _TACTIC_MITRE_MAP.get(tactic_lower, [])


def _save(args: Any, prefix: str, data: Any) -> str:
    out = getattr(args, "output", ".")
    os.makedirs(out, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out, f"{prefix}_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"[+] Results saved to {path}")
    return path


def list_techniques(binary: str) -> list[dict[str, Any]]:
    """Enumerate all available Stratus techniques."""
    # Try JSON output first
    rc, out, err = _exec_stratus(binary, "list", ["--json"])
    if rc != 0:
        # Fallback without --json
        rc, out, err = _exec_stratus(binary, "list")
    if rc != 0:
        print(f"[-] stratus list failed: {err}", file=sys.stderr)
        return []
    return _parse_technique_list(out)


def show_technique(binary: str, technique_id: str) -> dict[str, Any]:
    """Retrieve detailed information about a specific technique."""
    rc, out, err = _exec_stratus(binary, "show", [technique_id])
    if rc != 0:
        print(f"[-] stratus show {technique_id} failed: {err}", file=sys.stderr)
        return {"error": err}
    return _parse_show_output(out)


def warmup_technique(binary: str, technique_id: str) -> dict[str, Any]:
    """Warm up (provision prerequisites for) a technique."""
    rc, out, err = _exec_stratus(binary, "warmup", [technique_id])
    return {
        "action": "warmup",
        "technique": technique_id,
        "success": rc == 0,
        "stdout": out.strip(),
        "stderr": err.strip(),
    }


def detonate_technique(
    binary: str,
    technique_id: str,
    cleanup: bool = False,
) -> dict[str, Any]:
    """Detonate (execute) a technique."""
    extra = [technique_id]
    if cleanup:
        extra.append("--cleanup")
    rc, out, err = _exec_stratus(binary, "detonate", extra, timeout=600)
    return {
        "action": "detonate",
        "technique": technique_id,
        "success": rc == 0,
        "stdout": out.strip(),
        "stderr": err.strip(),
    }


def revert_technique(binary: str, technique_id: str) -> dict[str, Any]:
    """Revert (undo the detonation of) a technique."""
    rc, out, err = _exec_stratus(binary, "revert", [technique_id])
    return {
        "action": "revert",
        "technique": technique_id,
        "success": rc == 0,
        "stdout": out.strip(),
        "stderr": err.strip(),
    }


def cleanup_technique(binary: str, technique_id: str) -> dict[str, Any]:
    """Clean up (tear down prerequisites of) a technique."""
    rc, out, err = _exec_stratus(binary, "cleanup", [technique_id])
    return {
        "action": "cleanup",
        "technique": technique_id,
        "success": rc == 0,
        "stdout": out.strip(),
        "stderr": err.strip(),
    }


def status_techniques(binary: str) -> dict[str, Any]:
    """Get the current state of all techniques."""
    rc, out, err = _exec_stratus(binary, "status")
    if rc != 0:
        return {"error": err}
    try:
        return json.loads(out)
    except (json.JSONDecodeError, ValueError):
        return {"raw": out.strip()}


def run(args: Any) -> int:
    """Execute stratus_redteam module.

    Supported actions via ``args.action``:
        list      - enumerate all available techniques
        show      - show details for a technique (requires args.technique)
        warmup    - provision prerequisites (requires args.technique)
        detonate  - execute the attack (requires args.technique)
        revert    - undo the detonation (requires args.technique)
        cleanup   - tear down prerequisites (requires args.technique)
        status    - show state of all techniques

    If no action is given, defaults to ``list``.
    """
    provider = getattr(args, "command", "multi")
    action = getattr(args, "action", "list")
    technique = getattr(args, "technique", None)

    print(f"[*] {MANIFEST['capability_id']}  -  Stratus Red Team adversary emulation bridge")
    print(f"[*] Provider: {provider} | Action: {action}")

    results: dict[str, Any] = {
        "module": "stratus_redteam",
        "provider": provider,
        "action": action,
        "findings": [],
        "summary": {},
    }

    # Locate binary
    binary = getattr(args, "stratus_bin", None) or _find_stratus()
    if not binary:
        print("[!] Stratus Red Team binary not found on PATH", file=sys.stderr)
        print("[*] Install: go install github.com/datadog/stratus-red-team/v2/cmd/stratus@latest")
        results["status"] = "missing_dependency"
        results["error"] = "stratus binary not found"
        _save(args, "multi_stratus_redteam", results)
        return 1

    print(f"[*] Using stratus binary: {binary}")

    # Validate action
    if action not in _VALID_ACTIONS:
        print(f"[!] Invalid action: {action}. Valid: {', '.join(_VALID_ACTIONS)}", file=sys.stderr)
        results["status"] = "invalid_action"
        results["error"] = f"unknown action {action}"
        _save(args, "multi_stratus_redteam", results)
        return 1

    # Actions requiring a technique ID
    if action in ("show", "warmup", "detonate", "revert", "cleanup") and not technique:
        print(f"[!] Action '{action}' requires --technique <id>", file=sys.stderr)
        results["status"] = "missing_argument"
        results["error"] = f"action {action} requires technique id"
        _save(args, "multi_stratus_redteam", results)
        return 1

    try:
        if action == "list":
            techniques = list_techniques(binary)
            results["findings"] = techniques
            results["summary"] = {
                "techniques_available": len(techniques),
                "platforms": sorted({t.get("platform", "unknown") for t in techniques}),
            }
            print(f"[+] Discovered {len(techniques)} techniques")
            for t in techniques[:10]:
                tid = t.get("id", "?")
                tname = t.get("name", "?")
                print(f"    {tid}: {tname}")
            if len(techniques) > 10:
                print(f"    ... and {len(techniques) - 10} more")

        elif action == "show":
            info = show_technique(binary, technique)
            results["findings"] = [info]
            tactic = info.get("tactic", info.get("mitre_attack_tactic", ""))
            mitre_ids = _mitre_for_tactic(tactic) if tactic else []
            results["summary"] = {
                "technique": technique,
                "mitre_ids": mitre_ids,
                "details": info,
            }
            print(f"[+] Technique details for {technique}")

        elif action == "warmup":
            result = warmup_technique(binary, technique)
            results["findings"] = [result]
            results["summary"] = {
                "technique": technique,
                "warmup_success": result["success"],
            }
            status_label = "succeeded" if result["success"] else "failed"
            print(f"[+] Warmup {status_label} for {technique}")

        elif action == "detonate":
            auto_cleanup = getattr(args, "cleanup", False)
            result = detonate_technique(binary, technique, cleanup=auto_cleanup)
            results["findings"] = [result]
            results["summary"] = {
                "technique": technique,
                "detonate_success": result["success"],
                "auto_cleanup": auto_cleanup,
            }
            status_label = "succeeded" if result["success"] else "failed"
            print(f"[+] Detonation {status_label} for {technique}")

        elif action == "revert":
            result = revert_technique(binary, technique)
            results["findings"] = [result]
            results["summary"] = {
                "technique": technique,
                "revert_success": result["success"],
            }
            status_label = "succeeded" if result["success"] else "failed"
            print(f"[+] Revert {status_label} for {technique}")

        elif action == "cleanup":
            result = cleanup_technique(binary, technique)
            results["findings"] = [result]
            results["summary"] = {
                "technique": technique,
                "cleanup_success": result["success"],
            }
            status_label = "succeeded" if result["success"] else "failed"
            print(f"[+] Cleanup {status_label} for {technique}")

        elif action == "status":
            status_data = status_techniques(binary)
            results["findings"] = [status_data]
            results["summary"] = {"status_retrieved": "error" not in status_data}
            print("[+] Technique status retrieved")

        results["status"] = "completed"

    except subprocess.TimeoutExpired:
        print(f"[-] stratus {action} timed out", file=sys.stderr)
        results["status"] = "timeout"
        results["error"] = f"stratus {action} exceeded timeout"
        _save(args, "multi_stratus_redteam", results)
        return 1
    except Exception as exc:
        print(f"[-] Module execution failed: {exc}", file=sys.stderr)
        results["status"] = "error"
        results["error"] = str(exc)
        _save(args, "multi_stratus_redteam", results)
        return 1

    _save(args, "multi_stratus_redteam", results)
    return 0
