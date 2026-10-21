"""Wrapper for RAVEN Elasticsearch offensive tool.

Source: SpiderLabs/LevelBlue
License: verify
SRC-ID: SRC-1028
Category: Elasticsearch, offensive, CVE, SpiderLabs
"""

import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, UTC
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.paas.raven_elasticsearch.v1",
    "safety_class": "EXPLOIT",
    "requires_authorization": True,
    "side_effects": ["network_connections", "exploit_attempts"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1190", "T1210"],
}

MODULES = {
    "enum_indices": "Enumerate Elasticsearch indices and document counts",
    "dump_index": "Dump documents from a specific index",
    "cve_2015_1427": "Groovy sandbox escape (CVE-2015-1427)",
    "cve_2015_3337": "Directory traversal via snapshot API (CVE-2015-3337)",
    "cve_2015_5531": "Directory traversal (CVE-2015-5531)",
    "cve_2018_17246": "Local file inclusion via Kibana (CVE-2018-17246)",
    "cve_2021_22145": "Information disclosure (CVE-2021-22145)",
    "cve_2023_31419": "Search API DoS (CVE-2023-31419)",
    "cve_2023_46645": "Kibana SSRF (CVE-2023-46645)",
    "cve_2024_37288": "YAML deserialization (CVE-2024-37288)",
    "enum_cluster": "Cluster health and node enumeration",
    "snapshot_enum": "Enumerate snapshot repositories",
    "xpack_security": "Check X-Pack security configuration",
    "api_keys": "Enumerate and test API key access",
    "ingest_pipelines": "Enumerate ingest pipelines for data access",
    "watcher_abuse": "Check Watcher for RCE via script execution",
    "ml_jobs_enum": "Enumerate ML jobs for data access",
    "remote_clusters": "Enumerate cross-cluster search configurations",
    "ilm_policies": "Enumerate index lifecycle management policies",
}


def _find_raven() -> str | None:
    binary = shutil.which("raven-es") or shutil.which("raven")
    if binary:
        return binary
    for candidate in [
        os.path.expanduser("~/tools/raven/raven.py"),
        "/opt/raven/raven.py",
    ]:
        if os.path.isfile(candidate):
            return candidate
    return None


def _save(args: Any, prefix: str, data: Any) -> str:
    out = getattr(args, "output", ".")
    os.makedirs(out, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out, f"{prefix}_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"[+] Results saved to {path}")
    return path


def run(args: Any) -> int:
    """Execute raven_elasticsearch module.

    Actions (via args.action):
        check  - Verify RAVEN installation
        list   - List available modules and CVEs
        scan   - Run module against target (--target, --module)
        all    - Run all enumeration modules against target
    """
    action = getattr(args, "action", "check")
    print(f"[*] {MANIFEST['capability_id']} : RAVEN Elasticsearch offensive tool")
    print(f"[*] Action: {action}")

    results: dict[str, Any] = {"module": "raven_elasticsearch", "action": action, "findings": []}

    raven = _find_raven()

    if action == "check":
        results["installed"] = raven is not None
        results["path"] = raven
        results["module_count"] = len(MODULES)
        print(f"[+] RAVEN: {raven or 'not found'} ({len(MODULES)} modules)")
        results["status"] = "completed"
        _save(args, "paas_raven_check", results)
        return 0

    if action == "list":
        results["modules"] = MODULES
        cve_count = sum(1 for k in MODULES if k.startswith("cve_"))
        print(f"[*] {len(MODULES)} modules ({cve_count} CVE exploits)")
        for name, desc in MODULES.items():
            print(f"  [{name}] {desc}")
        results["status"] = "completed"
        _save(args, "paas_raven_list", results)
        return 0

    if not raven:
        print("[-] RAVEN not installed", file=sys.stderr)
        return 1

    target = getattr(args, "target", None)
    if not target:
        print("[-] --target required (host:port)", file=sys.stderr)
        return 1

    port = getattr(args, "port", 9200)
    use_ssl = getattr(args, "use_ssl", False)
    base_url = f"{'https' if use_ssl else 'http'}://{target}:{port}"

    if action == "scan":
        module = getattr(args, "module", None)
        if not module:
            print("[-] --module required", file=sys.stderr)
            return 1

        cmd = [sys.executable, raven] if raven.endswith(".py") else [raven]
        cmd.extend(["--target", base_url, "--module", module])
        timeout_val = getattr(args, "timeout", 30)
        cmd.extend(["--timeout", str(timeout_val)])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            results["findings"].append({
                "module": module,
                "target": base_url,
                "stdout": proc.stdout[:8192],
                "returncode": proc.returncode,
            })
            results["status"] = "completed"
        except subprocess.TimeoutExpired:
            results["status"] = "timeout"
        _save(args, f"paas_raven_{module}", results)
        return 0

    if action == "all":
        enum_modules = [k for k in MODULES if not k.startswith("cve_")]
        for mod in enum_modules:
            print(f"[*] Running: {mod}")
            cmd = [sys.executable, raven] if raven.endswith(".py") else [raven]
            cmd.extend(["--target", base_url, "--module", mod])
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                results["findings"].append({
                    "module": mod,
                    "stdout": proc.stdout[:4096],
                    "returncode": proc.returncode,
                })
            except subprocess.TimeoutExpired:
                results["findings"].append({"module": mod, "error": "timeout"})
        results["status"] = "completed"
        _save(args, "paas_raven_all", results)
        return 0

    print(f"[-] Unknown action: {action}", file=sys.stderr)
    return 1
