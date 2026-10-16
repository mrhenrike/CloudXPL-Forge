"""Azure ARM template injection — detect dangerous template patterns."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.azure.arm_injection.v1",
    "safety_class": "READ_ONLY",
    "requires_authorization": False,
    "side_effects": [],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1195.002"],
}

DANGEROUS_PATTERNS = [
    {
        "name": "listKeys_in_output",
        "pattern": r'"listKeys\s*\(',
        "severity": "HIGH",
        "description": "listKeys() in template may expose storage account keys",
    },
    {
        "name": "listCallbackUrl",
        "pattern": r'"listCallbackUrl\s*\(',
        "severity": "MEDIUM",
        "description": "listCallbackUrl() may expose webhook secrets",
    },
    {
        "name": "reference_to_secret",
        "pattern": r'"reference\s*\([^)]*secret',
        "severity": "HIGH",
        "description": "reference() accessing secrets in outputs section",
    },
    {
        "name": "plaintext_password",
        "pattern": r'"adminPassword"\s*:\s*"[^"]*\[parameters',
        "severity": "MEDIUM",
        "description": "Admin password passed as parameter (check securestring)",
    },
    {
        "name": "commandToExecute_inline",
        "pattern": r'"commandToExecute"\s*:\s*"[^"]*(?:curl|wget|bash|powershell)',
        "severity": "HIGH",
        "description": "Inline command execution in CustomScript extension",
    },
    {
        "name": "no_https_enforcement",
        "pattern": r'"supportsHttpsTrafficOnly"\s*:\s*false',
        "severity": "MEDIUM",
        "description": "HTTPS-only traffic disabled on storage account",
    },
    {
        "name": "public_network_access",
        "pattern": r'"publicNetworkAccess"\s*:\s*"Enabled"',
        "severity": "MEDIUM",
        "description": "Public network access enabled",
    },
]


def run(args: Any) -> int:
    scan_path = args.target if args.target else "."
    print(f"[*] ARM Template Injection Analysis: {scan_path}")

    templates = []
    p = Path(scan_path)
    if p.is_file():
        templates = [p]
    else:
        templates = list(p.rglob("*.json"))

    arm_templates = []
    for t in templates:
        try:
            with open(t) as fh:
                data = json.load(fh)
            if "$schema" in data and "deploymentTemplate" in data.get("$schema", ""):
                arm_templates.append((t, data))
        except (json.JSONDecodeError, OSError):
            continue

    print(f"[+] {len(arm_templates)} ARM templates found")
    results = []

    for path, template in arm_templates:
        content = json.dumps(template)
        findings = []

        for pattern_def in DANGEROUS_PATTERNS:
            matches = list(re.finditer(pattern_def["pattern"], content, re.IGNORECASE))
            if matches:
                findings.append({
                    "pattern": pattern_def["name"],
                    "severity": pattern_def["severity"],
                    "description": pattern_def["description"],
                    "count": len(matches),
                })

        outputs = template.get("outputs", {})
        for out_name, out_val in outputs.items():
            val_str = json.dumps(out_val)
            if re.search(r"listKeys|listCallbackUrl|reference\(", val_str, re.IGNORECASE):
                findings.append({
                    "pattern": "secret_in_output",
                    "severity": "CRITICAL",
                    "description": f"Output '{out_name}' may leak secrets via deployment outputs",
                    "count": 1,
                })

        resources = template.get("resources", [])
        for res in resources:
            if res.get("type", "").endswith("extensions") and "CustomScript" in res.get("type", ""):
                settings = res.get("properties", {}).get("settings", {})
                if "commandToExecute" in settings or "script" in settings:
                    findings.append({
                        "pattern": "custom_script_extension",
                        "severity": "HIGH",
                        "description": "CustomScript extension with inline commands",
                        "count": 1,
                    })

        if findings:
            entry = {"template": str(path), "findings": findings}
            results.append(entry)
            for f in findings:
                print(f"  [{f['severity']}] {path.name}: {f['description']}")

    os.makedirs(args.output, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = os.path.join(args.output, f"arm_injection_{ts}.json")
    with open(out_path, "w") as fh:
        json.dump(results, fh, indent=2, default=str)

    total_findings = sum(len(r["findings"]) for r in results)
    print(f"[+] {total_findings} findings in {len(results)} templates → {out_path}")
    return 0
