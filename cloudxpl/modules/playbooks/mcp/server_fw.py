#!/usr/bin/env python3
"""
MCP Server — Firewall Containment
===================================
Expõe ferramentas de contenção de firewall via Model Context Protocol.
Suporta FortiGate (REST API primeiro, SSH CLI como fallback). Extensível.

Author: André Henrique (@mrhenrike) | União Geek
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Configuração e env
# ---------------------------------------------------------------------------

_ENV_PATHS = [
    Path(__file__).parent / ".env",
    Path(__file__).parent.parent / ".env",
    Path(__file__).parent.parent.parent / "laboratory" / "poc-harpia" / ".env",
]


def _load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for p in _ENV_PATHS:
        if p.is_file():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                env.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    for k in list(env):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


ENV = _load_env()

FW_HOST     = ENV.get("FORTIGATE_WEB_IP", ENV.get("VM_FORTIGATE_IP_PRIVATE", "164.152.245.165"))
FW_PORT     = int(ENV.get("FORTIGATE_WEB_PORT", "80"))
FW_PROTOCOL = ENV.get("FORTIGATE_WEB_PROTOCOL", "http")
FW_API_KEY  = ENV.get("FORTIGATE_RESTFUL_API_KEY", "")
FW_SSH_USER = ENV.get("FORTIGATE_SSH_USER", ENV.get("VM_FORTIGATE_USER", "admin"))
FW_SSH_PASS = ENV.get("FORTIGATE_SSH_PASSWORD", ENV.get("VM_FORTIGATE_PASSWORD", ""))
FW_VDOM     = ENV.get("FORTIGATE_VDOM", "root")
TRANSPORT   = ENV.get("FORTIGATE_TRANSPORT", "api").lower()

IOC_LISTS_DIR = Path(__file__).parent / "ioc_lists"
TTL_FILE      = Path(__file__).parent / ".ioc_ttl.json"

PFX      = "safelabs"
GRP_IP   = f"{PFX}-blocklist-ip"
GRP_GEO  = f"{PFX}-blocklist-geo"
GRP_ISO  = f"{PFX}-isolated-hosts"
DNS_FLT  = f"{PFX}-dns-block"
URL_FLT  = f"{PFX}-url-block"
ISO_POL_OUT = f"{PFX}-iso-deny-out"
ISO_POL_DNS = f"{PFX}-iso-deny-dns"
UTM_POL     = f"{PFX}-utm-policy"


# ---------------------------------------------------------------------------
# FortiGate REST API client (primary transport)
# ---------------------------------------------------------------------------

class _FGApi:
    """FortiGate REST API v2 client."""

    def __init__(self):
        self._base = f"{FW_PROTOCOL}://{FW_HOST}:{FW_PORT}"
        self._key  = FW_API_KEY
        self._ctx  = ssl.create_default_context()
        self._ctx.check_hostname = False
        self._ctx.verify_mode = ssl.CERT_NONE

    def _req(self, method: str, path: str, data: dict | None = None,
             params: dict | None = None) -> dict:
        """Execute FortiGate REST API request."""
        sep = "&" if "?" in path else "?"
        url = f"{self._base}{path}{sep}access_token={self._key}"
        if FW_VDOM and FW_VDOM != "root":
            url += f"&vdom={FW_VDOM}"
        if params:
            url += "&" + urllib.parse.urlencode(params)
        body = json.dumps(data).encode("utf-8") if data else None
        req  = urllib.request.Request(url, data=body, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, context=self._ctx, timeout=20) as r:
                return json.loads(r.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")[:500]
            raise RuntimeError(f"API {e.code}: {err_body}") from e

    def _get(self, path: str, params: dict | None = None) -> dict:
        return self._req("GET", path, params=params)

    def _post(self, path: str, data: dict) -> dict:
        return self._req("POST", path, data=data)

    def _put(self, path: str, data: dict) -> dict:
        return self._req("PUT", path, data=data)

    def _delete(self, path: str) -> dict:
        return self._req("DELETE", path)

    # ---- connectivity check ----

    def check(self) -> bool:
        try:
            r = self._get("/api/v2/cmdb/system/status")
            return "results" in r or "version" in r or "serial" in r
        except Exception:
            return False

    # ---- status ----

    def status(self) -> dict:
        r = self._get("/api/v2/cmdb/system/status")
        res = r.get("results", r)
        return {
            "host":     FW_HOST,
            "version":  res.get("version", "?"),
            "serial":   res.get("serial", "?"),
            "hostname": res.get("hostname", "?"),
            "transport": "api",
        }

    # ---- address objects ----

    def _addr_exists(self, name: str) -> bool:
        try:
            self._get(f"/api/v2/cmdb/firewall/address/{urllib.parse.quote(name, safe='')}")
            return True
        except Exception:
            return False

    def _create_addr(self, name: str, ip: str, comment: str) -> None:
        net  = ipaddress.ip_network(ip, strict=False)
        self._post("/api/v2/cmdb/firewall/address", {
            "name":    name,
            "type":    "ipmask",
            "subnet":  f"{net.network_address} {net.netmask}",
            "comment": comment[:63],
        })

    def _delete_addr(self, name: str) -> None:
        self._delete(f"/api/v2/cmdb/firewall/address/{urllib.parse.quote(name, safe='')}")

    def _ensure_group(self, grp_name: str) -> None:
        try:
            self._get(f"/api/v2/cmdb/firewall/addrgrp/{urllib.parse.quote(grp_name, safe='')}")
        except Exception:
            self._post("/api/v2/cmdb/firewall/addrgrp", {
                "name":    grp_name,
                "member":  [{"name": "none"}],
                "comment": "SafeLabs MCP — managed group",
            })

    def _add_to_group(self, grp_name: str, member_name: str) -> None:
        self._ensure_group(grp_name)
        try:
            r = self._get(f"/api/v2/cmdb/firewall/addrgrp/{urllib.parse.quote(grp_name, safe='')}")
            current = [m["name"] for m in r.get("results", [{}])[0].get("member", [])
                       if m.get("name") not in ("none", "")]
        except Exception:
            current = []
        if member_name not in current:
            current.append(member_name)
        self._put(f"/api/v2/cmdb/firewall/addrgrp/{urllib.parse.quote(grp_name, safe='')}", {
            "member": [{"name": n} for n in current],
        })

    def _remove_from_group(self, grp_name: str, member_name: str) -> None:
        try:
            r = self._get(f"/api/v2/cmdb/firewall/addrgrp/{urllib.parse.quote(grp_name, safe='')}")
            current = [m["name"] for m in r.get("results", [{}])[0].get("member", [])
                       if m.get("name") not in ("none", "", member_name)]
        except Exception:
            return
        if not current:
            current = ["none"]
        self._put(f"/api/v2/cmdb/firewall/addrgrp/{urllib.parse.quote(grp_name, safe='')}", {
            "member": [{"name": n} for n in current],
        })

    def _list_group(self, grp_name: str) -> list[str]:
        try:
            r = self._get(f"/api/v2/cmdb/firewall/addrgrp/{urllib.parse.quote(grp_name, safe='')}")
            return [m["name"] for m in r.get("results", [{}])[0].get("member", [])
                    if m.get("name") not in ("none", "")]
        except Exception:
            return []

    # ---- IP blocking ----

    def block_ip(self, ip: str, comment: str = "SafeLabs MCP") -> str:
        name = f"{PFX}-ip-{ip.replace('/', '_').replace('.', '_')}"
        if self._addr_exists(name):
            current = self._list_group(GRP_IP)
            if name not in current:
                self._add_to_group(GRP_IP, name)
                return f"FIXED_GROUP:{ip}:{name}"
            return f"ALREADY_BLOCKED:{ip}:{name}"
        self._create_addr(name, ip, comment)
        self._add_to_group(GRP_IP, name)
        return f"BLOCKED_IP:{ip}:{name}"

    def unblock_ip(self, ip: str) -> str:
        name = f"{PFX}-ip-{ip.replace('/', '_').replace('.', '_')}"
        self._remove_from_group(GRP_IP, name)
        try:
            self._delete_addr(name)
        except Exception:
            pass
        return f"UNBLOCKED_IP:{ip}"

    # ---- DNS filter (domain blocking) ----

    def _ensure_dns_filter(self) -> None:
        try:
            self._get("/api/v2/cmdb/dnsfilter/domain-filter/1")
        except Exception:
            self._post("/api/v2/cmdb/dnsfilter/domain-filter", {
                "id": 1, "name": DNS_FLT,
            })

    def _dns_filter_entries(self) -> list[dict]:
        try:
            r = self._get("/api/v2/cmdb/dnsfilter/domain-filter/1/entries")
            return r.get("results", [])
        except Exception:
            return []

    def _find_dns_entry_id(self, domain: str) -> int | None:
        for e in self._dns_filter_entries():
            if e.get("domain", "").lower() == domain.lower():
                return e.get("id")
        return None

    def block_domain(self, domain: str) -> str:
        results = []
        self._ensure_dns_filter()
        if self._find_dns_entry_id(domain) is None:
            self._post("/api/v2/cmdb/dnsfilter/domain-filter/1/entries", {
                "domain": domain, "type": 2, "action": 1, "status": 1,
            })
            results.append("DNS_FILTER")
        self._ensure_url_filter()
        if self._find_url_entry_id(domain) is None:
            self._post("/api/v2/cmdb/webfilter/urlfilter/1/entries", {
                "url": domain, "type": 2, "action": 0, "status": 1,
            })
            results.append("URL_FILTER")
        if not results:
            return f"ALREADY_BLOCKED:{domain}"
        self._ensure_dns_filter_applied()
        self._ensure_url_filter_applied()
        return f"BLOCKED_DOMAIN:{domain}:{'+'.join(results)}"

    def unblock_domain(self, domain: str) -> str:
        removed = []
        eid = self._find_dns_entry_id(domain)
        if eid is not None:
            self._delete(f"/api/v2/cmdb/dnsfilter/domain-filter/1/entries/{eid}")
            removed.append("DNS_FILTER")
        uid = self._find_url_entry_id(domain)
        if uid is not None:
            self._delete(f"/api/v2/cmdb/webfilter/urlfilter/1/entries/{uid}")
            removed.append("URL_FILTER")
        if removed:
            return f"UNBLOCKED_DOMAIN:{domain}:{'+'.join(removed)}"
        return f"NOT_FOUND:{domain}"

    def list_blocked_domains(self) -> list[str]:
        return [e.get("domain", "") for e in self._dns_filter_entries()
                if e.get("action") == 1]

    # ---- URL filter ----

    def _ensure_url_filter(self) -> None:
        try:
            self._get("/api/v2/cmdb/webfilter/urlfilter/1")
        except Exception:
            self._post("/api/v2/cmdb/webfilter/urlfilter", {
                "id": 1, "name": URL_FLT,
            })

    def _url_filter_entries(self) -> list[dict]:
        try:
            r = self._get("/api/v2/cmdb/webfilter/urlfilter/1/entries")
            return r.get("results", [])
        except Exception:
            return []

    def _find_url_entry_id(self, url: str) -> int | None:
        for e in self._url_filter_entries():
            if e.get("url", "").lower() == url.lower():
                return e.get("id")
        return None

    def block_url(self, url: str) -> str:
        self._ensure_url_filter()
        existing = self._find_url_entry_id(url)
        if existing is not None:
            return f"ALREADY_BLOCKED:{url}"
        self._post("/api/v2/cmdb/webfilter/urlfilter/1/entries", {
            "url": url, "type": 2, "action": 0, "status": 1,
        })
        self._ensure_url_filter_applied()
        return f"BLOCKED_URL:{url}"

    def unblock_url(self, url: str) -> str:
        eid = self._find_url_entry_id(url)
        if eid is None:
            return f"NOT_FOUND:{url}"
        self._delete(f"/api/v2/cmdb/webfilter/urlfilter/1/entries/{eid}")
        return f"UNBLOCKED_URL:{url}"

    def list_blocked_urls(self) -> list[str]:
        return [e.get("url", "") for e in self._url_filter_entries()
                if e.get("action") == 0]

    # ---- host isolation ----

    def isolate_host(self, ip: str, comment: str = "SafeLabs MCP — host isolation") -> str:
        name = f"{PFX}-isolated-{ip.replace('.', '_')}"
        already = self._addr_exists(name)
        if not already:
            self._create_addr(name, ip, comment)
            self._add_to_group(GRP_ISO, name)
        self._ensure_isolation_policy()
        _clear_sessions_ssh(ip)
        status = "ALREADY_ISOLATED" if already else "ISOLATED"
        return f"{status}:{ip}:{name}"

    def deisolate_host(self, ip: str) -> str:
        name = f"{PFX}-isolated-{ip.replace('.', '_')}"
        self._remove_from_group(GRP_ISO, name)
        try:
            self._delete_addr(name)
        except Exception:
            pass
        remaining = self._list_group(GRP_ISO)
        if not remaining:
            self._restore_egress_policy()
        return f"DEISOLATED:{ip}"

    def _restore_egress_policy(self) -> None:
        """Restore LAB_TO_INTERNET srcaddr to original when no hosts are isolated."""
        try:
            r = self._get("/api/v2/cmdb/firewall/policy", params={"filter": "name==LAB_TO_INTERNET"})
            policies = r.get("results", [])
            if policies:
                pol_id = policies[0].get("policyid")
                self._put(f"/api/v2/cmdb/firewall/policy/{pol_id}", {
                    "srcaddr": [{"name": "LAB_INTERNAL_SUBNETS"}],
                    "srcaddr-negate": "disable",
                })
        except Exception:
            pass

    # ---- list IOCs ----

    def list_iocs(self) -> dict:
        return {
            "blocked_ips":     self._list_group(GRP_IP),
            "blocked_geos":    self._list_group(GRP_GEO),
            "isolated_hosts":  self._list_group(GRP_ISO),
            "blocked_domains": self.list_blocked_domains(),
            "blocked_urls":    self.list_blocked_urls(),
        }

    # ---- security profile binding (ensures filters actually block traffic) ----

    def _ensure_dns_filter_applied(self) -> None:
        """Ensure a DNS filter profile exists and is referenced by a security policy."""
        profile_name = DNS_FLT
        try:
            self._get(f"/api/v2/cmdb/dnsfilter/profile/{urllib.parse.quote(profile_name, safe='')}")
        except Exception:
            self._post("/api/v2/cmdb/dnsfilter/profile", {
                "name": profile_name,
                "domain-filter": {"domain-filter-table": 1},
                "comment": "SafeLabs MCP managed DNS filter profile",
            })
        self._ensure_utm_policy(dns_profile=profile_name)

    def _ensure_url_filter_applied(self) -> None:
        """Ensure a webfilter profile exists and is referenced by a security policy."""
        profile_name = URL_FLT
        try:
            self._get(f"/api/v2/cmdb/webfilter/profile/{urllib.parse.quote(profile_name, safe='')}")
        except Exception:
            self._post("/api/v2/cmdb/webfilter/profile", {
                "name": profile_name,
                "web": {"urlfilter-table": 1},
                "comment": "SafeLabs MCP managed URL filter profile",
            })
        self._ensure_utm_policy(webfilter_profile=profile_name)

    def _ensure_utm_policy(self, dns_profile: str | None = None,
                           webfilter_profile: str | None = None) -> None:
        """Ensure a UTM-enabled policy exists to enforce DNS/URL filtering."""
        pol_name = UTM_POL
        try:
            r = self._get(f"/api/v2/cmdb/firewall/policy", params={"filter": f"name=={pol_name}"})
            existing = r.get("results", [])
            if existing:
                updates: dict[str, Any] = {"utm-status": "enable"}
                if dns_profile:
                    updates["dnsfilter-profile"] = dns_profile
                if webfilter_profile:
                    updates["webfilter-profile"] = webfilter_profile
                pol_id = existing[0].get("policyid")
                self._put(f"/api/v2/cmdb/firewall/policy/{pol_id}", updates)
                return
        except Exception:
            pass
        policy: dict[str, Any] = {
            "name":         pol_name,
            "srcintf":      [{"name": "any"}],
            "dstintf":      [{"name": "any"}],
            "srcaddr":      [{"name": "all"}],
            "dstaddr":      [{"name": "all"}],
            "action":       "accept",
            "schedule":     "always",
            "service":      [{"name": "ALL"}],
            "utm-status":   "enable",
            "inspection-mode": "proxy",
            "ssl-ssh-profile": "certificate-inspection",
            "logtraffic":   "all",
            "comment":      "SafeLabs MCP — UTM enforcement for DNS/URL blocking",
        }
        if dns_profile:
            policy["dnsfilter-profile"] = dns_profile
        if webfilter_profile:
            policy["webfilter-profile"] = webfilter_profile
        try:
            self._post("/api/v2/cmdb/firewall/policy", policy)
        except Exception:
            pass

    def _ensure_isolation_policy(self) -> None:
        """
        Enforce isolation via srcaddr-negate on existing egress policies.
        Sets srcaddr = isolated-hosts group + srcaddr-negate = enable on the
        main LAB_TO_INTERNET policy, so isolated hosts get implicit deny.
        """
        self._ensure_group(GRP_ISO)
        try:
            r = self._get("/api/v2/cmdb/firewall/policy", params={"filter": "name==LAB_TO_INTERNET"})
            policies = r.get("results", [])
            if policies:
                pol_id = policies[0].get("policyid")
                self._put(f"/api/v2/cmdb/firewall/policy/{pol_id}", {
                    "srcaddr": [{"name": GRP_ISO}],
                    "srcaddr-negate": "enable",
                })
        except Exception:
            pass

    def close(self):
        pass


# ---------------------------------------------------------------------------
# FortiGate SSH CLI (fallback transport)
# ---------------------------------------------------------------------------

class _FGCli:
    """Sessão SSH interativa com o FortiGate."""

    def __init__(self):
        try:
            import paramiko
        except ImportError:
            raise RuntimeError("pip install paramiko")
        self._ssh = paramiko.SSHClient()
        self._ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._ssh.connect(
            FW_HOST, port=22, username=FW_SSH_USER, password=FW_SSH_PASS,
            timeout=15, look_for_keys=False, allow_agent=False,
        )
        self._sh = self._ssh.invoke_shell(width=300, height=200)
        time.sleep(1.5)
        self._drain()

    def _drain(self, timeout: float = 3.0, idle: float = 0.8) -> str:
        buf = b""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._sh.recv_ready():
                buf += self._sh.recv(8192)
                deadline = time.time() + idle
            else:
                time.sleep(0.2)
        return buf.decode("utf-8", errors="replace")

    def run(self, cmd: str, wait: float = 0.8) -> str:
        self._sh.send(cmd + "\n")
        time.sleep(wait)
        return self._drain(timeout=3.0, idle=0.6)

    def exec_block(self, cmds: list[str], wait: float = 0.4) -> str:
        return "\n".join(self.run(c, wait) for c in cmds)

    def close(self):
        try:
            self._sh.close()
            self._ssh.close()
        except Exception:
            pass

    # ---- status ----

    def status(self) -> dict:
        out = self.run("get system status", wait=3)
        info: dict[str, str] = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                info[k.strip()] = v.strip()
        return {
            "host":     FW_HOST,
            "version":  info.get("Version", "?"),
            "serial":   info.get("Serial-Number", "?"),
            "hostname": info.get("Hostname", "?"),
            "transport": "ssh",
        }

    # ---- helpers ----

    def _addr_exists(self, name: str) -> bool:
        out = self.run(f'show firewall address "{name}"', wait=1.5)
        return f'edit "{name}"' in out

    def _ensure_group(self, name: str) -> None:
        out = self.run(f'show firewall addrgrp "{name}"', wait=1.5)
        if f'edit "{name}"' in out:
            return
        self.exec_block([
            "config firewall addrgrp",
            f'  edit "{name}"',
            '    set member "none"',
            f'    set comment "SafeLabs MCP — managed group"',
            "  next", "end",
        ])

    def _remove_from_group(self, grp: str, member: str) -> None:
        out = self.run(f'show firewall addrgrp "{grp}"', wait=2)
        m = re.search(r'set member(.*?)(?=set |next|$)', out, re.DOTALL | re.IGNORECASE)
        if not m:
            return
        members = [x for x in re.findall(r'"([^"]+)"', m.group(1))
                   if x not in (member, "none")]
        mstr = " ".join(f'"{x}"' for x in members) if members else '"none"'
        self.exec_block([
            "config firewall addrgrp",
            f'  edit "{grp}"',
            f'    set member {mstr}',
            "  next", "end",
        ])

    def _list_group(self, grp: str) -> list[str]:
        out = self.run(f'show firewall addrgrp "{grp}"', wait=2)
        m = re.search(r'set member(.*?)(?=set |next|$)', out, re.DOTALL | re.IGNORECASE)
        if not m:
            return []
        return [x for x in re.findall(r'"([^"]+)"', m.group(1)) if x != "none"]

    # ---- IP blocking ----

    def block_ip(self, ip: str, comment: str = "SafeLabs MCP") -> str:
        name = f"{PFX}-ip-{ip.replace('/', '_').replace('.', '_')}"
        if self._addr_exists(name):
            current = self._list_group(GRP_IP)
            if name not in current:
                self._ensure_group(GRP_IP)
                current.append(name)
                mstr = " ".join(f'"{m}"' for m in current)
                self.exec_block([
                    "config firewall addrgrp",
                    f'  edit "{GRP_IP}"',
                    f'    set member {mstr}',
                    "  next", "end",
                ])
                return f"FIXED_GROUP:{ip}:{name}"
            return f"ALREADY_BLOCKED:{ip}:{name}"
        net = ipaddress.ip_network(ip, strict=False)
        self.exec_block([
            "config firewall address",
            f'  edit "{name}"',
            '    set type ipmask',
            f'    set subnet {net.network_address} {net.netmask}',
            f'    set comment "{comment[:63]}"',
            "  next", "end",
        ])
        self._ensure_group(GRP_IP)
        current = self._list_group(GRP_IP)
        current.append(name)
        mstr = " ".join(f'"{m}"' for m in current)
        self.exec_block([
            "config firewall addrgrp",
            f'  edit "{GRP_IP}"',
            f'    set member {mstr}',
            "  next", "end",
        ])
        return f"BLOCKED_IP:{ip}:{name}"

    def unblock_ip(self, ip: str) -> str:
        name = f"{PFX}-ip-{ip.replace('/', '_').replace('.', '_')}"
        self._remove_from_group(GRP_IP, name)
        self.exec_block(["config firewall address", f'  delete "{name}"', "end"])
        return f"UNBLOCKED_IP:{ip}"

    # ---- DNS filter (domain blocking) ----

    def _ensure_dns_filter(self) -> None:
        out = self.run("show dnsfilter domain-filter 1", wait=2)
        if "edit 1" in out:
            return
        self.exec_block([
            "config dnsfilter domain-filter",
            "  edit 1",
            f'    set name "{DNS_FLT}"',
            "  next", "end",
        ])

    def _dns_entries(self) -> list[tuple[int, str]]:
        out = self.run("show dnsfilter domain-filter 1", wait=3)
        entries = []
        for m in re.finditer(r'edit (\d+).*?set domain "([^"]+)"', out, re.DOTALL):
            entries.append((int(m.group(1)), m.group(2)))
        return entries

    def block_domain(self, domain: str) -> str:
        results = []
        # DNS filter (blocks DNS resolution if query crosses FW)
        self._ensure_dns_filter()
        dns_exists = any(d.lower() == domain.lower() for _, d in self._dns_entries())
        if not dns_exists:
            out = self.run("show dnsfilter domain-filter 1", wait=2)
            ids = [int(x) for x in re.findall(r"edit (\d+)", out)]
            next_id = max((x for x in ids if x != 1), default=0) + 1
            self.exec_block([
                "config dnsfilter domain-filter",
                "  edit 1", "  config entries",
                f'    edit {next_id}',
                f'      set domain "{domain}"',
                '      set type wildcard',
                '      set action block',
                "    next", "  end",
                "  next", "end",
            ], wait=0.4)
            results.append("DNS_FILTER")
        # URL/webfilter (blocks HTTPS connection via SNI even if DNS is local)
        self._ensure_url_filter()
        url_exists = any(u.lower() == domain.lower() for _, u in self._url_entries())
        if not url_exists:
            out = self.run("show webfilter urlfilter 1", wait=2)
            ids = [int(x) for x in re.findall(r"edit (\d+)", out)]
            next_id = max((x for x in ids if x != 1), default=0) + 1
            self.exec_block([
                "config webfilter urlfilter",
                "  edit 1", "  config entries",
                f'    edit {next_id}',
                f'      set url "{domain}"',
                '      set type wildcard',
                '      set action block',
                "    next", "  end",
                "  next", "end",
            ], wait=0.4)
            results.append("URL_FILTER")
        if not results:
            return f"ALREADY_BLOCKED:{domain}"
        return f"BLOCKED_DOMAIN:{domain}:{'+'.join(results)}"

    def unblock_domain(self, domain: str) -> str:
        removed = []
        # Remove from DNS filter
        for eid, d in self._dns_entries():
            if d.lower() == domain.lower():
                self.exec_block([
                    "config dnsfilter domain-filter",
                    "  edit 1", "  config entries",
                    f"    delete {eid}",
                    "  end", "  next", "end",
                ])
                removed.append("DNS_FILTER")
                break
        # Remove from URL filter
        for eid, u in self._url_entries():
            if u.lower() == domain.lower():
                self.exec_block([
                    "config webfilter urlfilter",
                    "  edit 1", "  config entries",
                    f"    delete {eid}",
                    "  end", "  next", "end",
                ])
                removed.append("URL_FILTER")
                break
        if removed:
            return f"UNBLOCKED_DOMAIN:{domain}:{'+'.join(removed)}"
        return f"NOT_FOUND:{domain}"

    def list_blocked_domains(self) -> list[str]:
        return [d for _, d in self._dns_entries()]

    # ---- URL filter ----

    def _ensure_url_filter(self) -> None:
        out = self.run("show webfilter urlfilter 1", wait=2)
        if "edit 1" in out:
            return
        self.exec_block([
            "config webfilter urlfilter",
            "  edit 1",
            f'    set name "{URL_FLT}"',
            "  next", "end",
        ])

    def _url_entries(self) -> list[tuple[int, str]]:
        out = self.run("show webfilter urlfilter 1", wait=3)
        entries = []
        for m in re.finditer(r'edit (\d+).*?set url "([^"]+)"', out, re.DOTALL):
            entries.append((int(m.group(1)), m.group(2)))
        return entries

    def block_url(self, url: str) -> str:
        self._ensure_url_filter()
        for _, u in self._url_entries():
            if u.lower() == url.lower():
                return f"ALREADY_BLOCKED:{url}"
        out = self.run("show webfilter urlfilter 1", wait=2)
        ids = [int(x) for x in re.findall(r"edit (\d+)", out)]
        next_id = max((x for x in ids if x != 1), default=0) + 1
        self.exec_block([
            "config webfilter urlfilter",
            "  edit 1", "  config entries",
            f'    edit {next_id}',
            f'      set url "{url}"',
            '      set type wildcard',
            '      set action block',
            "    next", "  end",
            "  next", "end",
        ], wait=0.4)
        self._ensure_url_filter_applied()
        return f"BLOCKED_URL:{url}"

    def unblock_url(self, url: str) -> str:
        for eid, u in self._url_entries():
            if u.lower() == url.lower():
                self.exec_block([
                    "config webfilter urlfilter",
                    "  edit 1", "  config entries",
                    f"    delete {eid}",
                    "  end", "  next", "end",
                ])
                return f"UNBLOCKED_URL:{url}"
        return f"NOT_FOUND:{url}"

    def list_blocked_urls(self) -> list[str]:
        return [u for _, u in self._url_entries()]

    # ---- host isolation ----

    def _clear_host_sessions(self, ip: str) -> None:
        """Kill all existing firewall sessions from/to a host so policy changes take effect immediately."""
        self.run(f"diagnose sys session filter src {ip}", wait=0.5)
        self.run("diagnose sys session clear", wait=1)
        self.run("diagnose sys session filter clear", wait=0.3)
        self.run(f"diagnose sys session filter dst {ip}", wait=0.5)
        self.run("diagnose sys session clear", wait=1)
        self.run("diagnose sys session filter clear", wait=0.3)

    def isolate_host(self, ip: str, comment: str = "SafeLabs MCP — host isolation") -> str:
        name = f"{PFX}-isolated-{ip.replace('.', '_')}"
        already = self._addr_exists(name)
        if not already:
            net = ipaddress.ip_network(ip, strict=False)
            self.exec_block([
                "config firewall address",
                f'  edit "{name}"',
                '    set type ipmask',
                f'    set subnet {net.network_address} {net.netmask}',
                f'    set comment "{comment[:63]}"',
                "  next", "end",
            ])
            self._ensure_group(GRP_ISO)
            current = self._list_group(GRP_ISO)
            current.append(name)
            mstr = " ".join(f'"{m}"' for m in current)
            self.exec_block([
                "config firewall addrgrp",
                f'  edit "{GRP_ISO}"',
                f'    set member {mstr}',
                "  next", "end",
            ])
        self._ensure_isolation_policy()
        self._clear_host_sessions(ip)
        status = "ALREADY_ISOLATED" if already else "ISOLATED"
        return f"{status}:{ip}:{name}"

    def deisolate_host(self, ip: str) -> str:
        name = f"{PFX}-isolated-{ip.replace('.', '_')}"
        self._remove_from_group(GRP_ISO, name)
        self.exec_block(["config firewall address", f'  delete "{name}"', "end"])
        remaining = self._list_group(GRP_ISO)
        if not remaining:
            self._restore_egress_policy()
        return f"DEISOLATED:{ip}"

    def _restore_egress_policy(self) -> None:
        """Restore LAB_TO_INTERNET srcaddr when no hosts are isolated."""
        self.exec_block([
            "config firewall policy",
            "  edit 1",
            '    set srcaddr "LAB_INTERNAL_SUBNETS"',
            '    set srcaddr-negate disable',
            "  next", "end",
        ])

    # ---- list IOCs ----

    def list_iocs(self) -> dict:
        return {
            "blocked_ips":     self._list_group(GRP_IP),
            "blocked_geos":    self._list_group(GRP_GEO),
            "isolated_hosts":  self._list_group(GRP_ISO),
            "blocked_domains": self.list_blocked_domains(),
            "blocked_urls":    self.list_blocked_urls(),
        }

    # ---- security profile binding (SSH variant) ----

    def _ensure_dns_filter_applied(self) -> None:
        """Ensure policy 1 (LAB_TO_INTERNET) has UTM + dnsfilter enabled."""
        self.exec_block([
            "config firewall policy",
            "  edit 1",
            "    set utm-status enable",
            "  next", "end",
        ])

    def _ensure_url_filter_applied(self) -> None:
        """Ensure policy 1 (LAB_TO_INTERNET) has UTM + webfilter enabled."""
        self.exec_block([
            "config firewall policy",
            "  edit 1",
            "    set utm-status enable",
            "  next", "end",
        ])

    def _ensure_isolation_policy(self) -> None:
        """Enforce isolation via srcaddr-negate on the LAB_TO_INTERNET policy."""
        self._ensure_group(GRP_ISO)
        self.exec_block([
            "config firewall policy",
            '  edit 1',
            f'    set srcaddr "{GRP_ISO}"',
            '    set srcaddr-negate enable',
            "  next", "end",
        ])


# ---------------------------------------------------------------------------
# Session clearing (needed after policy changes to force immediate effect)
# ---------------------------------------------------------------------------

def _clear_sessions_ssh(ip: str) -> None:
    """Clear all FW sessions for a host via SSH. Required after isolation/policy changes."""
    try:
        import paramiko
        ssh_c = paramiko.SSHClient()
        ssh_c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_c.connect(FW_HOST, port=22, username=FW_SSH_USER, password=FW_SSH_PASS,
                      timeout=10, look_for_keys=False, allow_agent=False)
        sh = ssh_c.invoke_shell(width=200, height=100)
        time.sleep(1)
        for cmd in [
            f"diagnose sys session filter src {ip}",
            "diagnose sys session clear",
            "diagnose sys session filter clear",
            f"diagnose sys session filter dst {ip}",
            "diagnose sys session clear",
            "diagnose sys session filter clear",
        ]:
            sh.send(cmd + "\n")
            time.sleep(0.5)
        ssh_c.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Transport selection: API-first, SSH fallback
# ---------------------------------------------------------------------------

_transport_mode: str | None = None


def _get_client() -> _FGApi | _FGCli:
    """Return the best available FortiGate client, preferring REST API."""
    global _transport_mode
    if TRANSPORT == "ssh":
        _transport_mode = "ssh"
        return _FGCli()
    if FW_API_KEY:
        try:
            api = _FGApi()
            if api.check():
                _transport_mode = "api"
                return api
        except Exception:
            pass
    _transport_mode = "ssh"
    return _FGCli()


# ---------------------------------------------------------------------------
# TTL management: temporary blocks that auto-expire
# ---------------------------------------------------------------------------

def _load_ttl() -> dict:
    if TTL_FILE.is_file():
        try:
            return json.loads(TTL_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_ttl(data: dict) -> None:
    TTL_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _register_ttl(ioc_type: str, value: str, ttl_minutes: int) -> None:
    if ttl_minutes <= 0:
        return
    data = _load_ttl()
    key = f"{ioc_type}:{value}"
    data[key] = {
        "type":    ioc_type,
        "value":   value,
        "expires": time.time() + (ttl_minutes * 60),
    }
    _save_ttl(data)


def _ttl_cleanup_loop() -> None:
    """Background thread that unblocks expired IOCs."""
    while True:
        time.sleep(60)
        try:
            data = _load_ttl()
            now = time.time()
            expired = [k for k, v in data.items() if v.get("expires", 0) < now]
            if not expired:
                continue
            cli = _get_client()
            for key in expired:
                entry = data[key]
                itype, val = entry["type"], entry["value"]
                try:
                    if itype == "ip":
                        cli.unblock_ip(val)
                    elif itype == "domain":
                        cli.unblock_domain(val)
                    elif itype == "url":
                        cli.unblock_url(val)
                    elif itype == "isolate":
                        cli.deisolate_host(val)
                except Exception:
                    pass
                del data[key]
            _save_ttl(data)
            cli.close()
        except Exception:
            pass


threading.Thread(target=_ttl_cleanup_loop, daemon=True).start()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_list(path: Path) -> list[str]:
    """Lê arquivo de lista — ignora linhas vazias e comentários."""
    values = []
    for line in path.read_text(encoding="utf-8-sig").splitlines():
        line = line.split("#")[0].strip()
        if line:
            values.append(line)
    return values


# ---------------------------------------------------------------------------
# MCP Server
# ---------------------------------------------------------------------------

mcp = FastMCP(
    "safelabs-fw",
    instructions=(
        "Firewall containment tools for SafeLabs SOC. "
        "Operates on FortiGate via REST API (preferred) or SSH CLI (fallback). "
        "All objects use prefix 'safelabs-' to avoid touching existing rules. "
        "Always prefer blocking specific IPs/domains over broad actions. "
        "Confirm before bulk operations."
    ),
)


@mcp.tool()
def fw_status() -> str:
    """Retorna status do firewall (versão, hostname, serial, transporte)."""
    try:
        cli = _get_client()
        s   = cli.status()
        cli.close()
        return json.dumps(s, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def fw_block_ip(ip: str, comment: str = "SafeLabs SOC",
                ttl_minutes: int = 0) -> str:
    """
    Bloqueia um IP ou CIDR no FortiGate (entrada e saída).

    Args:
        ip: Endereço IP ou CIDR a bloquear (ex: '1.2.3.4', '10.0.0.0/24')
        comment: Motivo do bloqueio (máx 63 chars)
        ttl_minutes: Minutos até expirar (0 = permanente)
    """
    try:
        cli = _get_client()
        r   = cli.block_ip(ip, comment)
        cli.close()
        if ttl_minutes > 0:
            _register_ttl("ip", ip, ttl_minutes)
        return f"[OK] {r}"
    except Exception as e:
        return f"[ERRO] block_ip({ip}): {e}"


@mcp.tool()
def fw_unblock_ip(ip: str) -> str:
    """Remove o bloqueio de um IP/CIDR no FortiGate."""
    try:
        cli = _get_client()
        r   = cli.unblock_ip(ip)
        cli.close()
        return f"[OK] {r}"
    except Exception as e:
        return f"[ERRO] unblock_ip({ip}): {e}"


@mcp.tool()
def fw_block_domain(domain: str, ttl_minutes: int = 0) -> str:
    """
    Bloqueia resolução de domínio no DNS filter do FortiGate (wildcard).

    Args:
        domain: Domínio a bloquear (ex: 'malicious.com')
        ttl_minutes: Minutos até expirar (0 = permanente)
    """
    try:
        cli = _get_client()
        r   = cli.block_domain(domain)
        cli.close()
        if ttl_minutes > 0:
            _register_ttl("domain", domain, ttl_minutes)
        return f"[OK] {r}"
    except Exception as e:
        return f"[ERRO] block_domain({domain}): {e}"


@mcp.tool()
def fw_unblock_domain(domain: str) -> str:
    """Remove o bloqueio de um domínio no DNS filter do FortiGate."""
    try:
        cli = _get_client()
        r   = cli.unblock_domain(domain)
        cli.close()
        return f"[OK] {r}"
    except Exception as e:
        return f"[ERRO] unblock_domain({domain}): {e}"


@mcp.tool()
def fw_block_url(url: str, ttl_minutes: int = 0) -> str:
    """
    Bloqueia uma URL específica no web filter do FortiGate.

    Args:
        url: URL a bloquear
        ttl_minutes: Minutos até expirar (0 = permanente)
    """
    try:
        cli = _get_client()
        r   = cli.block_url(url)
        cli.close()
        if ttl_minutes > 0:
            _register_ttl("url", url, ttl_minutes)
        return f"[OK] {r}"
    except Exception as e:
        return f"[ERRO] block_url({url}): {e}"


@mcp.tool()
def fw_unblock_url(url: str) -> str:
    """Remove o bloqueio de uma URL no web filter do FortiGate."""
    try:
        cli = _get_client()
        r   = cli.unblock_url(url)
        cli.close()
        return f"[OK] {r}"
    except Exception as e:
        return f"[ERRO] unblock_url({url}): {e}"


@mcp.tool()
def fw_isolate_host(ip: str, reason: str = "Compromised host",
                    ttl_minutes: int = 0) -> str:
    """
    Isola um host interno no FortiGate. Cria policy de deny outbound + DNS.
    O host perde acesso à internet e não consegue resolver DNS externo.

    Args:
        ip: IP do host interno a isolar
        reason: Motivo do isolamento
        ttl_minutes: Minutos até expirar (0 = permanente)
    """
    try:
        cli = _get_client()
        r   = cli.isolate_host(ip, reason)
        cli.close()
        if ttl_minutes > 0:
            _register_ttl("isolate", ip, ttl_minutes)
        return f"[OK] {r}\n⚠ Host {ip} isolado. Use fw_deisolate_host para remover."
    except Exception as e:
        return f"[ERRO] isolate_host({ip}): {e}"


@mcp.tool()
def fw_deisolate_host(ip: str) -> str:
    """Remove o isolamento de um host no FortiGate."""
    try:
        cli = _get_client()
        r   = cli.deisolate_host(ip)
        cli.close()
        return f"[OK] {r}"
    except Exception as e:
        return f"[ERRO] deisolate_host({ip}): {e}"


@mcp.tool()
def fw_list_iocs() -> str:
    """Lista todos os IOCs bloqueados no FortiGate (IPs, domínios, URLs, hosts isolados)."""
    try:
        cli  = _get_client()
        data = cli.list_iocs()
        cli.close()
        return json.dumps(data, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
def fw_block_ip_list(list_name: str, comment: str = "SafeLabs MCP bulk block") -> str:
    """
    Bloqueia todos os IPs de um arquivo de lista pré-carregado.

    Args:
        list_name: Nome da lista em ioc_lists/ (sem extensão .txt)
        comment: Razão do bloqueio
    """
    list_path = IOC_LISTS_DIR / f"{list_name}.txt"
    if not list_path.is_file():
        available = [f.stem for f in IOC_LISTS_DIR.glob("*.txt")]
        return f"[ERRO] Lista '{list_name}' não encontrada. Disponíveis: {available}"
    ips = _read_list(list_path)
    if not ips:
        return "[AVISO] Lista vazia."
    try:
        cli = _get_client()
        results = []
        for ip in ips:
            try:
                r = cli.block_ip(ip, comment)
                results.append(f"[OK] {r}")
            except Exception as e:
                results.append(f"[ERRO] {ip}: {e}")
        cli.close()
        ok   = sum(1 for r in results if r.startswith("[OK]"))
        fail = len(results) - ok
        return f"Lista '{list_name}': {ok} bloqueados | {fail} erros\n" + "\n".join(results[:20])
    except Exception as e:
        return f"[ERRO] conexão FW: {e}"


@mcp.tool()
def fw_block_domain_list(list_name: str) -> str:
    """
    Bloqueia todos os domínios de um arquivo de lista.

    Args:
        list_name: Nome da lista (ex: 'apt44_domains')
    """
    list_path = IOC_LISTS_DIR / f"{list_name}.txt"
    if not list_path.is_file():
        available = [f.stem for f in IOC_LISTS_DIR.glob("*.txt")]
        return f"[ERRO] Lista '{list_name}' não encontrada. Disponíveis: {available}"
    domains = _read_list(list_path)
    if not domains:
        return "[AVISO] Lista vazia."
    try:
        cli = _get_client()
        results = []
        for domain in domains:
            try:
                r = cli.block_domain(domain)
                results.append(f"[OK] {r}")
            except Exception as e:
                results.append(f"[ERRO] {domain}: {e}")
        cli.close()
        ok   = sum(1 for r in results if r.startswith("[OK]"))
        fail = len(results) - ok
        return f"Lista '{list_name}': {ok} bloqueados | {fail} erros\n" + "\n".join(results[:20])
    except Exception as e:
        return f"[ERRO] conexão FW: {e}"


@mcp.tool()
def fw_list_available_lists() -> str:
    """Lista todos os arquivos de IOCs disponíveis na pasta ioc_lists/."""
    lists = []
    for f in sorted(IOC_LISTS_DIR.glob("*.txt")):
        lines = _read_list(f)
        lists.append(f"  {f.stem} ({len(lines)} entradas) — {f.name}")
    if not lists:
        return "Nenhuma lista encontrada em ioc_lists/"
    return "Listas disponíveis:\n" + "\n".join(lists)


# ---------------------------------------------------------------------------
# Resources
# ---------------------------------------------------------------------------

@mcp.resource("ioc://apt44/ips")
def apt44_ips_resource() -> str:
    p = IOC_LISTS_DIR / "apt44_ips.txt"
    return p.read_text(encoding="utf-8") if p.is_file() else "Arquivo não encontrado"


@mcp.resource("ioc://apt44/domains")
def apt44_domains_resource() -> str:
    p = IOC_LISTS_DIR / "apt44_domains.txt"
    return p.read_text(encoding="utf-8") if p.is_file() else "Arquivo não encontrado"


@mcp.resource("ioc://apt44/hashes")
def apt44_hashes_resource() -> str:
    p = IOC_LISTS_DIR / "apt44_hashes.txt"
    return p.read_text(encoding="utf-8") if p.is_file() else "Arquivo não encontrado"


if __name__ == "__main__":
    transport = "stdio"
    port = 8090
    for arg in sys.argv[1:]:
        if arg == "--sse":
            transport = "sse"
        elif arg.startswith("--port="):
            port = int(arg.split("=")[1])
    if transport == "sse":
        mcp.run(transport="sse", host="0.0.0.0", port=port)
    else:
        mcp.run()
