# Changelog

All notable changes to CloudXPL-Forge will be documented in this file.

## [4.2.0] - 2026-10-19

### Added
- PEP 561 `py.typed` marker for downstream type checking
- `ruff` linter configuration with per-file-ignores for exploit modules (0 errors)
- `mypy` type checker configuration with 26 third-party module overrides
- `pytest` configuration with testpaths and verbose output
- GitHub Actions CI: ruff lint gate + pytest matrix (Python 3.9-3.14)
- New test files: `test_shells_shim.py` (16 tests), `test_credential.py` (10 tests), `test_dispatcher.py` (11 tests), `test_shell_mixin.py` (8 tests)
- Test suite expanded from 11 to 53 tests

### Fixed
- `test_core.py` version assertion updated from v1.0.0 to current
- `test_core.py` manifest detection now handles annotated assignments (`MANIFEST: dict`)
- `test_core.py` safety_class validation includes all current values (EXPLOIT, BRIDGE, RECON)

## [4.1.1] - 2026-10-12

### Fixed
- PyPI republish with corrected package metadata

## [4.1.0] - 2026-10-11

### Added
- 508 modules across 20 categories
- 25 new modules from deep research phase
- Hypervisor CVE research (VMware, Hyper-V, KVM/QEMU, Xen/Citrix, Nutanix, Firecracker, Kata)
- VDI escape modules, PaaS escape modules, CI/CD runner escape modules
- Side-channel attack surface scanners (AMD SEV-SNP, Intel TDX)

## [4.0.1] - 2026-10-10

### Fixed
- PyPI re-upload (v4.0.0 filename already registered)

## [4.0.0] - 2026-10-10

### Added
- Major release: 483 modules across 20 categories
- Cloud-native shell infrastructure via xpl-core integration
- Shell staging mixin with cloud-specific payloads (Lambda, cloud-init, SSRF-IMDS)
