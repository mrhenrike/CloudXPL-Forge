"""Wrapper stub for cloud security audit orchestrator.

Source: https://github.com/cloudflare/security-audit-skill
License: MIT
SRC-ID: SRC-1019
Category: Cloud audit, multi-phase, recon, adversarial validation

Adapted from Cloudflare's security-audit-skill. Implements a
six-phase audit workflow: recon, coverage-led hunting, adversarial
validation, structured output, independent verification, reporting.
"""

from dataclasses import dataclass


@dataclass
class SecurityAuditConfig:
    target_scope: str = ""
    phases: list[str] | None = None
    output_dir: str = "audit_output"
    max_depth: int = 3
