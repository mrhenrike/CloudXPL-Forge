"""Tests for cloudxpl.core.shell_mixin cloud-specific payloads."""


import pytest

pytestmark = pytest.mark.skip(reason="xpl_core.shells not yet extracted; see shell-integration plan")

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cloudxpl.core.shell_mixin import (
    CLOUD_SHELL_TYPES,
    _cloud_payload,
    get_session_manager,
)


def test_cloud_shell_types_tuple():
    assert isinstance(CLOUD_SHELL_TYPES, tuple)
    assert "python" in CLOUD_SHELL_TYPES
    assert "bash" in CLOUD_SHELL_TYPES
    assert "lambda_reverse" in CLOUD_SHELL_TYPES

def test_lambda_reverse_payload():
    payload = _cloud_payload("lambda_reverse", "10.0.0.1", 4444)
    assert "10.0.0.1" in payload
    assert "4444" in payload
    assert "python3" in payload

def test_cloud_init_inject_payload():
    payload = _cloud_payload("cloud_init_inject", "192.168.1.1", 9999)
    assert "#cloud-config" in payload
    assert "192.168.1.1" in payload
    assert "9999" in payload

def test_ssrf_imds_shell_payload():
    payload = _cloud_payload("ssrf_imds_shell", "10.10.10.1", 5555)
    assert "169.254.169.254" in payload
    assert "10.10.10.1" in payload
    assert "5555" in payload

def test_fallback_to_generate_payload():
    payload = _cloud_payload("bash", "10.0.0.1", 4444)
    assert "10.0.0.1" in payload
    assert "4444" in payload

def test_get_session_manager():
    mgr = get_session_manager()
    from xpl_core.shells import SessionManager
    assert isinstance(mgr, SessionManager)

def test_session_manager_singleton():
    mgr1 = get_session_manager()
    mgr2 = get_session_manager()
    assert mgr1 is mgr2

def test_cloud_shell_types_count():
    assert len(CLOUD_SHELL_TYPES) >= 5
