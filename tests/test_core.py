"""CloudXPL-Forge core tests — version, credentials, dispatcher, CLI, manifests."""

from __future__ import annotations

import ast
import importlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_version():
    import cloudxpl
    assert cloudxpl.__version__ == "1.0.0"
    assert cloudxpl.PRODUCT == "CloudXPL-Forge"


def test_cli_name():
    import cloudxpl
    assert cloudxpl.CLI == "cxf"


def test_credential_dataclass():
    from cloudxpl.core.credential import CloudCredential
    cred = CloudCredential(provider="aws", identity="arn:aws:iam::123:user/test")
    assert cred.provider == "aws"
    assert cred.masked_secret == "(none)"
    cred.secret_key = "ABCDEFGHIJKLMNOP"
    assert "****" in cred.masked_secret
    d = cred.to_dict()
    assert "secret_key" not in d


def test_dispatcher_modules():
    from cloudxpl.core.dispatcher import MODULE_MAP
    total = sum(len(v) for v in MODULE_MAP.values())
    assert total == 13
    for provider, modules in MODULE_MAP.items():
        for key, path in modules.items():
            assert "." in path, f"{provider}/{key} module path must be dotted"


def test_cli_help():
    result = subprocess.run(
        [sys.executable, "-m", "cloudxpl", "--help"],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0
    assert "cxf" in result.stdout.lower() or "cloudxpl" in result.stdout.lower()


def test_all_modules_parseable():
    """Every .py under cloudxpl/modules/ must parse without SyntaxError."""
    modules_dir = ROOT / "cloudxpl" / "modules"
    py_files = list(modules_dir.rglob("*.py"))
    assert len(py_files) >= 13
    for py in py_files:
        if py.name == "__init__.py":
            continue
        source = py.read_text()
        ast.parse(source, filename=str(py))


def test_all_modules_have_manifest():
    """Every module (not __init__) must define MANIFEST dict."""
    modules_dir = ROOT / "cloudxpl" / "modules"
    for py in modules_dir.rglob("*.py"):
        if py.name == "__init__.py":
            continue
        source = py.read_text()
        tree = ast.parse(source)
        manifest_found = any(
            isinstance(node, ast.Assign)
            and any(
                isinstance(t, ast.Name) and t.id == "MANIFEST"
                for t in node.targets
            )
            for node in ast.walk(tree)
        )
        assert manifest_found, f"{py.name} missing MANIFEST"


def test_all_modules_have_run():
    """Every module must define a run() function."""
    modules_dir = ROOT / "cloudxpl" / "modules"
    for py in modules_dir.rglob("*.py"):
        if py.name == "__init__.py":
            continue
        source = py.read_text()
        tree = ast.parse(source)
        run_found = any(
            isinstance(node, ast.FunctionDef) and node.name == "run"
            for node in ast.walk(tree)
        )
        assert run_found, f"{py.name} missing run()"


def test_manifest_fields():
    """MANIFEST must have required keys."""
    modules_dir = ROOT / "cloudxpl" / "modules"
    required_keys = {"capability_id", "safety_class", "requires_authorization"}
    for py in modules_dir.rglob("*.py"):
        if py.name == "__init__.py":
            continue
        mod_path = (
            str(py.relative_to(ROOT))
            .replace("/", ".")
            .replace(".py", "")
        )
        mod = importlib.import_module(mod_path)
        manifest = getattr(mod, "MANIFEST", None)
        assert manifest is not None, f"{py.name}: MANIFEST not importable"
        for key in required_keys:
            assert key in manifest, f"{py.name}: MANIFEST missing '{key}'"


def test_safety_classes():
    """safety_class must be one of the allowed values."""
    allowed = {"READ_ONLY", "ACTIVE", "DESTRUCTIVE"}
    modules_dir = ROOT / "cloudxpl" / "modules"
    for py in modules_dir.rglob("*.py"):
        if py.name == "__init__.py":
            continue
        mod_path = (
            str(py.relative_to(ROOT))
            .replace("/", ".")
            .replace(".py", "")
        )
        mod = importlib.import_module(mod_path)
        sc = mod.MANIFEST["safety_class"]
        assert sc in allowed, f"{py.name}: invalid safety_class '{sc}'"
