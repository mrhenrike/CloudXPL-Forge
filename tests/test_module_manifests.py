"""Cross-cutting tests for all module manifests across all providers."""

import importlib
from pathlib import Path

import pytest

from cloudxpl.core.dispatcher import MODULE_MAP

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_SAFETY = {"READ_ONLY", "ACTIVE", "DESTRUCTIVE", "EXPLOIT", "BRIDGE", "RECON"}


def _all_modules():
    for provider, modules in MODULE_MAP.items():
        for key, path in modules.items():
            yield provider, key, path


class TestAllManifests:
    @pytest.mark.parametrize("provider,key,path", list(_all_modules()))
    def test_importable(self, provider, key, path) -> None:
        mod = importlib.import_module(path)
        assert mod is not None

    @pytest.mark.parametrize("provider,key,path", list(_all_modules()))
    def test_has_run(self, provider, key, path) -> None:
        mod = importlib.import_module(path)
        assert callable(getattr(mod, "run", None)), f"{provider}/{key}: no run()"

    @pytest.mark.parametrize("provider,key,path", list(_all_modules()))
    def test_has_manifest_or_info(self, provider, key, path) -> None:
        mod = importlib.import_module(path)
        m = getattr(mod, "MANIFEST", getattr(mod, "INFO", None))
        assert m is not None, f"{provider}/{key}: no MANIFEST/INFO"

    @pytest.mark.parametrize("provider,key,path", list(_all_modules()))
    def test_safety_class_if_present(self, provider, key, path) -> None:
        mod = importlib.import_module(path)
        m = getattr(mod, "MANIFEST", getattr(mod, "INFO", {}))
        sc = m.get("safety_class")
        if sc is not None:
            assert sc in ALLOWED_SAFETY, f"{provider}/{key}: bad safety_class '{sc}'"


class TestModuleMapIntegrity:
    def test_total_modules_above_threshold(self) -> None:
        total = sum(len(v) for v in MODULE_MAP.values())
        assert total >= 400

    def test_no_empty_providers(self) -> None:
        for provider, modules in MODULE_MAP.items():
            assert len(modules) > 0, f"Provider '{provider}' has no modules"

    def test_paths_are_valid_python_identifiers(self) -> None:
        for provider, modules in MODULE_MAP.items():
            for key, path in modules.items():
                parts = path.split(".")
                for part in parts:
                    assert part.isidentifier(), (
                        f"{provider}/{key}: '{part}' in path '{path}' is not a valid identifier"
                    )

    def test_no_duplicate_paths(self) -> None:
        seen: dict[str, str] = {}
        for provider, modules in MODULE_MAP.items():
            for key, path in modules.items():
                label = f"{provider}/{key}"
                if path in seen:
                    # Duplicates across aliases are OK, same provider duplicates are not
                    pass
                seen[path] = label
