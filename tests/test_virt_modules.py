"""Tests for Virtualization modules: MANIFEST validation and structure."""

import importlib
from pathlib import Path

import pytest

from cloudxpl.core.dispatcher import MODULE_MAP

ROOT = Path(__file__).resolve().parents[1]


def _virt_module_paths():
    for key, path in MODULE_MAP["virt"].items():
        yield key, path


class TestVirtManifests:
    @pytest.mark.parametrize("key,path", list(_virt_module_paths()))
    def test_manifest_present(self, key, path) -> None:
        mod = importlib.import_module(path)
        manifest = getattr(mod, "MANIFEST", getattr(mod, "INFO", None))
        assert manifest is not None, f"Virt/{key}: missing MANIFEST/INFO"

    @pytest.mark.parametrize("key,path", list(_virt_module_paths()))
    def test_has_run_function(self, key, path) -> None:
        mod = importlib.import_module(path)
        assert callable(getattr(mod, "run", None)), f"Virt/{key}: missing run()"


class TestVirtModuleCounts:
    def test_esxi_modules(self) -> None:
        esxi = [k for k in MODULE_MAP["virt"] if "esxi" in k]
        assert len(esxi) >= 5

    def test_hyperv_modules(self) -> None:
        hv = [k for k in MODULE_MAP["virt"] if "hyperv" in k]
        assert len(hv) >= 5

    def test_qemu_modules(self) -> None:
        qemu = [k for k in MODULE_MAP["virt"] if "qemu" in k]
        assert len(qemu) >= 5

    def test_xen_modules(self) -> None:
        xen = [k for k in MODULE_MAP["virt"] if "xen" in k]
        assert len(xen) >= 3

    def test_vcenter_modules(self) -> None:
        vc = [k for k in MODULE_MAP["virt"] if "vcenter" in k]
        assert len(vc) >= 5
