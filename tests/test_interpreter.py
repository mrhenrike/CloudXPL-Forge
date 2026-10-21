"""Tests for cloudxpl.interpreter module."""

import types
from unittest.mock import patch

from cloudxpl.interpreter import (
    BANNER,
    CloudXPLCompleter,
    Interpreter,
    _build_namespace,
    _Namespace,
)

# ---------------------------------------------------------------------------
# _Namespace
# ---------------------------------------------------------------------------

class TestNamespace:
    def test_basic_attrs(self):
        ns = _Namespace(command="aws", module="s3-enum")
        assert ns.command == "aws"
        assert ns.module == "s3-enum"

    def test_repr(self):
        ns = _Namespace(a=1)
        assert "a=1" in repr(ns)


# ---------------------------------------------------------------------------
# _build_namespace
# ---------------------------------------------------------------------------

class TestBuildNamespace:
    def test_builds_correct_ns(self):
        ns = _build_namespace("gcp", "bucket-enum", {"target": "example.com"})
        assert ns.command == "gcp"
        assert ns.module == "bucket-enum"
        assert ns.target == "example.com"


# ---------------------------------------------------------------------------
# Completer
# ---------------------------------------------------------------------------

class TestCompleter:
    def test_complete_use_prefix(self):
        c = CloudXPLCompleter()
        with patch("readline.get_line_buffer", return_value="use aws/s3"):
            result = c.complete("aws/s3", 0)
            assert result is not None
            assert result.startswith("aws/s3")

    def test_complete_categories(self):
        c = CloudXPLCompleter()
        with patch("readline.get_line_buffer", return_value="show modules a"):
            result = c.complete("a", 0)
            assert result is not None

    def test_complete_commands(self):
        c = CloudXPLCompleter()
        with patch("readline.get_line_buffer", return_value="he"):
            result = c.complete("he", 0)
            assert result == "help"

    def test_complete_returns_none_past_end(self):
        c = CloudXPLCompleter()
        with patch("readline.get_line_buffer", return_value="quit"):
            c.complete("quit", 0)
            assert c.complete("quit", 99) is None


# ---------------------------------------------------------------------------
# Interpreter
# ---------------------------------------------------------------------------

class TestInterpreter:
    def test_initial_prompt(self):
        interp = Interpreter()
        assert "cloudxpl" in interp.prompt

    def test_use_valid_module(self, capsys):
        interp = Interpreter()
        interp.handle("use aws/s3-enum")
        assert interp.current_category == "aws"
        assert interp.current_module == "s3-enum"

    def test_use_invalid_category(self, capsys):
        interp = Interpreter()
        interp.handle("use fakeprovider/mod")
        captured = capsys.readouterr()
        assert "Unknown category" in captured.out

    def test_use_invalid_module(self, capsys):
        interp = Interpreter()
        interp.handle("use aws/not-a-real-module")
        captured = capsys.readouterr()
        assert "Unknown module" in captured.out

    def test_use_no_slash(self, capsys):
        interp = Interpreter()
        interp.handle("use aws")
        captured = capsys.readouterr()
        assert "Usage" in captured.out

    def test_show_modules_all(self, capsys):
        interp = Interpreter()
        interp.handle("show modules")
        captured = capsys.readouterr()
        assert "aws" in captured.out
        assert "Total" in captured.out

    def test_show_modules_category(self, capsys):
        interp = Interpreter()
        interp.handle("show modules aws")
        captured = capsys.readouterr()
        assert "s3-enum" in captured.out

    def test_show_providers(self, capsys):
        interp = Interpreter()
        interp.handle("show providers")
        captured = capsys.readouterr()
        assert "gcp" in captured.out

    def test_show_options_no_module(self, capsys):
        interp = Interpreter()
        interp.handle("show options")
        captured = capsys.readouterr()
        assert "No module" in captured.out

    def test_set_option(self, capsys):
        interp = Interpreter()
        interp.handle("use aws/s3-enum")
        interp.handle("set target example.com")
        assert interp.options["target"] == "example.com"

    def test_set_no_value(self, capsys):
        interp = Interpreter()
        interp.handle("set onlyone")
        captured = capsys.readouterr()
        assert "Usage" in captured.out

    def test_back(self):
        interp = Interpreter()
        interp.handle("use aws/s3-enum")
        interp.handle("back")
        assert interp.current_module is None

    def test_help(self, capsys):
        interp = Interpreter()
        interp.handle("help")
        captured = capsys.readouterr()
        assert "show modules" in captured.out

    def test_exit(self):
        interp = Interpreter()
        result = interp.handle("exit")
        assert result is False

    def test_quit(self):
        interp = Interpreter()
        assert interp.handle("quit") is False

    def test_unknown_command(self, capsys):
        interp = Interpreter()
        interp.handle("foobar")
        captured = capsys.readouterr()
        assert "Unknown command" in captured.out

    def test_empty_input(self):
        interp = Interpreter()
        assert interp.handle("") is True

    def test_run_no_module(self, capsys):
        interp = Interpreter()
        interp.handle("run")
        captured = capsys.readouterr()
        assert "No module" in captured.out

    def test_run_import_error(self, capsys):
        interp = Interpreter()
        interp.handle("use aws/s3-enum")
        with patch("importlib.import_module", side_effect=ImportError("no boto3")):
            interp.handle("run")
        captured = capsys.readouterr()
        assert "Failed to import" in captured.out

    def test_run_success(self, capsys):
        interp = Interpreter()
        interp.handle("use aws/s3-enum")
        fake_mod = types.ModuleType("fake")
        fake_mod.run = lambda ns: print(f"OK:{ns.command}")
        with patch("importlib.import_module", return_value=fake_mod):
            interp.handle("run")
        captured = capsys.readouterr()
        assert "OK:aws" in captured.out

    def test_run_module_exception(self, capsys):
        interp = Interpreter()
        interp.handle("use aws/s3-enum")
        fake_mod = types.ModuleType("fake")
        fake_mod.run = lambda ns: (_ for _ in ()).throw(RuntimeError("boom"))
        with patch("importlib.import_module", return_value=fake_mod):
            interp.handle("run")
        captured = capsys.readouterr()
        assert "Module error" in captured.out

    def test_prompt_with_module(self):
        interp = Interpreter()
        interp.handle("use aws/s3-enum")
        assert "aws/s3-enum" in interp.prompt

    def test_show_options_with_module(self, capsys):
        interp = Interpreter()
        interp.handle("use aws/s3-enum")
        interp.handle("set target foo.com")
        interp.handle("show options")
        captured = capsys.readouterr()
        assert "target" in captured.out
        assert "foo.com" in captured.out


class TestBanner:
    def test_banner_contains_version(self):
        assert "CloudXPL" in BANNER
