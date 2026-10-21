"""CloudXPL interactive REPL interpreter."""

import importlib
import readline
from pathlib import Path
from typing import Any

from cloudxpl import __version__
from cloudxpl.core.dispatcher import MODULE_MAP

try:
    from xpl_core.config import ForgeConfig
    _HAS_CONFIG = True
except ImportError:
    _HAS_CONFIG = False


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

BANNER = rf"""
   _____ _                 _ __  ______  _
  / ____| |               | |\ \/ /  _ \| |
 | |    | | ___  _   _  __| | \  /| |_) | |
 | |    | |/ _ \| | | |/ _` | /  \|  __/| |
 | |____| | (_) | |_| | (_| |/ /\ \ |   | |____
  \_____|_|\___/ \__,_|\__,_/_/  \_\_|   |______|

  CloudXPL-Forge v{__version__}
  Cloud Security Assessment Framework
  508 modules | 20 providers
  https://github.com/mrhenrike/CloudXPL-Forge
"""

HELP_TEXT = """
Core commands
=============
  show modules             List all categories and module counts
  show modules <category>  List modules in a category
  show providers           List cloud providers / categories
  show options             Show current module options
  use <category>/<module>  Select a module
  set <option> <value>     Set a module option
  run                      Execute the selected module
  back                     Deselect the current module
  help                     Show this help
  exit / quit              Exit the interpreter
"""

HISTORY_FILE = Path.home() / ".cloudxpl_history"
HISTORY_LENGTH = 1000


# ---------------------------------------------------------------------------
# Completer
# ---------------------------------------------------------------------------

class CloudXPLCompleter:
    """Tab-completion for the CloudXPL REPL."""

    def __init__(self) -> None:
        self._matches: list[str] = []

    # -- helpers --
    @staticmethod
    def _module_paths() -> list[str]:
        paths: list[str] = []
        for cat, mods in sorted(MODULE_MAP.items()):
            for mod_name in sorted(mods):
                paths.append(f"{cat}/{mod_name}")
        return paths

    @staticmethod
    def _categories() -> list[str]:
        return sorted(MODULE_MAP.keys())

    # -- readline interface --
    def complete(self, text: str, state: int) -> str | None:
        if state == 0:
            line = readline.get_line_buffer().lstrip()
            self._matches = self._build_matches(line, text)
        try:
            return self._matches[state]
        except IndexError:
            return None

    def _build_matches(self, line: str, text: str) -> list[str]:
        if line.startswith("use "):
            prefix = text
            return [p for p in self._module_paths() if p.startswith(prefix)]

        if line.startswith("show modules "):
            prefix = text
            return [c for c in self._categories() if c.startswith(prefix)]

        if not text:
            return []

        commands = [
            "use ", "show ", "set ", "run", "back",
            "help", "exit", "quit",
        ]
        return [c for c in commands if c.startswith(text)]


# ---------------------------------------------------------------------------
# Interpreter
# ---------------------------------------------------------------------------

class Interpreter:
    """Lightweight interactive REPL for CloudXPL-Forge."""

    def __init__(self) -> None:
        self.current_category: str | None = None
        self.current_module: str | None = None
        self.options: dict[str, str] = {}
        self._loaded_mod: Any = None
        self._config: ForgeConfig | None = ForgeConfig("cloudxpl") if _HAS_CONFIG else None

    # -- prompt --
    @property
    def prompt(self) -> str:
        if self.current_module:
            return f"\033[1;31mcloudxpl\033[0m(\033[1;34m{self.current_category}/{self.current_module}\033[0m) > "
        return "\033[1;31mcloudxpl\033[0m > "

    # -- command dispatch --
    def handle(self, raw: str) -> bool:
        """Handle one line of input. Return False to exit."""
        line = raw.strip()
        if not line:
            return True

        parts = line.split(None, 1)
        cmd = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""

        dispatch: dict[str, Any] = {
            "use": self._cmd_use,
            "show": self._cmd_show,
            "set": self._cmd_set,
            "run": self._cmd_run,
            "back": self._cmd_back,
            "help": self._cmd_help,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
        }

        handler = dispatch.get(cmd)
        if handler is None:
            print(f"[!] Unknown command: {cmd}. Type 'help' for usage.")
            return True

        return handler(rest)

    # -- commands --
    def _cmd_use(self, rest: str) -> bool:
        if "/" not in rest:
            print("[!] Usage: use <category>/<module>")
            return True

        cat, _, mod = rest.partition("/")
        cat = cat.strip()
        mod = mod.strip()

        if cat not in MODULE_MAP:
            print(f"[!] Unknown category: {cat}")
            print(f"[*] Available: {', '.join(sorted(MODULE_MAP))}")
            return True

        if mod not in MODULE_MAP[cat]:
            print(f"[!] Unknown module: {mod} in category {cat}")
            return True

        self.current_category = cat
        self.current_module = mod
        self.options = {}
        self._loaded_mod = None
        if self._config:
            self._config.set_val("last_module", f"{cat}/{mod}")
        print(f"[*] Module set: {cat}/{mod}")
        return True

    def _cmd_show(self, rest: str) -> bool:
        parts = rest.split(None, 1)
        sub = parts[0].lower() if parts else ""

        if sub == "modules":
            cat_filter = parts[1].strip() if len(parts) > 1 else None
            self._show_modules(cat_filter)
        elif sub == "providers":
            self._show_providers()
        elif sub == "options":
            self._show_options()
        else:
            print("[!] Usage: show modules [category] | show providers | show options")
        return True

    def _cmd_set(self, rest: str) -> bool:
        parts = rest.split(None, 1)
        if len(parts) < 2:
            print("[!] Usage: set <option> <value>")
            return True
        key, val = parts[0], parts[1]
        self.options[key] = val
        print(f"[*] {key} => {val}")
        return True

    def _cmd_run(self, _rest: str) -> bool:
        if not self.current_module or not self.current_category:
            print("[!] No module selected. Use 'use <category>/<module>' first.")
            return True

        mod_path = MODULE_MAP.get(self.current_category, {}).get(self.current_module)
        if not mod_path:
            print("[!] Module not found in dispatcher map.")
            return True

        if self._loaded_mod is None:
            try:
                self._loaded_mod = importlib.import_module(mod_path)
            except ImportError as exc:
                print(f"[!] Failed to import {mod_path}: {exc}")
                print(f"[*] Try: pip install cloudxpl-forge[{self.current_category}]")
                return True

        run_fn = getattr(self._loaded_mod, "run", None)
        if run_fn is None:
            print(f"[!] Module {mod_path} has no run() function.")
            return True

        ns = _build_namespace(self.current_category, self.current_module, self.options)
        try:
            run_fn(ns)
        except KeyboardInterrupt:
            print("\n[!] Interrupted.")
        except Exception as exc:
            print(f"[!] Module error: {exc}")
        return True

    def _cmd_back(self, _rest: str) -> bool:
        self.current_category = None
        self.current_module = None
        self.options = {}
        self._loaded_mod = None
        return True

    @staticmethod
    def _cmd_help(_rest: str) -> bool:
        print(HELP_TEXT)
        return True

    @staticmethod
    def _cmd_exit(_rest: str) -> bool:
        return False

    # -- display helpers --
    @staticmethod
    def _show_modules(category: str | None) -> None:
        if category:
            mods = MODULE_MAP.get(category)
            if mods is None:
                print(f"[!] Unknown category: {category}")
                return
            print(f"\n  {category} ({len(mods)} modules)\n  {'=' * 40}")
            for name in sorted(mods):
                print(f"    {name}")
            print()
        else:
            total = 0
            print("\n  Category            Modules\n  " + "=" * 40)
            for cat in sorted(MODULE_MAP):
                count = len(MODULE_MAP[cat])
                total += count
                print(f"  {cat:<20s} {count}")
            print(f"  {'=' * 40}\n  Total: {total}\n")

    @staticmethod
    def _show_providers() -> None:
        print("\n  Cloud providers / categories\n  " + "=" * 40)
        for cat in sorted(MODULE_MAP):
            print(f"    {cat}")
        print()

    def _show_options(self) -> None:
        if not self.current_module:
            print("[!] No module selected.")
            return
        print(f"\n  Options for {self.current_category}/{self.current_module}\n  " + "=" * 40)
        if not self.options:
            print("    (none set)")
        for k, v in sorted(self.options.items()):
            print(f"    {k:<20s} {v}")
        print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class _Namespace:
    """Minimal argparse-like namespace for module run()."""

    def __init__(self, **kwargs: Any) -> None:
        for k, v in kwargs.items():
            setattr(self, k, v)

    def __repr__(self) -> str:
        attrs = ", ".join(f"{k}={v!r}" for k, v in self.__dict__.items())
        return f"Namespace({attrs})"


def _build_namespace(category: str, module: str, options: dict[str, str]) -> _Namespace:
    ns = _Namespace(command=category, module=module)
    for k, v in options.items():
        setattr(ns, k, v)
    return ns


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

def _load_history() -> None:
    try:
        if HISTORY_FILE.exists():
            readline.read_history_file(str(HISTORY_FILE))
    except OSError:
        pass


def _save_history() -> None:
    try:
        readline.set_history_length(HISTORY_LENGTH)
        readline.write_history_file(str(HISTORY_FILE))
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

def main() -> None:
    """Entry point for the CloudXPL interactive interpreter."""
    print(BANNER)

    _load_history()

    completer = CloudXPLCompleter()
    readline.set_completer(completer.complete)
    readline.parse_and_bind("tab: complete")
    readline.set_completer_delims(" \t\n/")

    interp = Interpreter()

    try:
        while True:
            try:
                line = input(interp.prompt)
            except EOFError:
                print()
                break
            if not interp.handle(line):
                break
    except KeyboardInterrupt:
        print("\n[*] Interrupted. Exiting.")
    finally:
        _save_history()
        print("[*] Bye.")


if __name__ == "__main__":
    main()
