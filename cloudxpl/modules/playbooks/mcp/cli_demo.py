#!/usr/bin/env python3
"""
SafeLabs MCP — CLI Demo Runner
================================
Executa qualquer ferramenta MCP diretamente no terminal para demonstrações em POC.

Uso:
  python cli_demo.py <server> <tool> [arg1] [arg2] ...

Servers:  fw | edr | ad

Exemplos:
  python cli_demo.py fw  fw_status
  python cli_demo.py fw  fw_block_ip 57.128.59.134 "APT44 C2"
  python cli_demo.py fw  fw_isolate_host 10.254.2.152 "Infected host"
  python cli_demo.py fw  fw_block_ip_list apt44_ips
  python cli_demo.py fw  fw_block_domain_list apt44_domains
  python cli_demo.py fw  fw_list_iocs

  python cli_demo.py edr edr_status
  python cli_demo.py edr edr_list_agents
  python cli_demo.py edr edr_list_threats
  python cli_demo.py edr edr_collect_iocs
  python cli_demo.py edr edr_containment_chain 2442300432464470030
  python cli_demo.py edr edr_blacklist_hash_list apt44_hashes
  python cli_demo.py edr edr_isolate_agent 2442300432464470030 "81 threats"
  python cli_demo.py edr edr_deisolate_agent 2442300432464470030

  python cli_demo.py ad  ad_user_status harpia.user
  python cli_demo.py ad  ad_disable_user harpia.user "APT44 credential leak"
  python cli_demo.py ad  ad_enable_user harpia.user
  python cli_demo.py ad  ad_force_password_reset harpia.user
  python cli_demo.py ad  ad_unlock_user harpia.user
  python cli_demo.py ad  ad_list_disabled_users
  python cli_demo.py ad  ad_containment_from_leak '["harpia.user","claro.user"]' reset-password
  python cli_demo.py ad  dns_status
  python cli_demo.py ad  dns_block_domain kalambur.net
  python cli_demo.py ad  dns_block_domain_list apt44_domains
  python cli_demo.py ad  dns_list_blocked
  python cli_demo.py ad  dns_flush_cache
  python cli_demo.py ad  dns_block_apt44_domains
  python cli_demo.py ad  ad_dns_check_certificate_store_modification
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

MCP_DIR = Path(__file__).parent

# ─── Load .env ───────────────────────────────────────────────────────────────

def _load_env():
    for p in [
        MCP_DIR / ".env",
        MCP_DIR.parent / ".env",
        MCP_DIR.parent.parent.parent / "laboratory" / "poc-harpia" / ".env",
    ]:
        if p.is_file():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

_load_env()

# ─── Load server module ───────────────────────────────────────────────────────

_SERVER_MAP = {
    "fw":  "server_fw",
    "edr": "server_edr",
    "ad":  "server_ad_dns",
}


def _load_server(alias: str):
    name = _SERVER_MAP.get(alias)
    if not name:
        print(f"[ERRO] Server '{alias}' desconhecido. Use: fw | edr | ad")
        sys.exit(1)
    spec = importlib.util.spec_from_file_location(name, MCP_DIR / f"{name}.py")
    mod  = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _print_result(result: str | dict | list):
    """Pretty-print resultado."""
    if isinstance(result, str):
        try:
            parsed = json.loads(result)
            print(json.dumps(parsed, ensure_ascii=False, indent=2))
        except Exception:
            print(result)
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2))


def _coerce_arg(val: str):
    """Converte string de arg para tipo Python adequado."""
    if val.lower() == "true":  return True
    if val.lower() == "false": return False
    if val.startswith("[") or val.startswith("{"):
        try:    return json.loads(val)
        except: pass
    try:    return int(val)
    except: pass
    return val


def _print_help():
    print(__doc__)
    print("\nTools disponíveis por server:")
    for alias, name in _SERVER_MAP.items():
        try:
            mod   = _load_server(alias)
            tools = list(mod.mcp._tool_manager._tools.keys())
            print(f"\n  [{alias}] ({name})")
            for t in tools:
                print(f"    {t}")
        except Exception as e:
            print(f"    [ERRO ao carregar {name}: {e}]")


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help", "help"):
        _print_help()
        return

    if len(args) < 2:
        print("Uso: python cli_demo.py <server> <tool> [args...]")
        print("Servers: fw | edr | ad")
        sys.exit(1)

    server_alias = args[0].lower()
    tool_name    = args[1]
    tool_args    = [_coerce_arg(a) for a in args[2:]]

    # Suppress paramiko INFO logs for cleaner demo output
    import logging
    logging.getLogger("paramiko").setLevel(logging.WARNING)

    sep = "=" * 60
    print(f"\n{sep}")
    print(f"  SafeLabs MCP :: {server_alias.upper()} :: {tool_name}")
    if tool_args:
        print(f"  Args: {tool_args}")
    print(f"{sep}\n")

    mod  = _load_server(server_alias)
    tool_fn = getattr(mod, tool_name, None)

    if tool_fn is None:
        print(f"[ERRO] Tool '{tool_name}' não encontrada no server '{server_alias}'")
        available = list(mod.mcp._tool_manager._tools.keys())
        print(f"       Disponíveis: {available}")
        sys.exit(1)

    try:
        result = tool_fn(*tool_args)
        _print_result(result)
    except TypeError as e:
        print(f"[ERRO] Argumentos incorretos: {e}")
        import inspect
        sig = inspect.signature(tool_fn)
        print(f"       Assinatura: {tool_name}{sig}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERRO] {e}")
        sys.exit(1)

    print(f"\n{'=' * 60}")


if __name__ == "__main__":
    main()
