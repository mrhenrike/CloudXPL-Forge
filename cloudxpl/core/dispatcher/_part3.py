def dispatch(args: Any) -> int:
    module_path = MODULE_MAP.get(args.command, {}).get(args.module)
    if not module_path:
        print(f"[!] Unknown: {args.command}/{args.module}", file=sys.stderr)
        return 1

    try:
        mod = importlib.import_module(module_path)
    except ImportError as exc:
        print(f"[!] Failed to load {module_path}: {exc}", file=sys.stderr)
        print(f"[*] Install provider deps: pip install cloudxpl-forge[{args.command}]", file=sys.stderr)
        return 1

    return mod.run(args)
