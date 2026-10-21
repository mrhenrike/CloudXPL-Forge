#!/usr/bin/env python3
"""
CLI: coleta Windows Event Log via WinRM (Linux -> Windows).
Alinhado às telas NW Platform: Event Categories + Hosts, Test Connection.
Uso: python -m wincollect [opções] | python cli.py [opções]
"""
import argparse
import os
import sys
import time
from pathlib import Path

def _read_version() -> str:
    try:
        return (Path(__file__).resolve().parent / "VERSION").read_text(encoding="utf-8").strip()
    except Exception:
        return "unknown"

__version__ = _read_version()

if __name__ == "__main__" and os.path.basename(os.getcwd()) != "WindowsCollectorOnLinux":
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import AuthMethod, CollectorConfig, TargetHost, Transport
from src.collector import collect_all
from src.output import (
    write_events_from_collector,
    write_raw_events_to_log,
    write_ietf_events_to_log,
    write_jsonl_events,
    write_cef_events_to_log,
    run_rolled_out,
    rotate_old_files,
)
from src.connection_test import test_connections_bulk
from src.config_loader import load_config_yaml
from src.discovery import discover_hosts_ldap


def _parse_host_line(line: str):
    """Retorna (hostname, ip ou None). Aceita 'ip hostname', 'hostname,ip' ou 'hostname'."""
    from src.etc_hosts import _is_ip
    line = line.strip()
    if not line:
        return None
    parts = [p.strip() for p in line.replace(",", " ").split() if p.strip()]
    if len(parts) >= 2:
        if _is_ip(parts[0]):
            return (parts[1], parts[0])
        if _is_ip(parts[-1]):
            return (parts[0], parts[-1])
    return (parts[0], None) if parts else None


def _hosts_from_args(args: argparse.Namespace) -> list:
    """Retorna lista de (hostname, ip_optional) sem duplicatas por hostname."""
    hosts = []  # list of (hostname, ip|None)
    seen = set()
    def add(h, ip=None):
        key = (h.lower(), (ip or ""))
        if key not in seen:
            seen.add(key)
            hosts.append((h, ip))

    if getattr(args, "discover_ldap", False) and getattr(args, "domain", None) and args.domain.strip():
        try:
            ldap_user = getattr(args, "ldap_user", None) or args.user
            ldap_pass = getattr(args, "ldap_password", None) or args.password
            discovered = discover_hosts_ldap(
                domain=args.domain.strip(),
                ou=getattr(args, "ldap_ou", None),
                ldap_server=getattr(args, "ldap_server", None),
                bind_user=ldap_user,
                bind_password=ldap_pass,
                use_ssl=getattr(args, "ldap_use_ssl", False),
            )
            for h in discovered:
                add(h, None)
        except Exception as e:
            raise SystemExit(f"Descoberta LDAP falhou: {e}")
    if not hosts and getattr(args, "host", None):
        host_ip = getattr(args, "host_ip", None)
        add(args.host.strip(), host_ip.strip() if host_ip else None)
    if getattr(args, "hosts", None):
        for part in args.hosts.split(","):
            parsed = _parse_host_line(part)
            if parsed:
                add(parsed[0], parsed[1])
    if getattr(args, "hosts_file", None):
        with open(args.hosts_file, "r", encoding="utf-8") as f:
            for line in f:
                parsed = _parse_host_line(line)
                if parsed:
                    add(parsed[0], parsed[1])
    return hosts


def _build_config_from_args(args: argparse.Namespace, hosts_override: list = None) -> CollectorConfig:
    host_list = hosts_override if hosts_override is not None else _hosts_from_args(args)
    if not host_list:
        return None
    if args.auth == "certificate":
        auth = AuthMethod.CERTIFICATE
    elif args.auth == "basic":
        auth = AuthMethod.BASIC
    else:
        auth = AuthMethod.NEGOTIATE
    transport = Transport.HTTPS if args.transport == "https" else Transport.HTTP
    log_names = [x.strip() for x in args.log_names.split(",") if x.strip()]
    targets = []
    for item in host_list:
        h, ip = (item[0], item[1]) if isinstance(item, (list, tuple)) else (item, None)
        targets.append(
            TargetHost(
                hostname=h,
                domain=args.domain or None,
                ip=ip,
                port=args.port,
                transport=transport,
                auth=auth,
                validate_server=not getattr(args, "no_verify_ssl", True),
                ca_trust_path=getattr(args, "ca_trust_path", None),
                client_cert_pem=getattr(args, "client_cert_pem", None),
                client_cert_key_pem=getattr(args, "client_cert_key_pem", None),
                client_cert_key_password=getattr(args, "client_cert_key_password", None),
            )
        )
    output_dir = (args.output_dir or "").strip() or os.path.join(os.getcwd(), "logs")
    output_pattern = getattr(args, "output_filename_pattern", None) or "{hostname}_{channel}_{YYYY}-{MM}-{DD}-{HHMMSS}Z"
    app_name = getattr(args, "app_name", None) or "harpiawincollector"
    retention_days = int(
        os.environ.get("WINCOLLECT_RETENTION_DAYS") or getattr(args, "retention_days", 15) or 15
    )
    retention_tiers = (86400, 10800, 3600, 1800, 0)
    if getattr(args, "retention_tiers", None):
        try:
            retention_tiers = tuple(int(x.strip()) for x in args.retention_tiers.split(",") if x.strip())
        except ValueError:
            pass
    elif retention_days > 0:
        retention_tiers = (retention_days * 86400, 0)
    return CollectorConfig(
        username=args.user or "",
        password=args.password or "",
        targets=targets,
        log_names=log_names,
        max_events_per_log=getattr(args, "max_events", 1000),
        output_dir=output_dir,
        output_filename_pattern=output_pattern,
        output_extension=".log",
        app_name=app_name,
        output_format=getattr(args, "output_format", "raw"),
        verify_ssl=not getattr(args, "no_verify_ssl", True),
        collect_all_logs=getattr(args, "collect_all_logs", False),
        ca_trust_path=getattr(args, "ca_trust_path", None),
        client_cert_pem=getattr(args, "client_cert_pem", None),
        client_cert_key_pem=getattr(args, "client_cert_key_pem", None),
        client_cert_key_password=getattr(args, "client_cert_key_password", None),
        max_duration_poll=getattr(args, "max_duration_poll", 120),
        polling_interval=getattr(args, "polling_interval", 60),
        rotation_interval_sec=getattr(args, "rotation_interval_sec", 60),
        rotation_max_lines=getattr(args, "rotation_max_lines", 10000),
        disk_threshold_percent=getattr(args, "disk_threshold_percent", 98.0),
        disk_target_percent=getattr(args, "disk_target_percent", 80.0),
        retention_tiers_sec=retention_tiers,
        retention_days=retention_days,
        bookmark_path=getattr(args, "bookmark_path", None)
        or (os.path.join(output_dir.rstrip("/").rstrip("\\"), ".wincollect_bookmarks.json") if output_dir else None),
    )


def _print_effective_config(config: CollectorConfig, args: argparse.Namespace) -> None:
    """Imprime parâmetros efetivos (incl. defaults) para --verbose-all e --debug."""
    out_dir = (config.output_dir or "").strip() or os.path.join(os.getcwd(), "logs")
    tiers = getattr(config, "retention_tiers_sec", (86400, 10800, 3600, 1800, 0))
    print("=== Parâmetros efetivos (wincollect) ===", file=sys.stderr)
    print(f"  host(s): {[t.hostname for t in config.targets]}", file=sys.stderr)
    print(f"  auth: {config.targets[0].auth.value if config.targets else 'N/A'}", file=sys.stderr)
    print(f"  transport: {config.targets[0].transport.value if config.targets else 'N/A'}", file=sys.stderr)
    print(f"  user: {config.username or '(vazio)'}", file=sys.stderr)
    print(f"  password: {'***' if config.password else '(vazio)'}", file=sys.stderr)
    print(f"  output_dir: {out_dir}", file=sys.stderr)
    print(f"  output_format: {config.output_format}", file=sys.stderr)
    print(f"  output_filename_pattern: {getattr(config, 'output_filename_pattern', '')}", file=sys.stderr)
    print(f"  app_name: {getattr(config, 'app_name', '')}", file=sys.stderr)
    print(f"  log_names: {config.log_names}", file=sys.stderr)
    print(f"  max_events_per_log: {config.max_events_per_log}", file=sys.stderr)
    print(f"  polling_interval: {config.polling_interval}", file=sys.stderr)
    print(f"  rotation_interval_sec: {getattr(config, 'rotation_interval_sec', 60)}", file=sys.stderr)
    print(f"  rotation_max_lines: {getattr(config, 'rotation_max_lines', 10000)}", file=sys.stderr)
    print(f"  disk_threshold_percent: {getattr(config, 'disk_threshold_percent', 98)}", file=sys.stderr)
    print(f"  disk_target_percent: {getattr(config, 'disk_target_percent', 80)}", file=sys.stderr)
    print(f"  retention_tiers_sec: {tiers}", file=sys.stderr)
    print(f"  verify_ssl: {config.verify_ssl}", file=sys.stderr)
    print(f"  collect_all_logs: {config.collect_all_logs}", file=sys.stderr)
    if getattr(args, "debug", False):
        for i, t in enumerate(config.targets):
            print(f"  target[{i}]: hostname={t.hostname} ip={t.ip} port={t.port}", file=sys.stderr)
    print("========================================", file=sys.stderr)


def _require_root_on_linux() -> bool:
    """Em Linux (HIN), exige root/sudo para garantir leitura e escrita em /etc/hosts. Retorna True se OK, False e sai se não."""
    if sys.platform == "win32":
        return True
    try:
        if os.geteuid() != 0:
            print(
                "Este programa roda apenas em Linux (HIN) e deve ser executado como root ou com sudo, "
                "para garantir leitura/escrita em /etc/hosts (mapeamento IP/hostname).",
                file=sys.stderr,
            )
            sys.exit(1)
    except AttributeError:
        pass
    return True


def main() -> int:
    _require_root_on_linux()
    p = argparse.ArgumentParser(
        description="Coleta Windows Event Log via WinRM (Linux -> Windows). Config alinhada ao NW Platform.",
    )
    p.add_argument("--config", type=str, help="Arquivo YAML de configuração (categories + hosts)")
    p.add_argument("--test-connection", action="store_true", help="Apenas testar conexão (single ou bulk)")
    p.add_argument("--host", type=str, help="Hostname (ou IP se for único alvo)")
    p.add_argument("--host-ip", type=str, help="IP do host (obrigatório para hosts fora do domínio; grava em /etc/hosts)")
    p.add_argument("--hosts", type=str, help="Vários hostnames (ou 'ip hostname' / 'hostname,ip' separados por vírgula)")
    p.add_argument("--hosts-file", type=str, help="Arquivo: uma linha por host ('ip hostname', 'hostname,ip' ou 'hostname')")
    p.add_argument("--domain", type=str, default="", help="Domínio (contexto; ex: safelabs.lab). Obrigatório com --discover-ldap.")
    p.add_argument("--discover-ldap", action="store_true", help="Descobrir hosts via LDAP (domain + OU)")
    p.add_argument("--ldap-ou", type=str, help="OU para busca (ex: Servers ou OU=Servers,DC=safelabs,DC=lab)")
    p.add_argument("--ldap-server", type=str, help="Servidor LDAP (ex: dc01.safelabs.lab). Se omitido, usa primeiro DC do domínio.")
    p.add_argument("--ldap-user", type=str, help="Usuário para bind LDAP (se omitido, usa --user)")
    p.add_argument("--ldap-password", type=str, help="Senha para bind LDAP (se omitida, usa --password)")
    p.add_argument("--ldap-use-ssl", action="store_true", help="Usar LDAPS (636)")
    p.add_argument("--auth", type=str, choices=["negotiate", "basic", "certificate"], default="negotiate")
    p.add_argument("--transport", type=str, choices=["http", "https"], default="http",
                   help="Transporte WinRM (default: http)")
    p.add_argument("--port", type=int, default=None)
    p.add_argument("--output-dir", type=str, default=None,
                   help="Pasta base de saída (default: <cwd>/logs); arquivos em output-dir/hostname/<arquivo>.log")
    p.add_argument("--output-filename-pattern", type=str, default=None,
                   help="Padrão do nome do arquivo (placeholders: {hostname}, {channel}, {YYYY}, {MM}, {DD}, {HHMMSS}). Default: {hostname}_{channel}_{YYYY}-{MM}-{DD}-{HHMMSS}Z")
    p.add_argument("--app-name", type=str, default="harpiawincollector",
                   help="Nome no header IETF (app-name RFC 5424)")
    p.add_argument("--output-format", type=str, choices=["ietf", "raw", "jsonl", "cef"], default="raw",
                   help="ietf|raw|jsonl|cef (default: raw = XML em linha)")
    # HTTPS / certificados (obrigatórios quando HTTPS + validar servidor ou auth certificate)
    p.add_argument("--ca-trust-path", type=str, help="CA ou cert do servidor (.crt, .pem) para validar HTTPS")
    p.add_argument("--client-cert-pem", type=str, help="Certificado cliente (.crt, .pem) para auth certificate")
    p.add_argument("--client-cert-key-pem", type=str, help="Chave privada (.key, .pem); senha opcional")
    p.add_argument("--client-cert-key-password", type=str, help="Senha da chave (só se estiver criptografada)")
    p.add_argument("--collect-all-logs", action="store_true", help="Coletar de todos os logs do Event Viewer")
    p.add_argument("--user", type=str, default=os.environ.get("WINCOLLECT_USER"))
    p.add_argument("--password", type=str, default=os.environ.get("WINCOLLECT_PASSWORD"))
    p.add_argument("--log-names", type=str, default="Security,System,Application")
    p.add_argument("--max-events", type=int, default=1000)
    p.add_argument("--max-duration-poll", type=int, default=120, help="Timeout por operação (segundos)")
    p.add_argument("--polling-interval", type=int, default=60,
                   help="Intervalo entre ciclos de coleta em segundos (default 1 min)")
    p.add_argument("--rotation-interval-sec", type=int, default=60,
                   help="Rotação de arquivo: janela de tempo em segundos (0=desliga). Default 60")
    p.add_argument("--rotation-max-lines", type=int, default=10000,
                   help="Rotação de arquivo: máximo de linhas por arquivo (0=desliga). Default 10000")
    p.add_argument("--disk-threshold-percent", type=float, default=98.0,
                   help="Rolled-out: acima deste uso de disco (%%) exclui logs antigos. Default 98")
    p.add_argument("--disk-target-percent", type=float, default=80.0,
                   help="Rolled-out: parar quando uso cair para este %%. Default 80")
    p.add_argument("--retention-tiers", type=str, default=None,
                   help="Rolled-out: idades em segundos (ex: 86400,10800,3600,1800,0). Default 24h,3h,1h,30min,tudo")
    p.add_argument("--retention-days", type=int, default=15,
                   help="Rotação por tempo: apaga arquivos .log/.jsonl mais antigos que N dias (0=desligado). Default 15")
    p.add_argument("--collect-duration", type=int, default=0,
                   help="Coletar por N segundos (loop; 0 = uma única passada)")
    p.add_argument("--daemon", action="store_true",
                   help="Loop infinito com intervalo polling_interval (mesmo padrão de serviço dos outros coletores)")
    p.add_argument("--no-verify-ssl", action="store_true")
    p.add_argument("--verbose", "-v", action="store_true", help="Saída verbosa (progresso)")
    p.add_argument("--verbose-all", action="store_true", help="Exibe todos os parâmetros efetivos (incl. defaults)")
    p.add_argument("--debug", action="store_true", help="Modo debug (verbose-all + detalhes extras)")
    args = p.parse_args()

    config = None
    if args.config:
        if not os.path.isfile(args.config):
            p.error(f"Arquivo não encontrado: {args.config}")
        config = load_config_yaml(args.config)
    else:
        if getattr(args, "discover_ldap", False) and not (getattr(args, "domain", None) or "").strip():
            p.error("Com --discover-ldap é obrigatório informar --domain (ex: safelabs.lab)")
        hosts = _hosts_from_args(args)
        if not hosts:
            p.error("Informe pelo menos um host: --host, --hosts, --hosts-file, --config ou --discover-ldap com --domain")
        if args.auth != "certificate" and (not args.user or not args.password):
            p.error(
                "Credenciais: use --user e --password (com sudo, env WINCOLLECT_* não é repassado; "
                "ou use: sudo -E python -m wincollect ... para preservar variáveis de ambiente)"
            )
        if args.auth == "certificate" and (not args.client_cert_pem or not args.client_cert_key_pem):
            p.error("Auth certificate exige --client-cert-pem e --client-cert-key-pem")
        config = _build_config_from_args(args, hosts_override=hosts)

    def _log(msg: str, level: str = "info") -> None:
        if getattr(args, "verbose", False) or getattr(args, "verbose_all", False) or getattr(args, "debug", False):
            print(msg, file=sys.stderr)
    if getattr(args, "verbose_all", False) or getattr(args, "debug", False):
        _print_effective_config(config, args)
    elif getattr(args, "verbose", False):
        _log(f"Hosts: {[t.hostname for t in config.targets]}; output: {config.output_dir}; format: {config.output_format}")

    if args.test_connection:
        results = test_connections_bulk(
            config.targets,
            config.username,
            config.password,
            config.verify_ssl,
            operation_timeout_sec=min(30, config.max_duration_poll),
        )
        print("Status\tHost\tError Message")
        for r in results:
            status = "Passed" if r.passed else "Failed"
            err = (r.error_message or "").replace("\t", " ").replace("\n", " ")
            print(f"{status}\t{r.host}\t{err}")
        failed = sum(1 for r in results if not r.passed)
        return 0 if failed == 0 else 1

    print(f"[wincollect] v{__version__} | poll={config.polling_interval}s | out={config.output_dir} | pid={os.getpid()}", flush=True)

    # Garante que o diretório de saída existe antes de qualquer coleta
    if config.output_dir:
        os.makedirs(config.output_dir, exist_ok=True)

    duration_sec = getattr(args, "collect_duration", 0) or 0
    daemon_mode = getattr(args, "daemon", False)
    deadline = None if (daemon_mode or duration_sec <= 0) else (time.time() + duration_sec)
    loop_forever = daemon_mode or duration_sec <= 0
    total_events = 0
    pass_num = 0
    try:
        while True:
            pass_num += 1
            # Rotação por tempo (retention_days)
            if config.retention_days > 0 and config.output_dir:
                rotated = rotate_old_files(config.output_dir, config.retention_days)
                if rotated > 0:
                    print(f"[rotate] {rotated} arquivo(s) removido(s) (retenção={config.retention_days}d).", file=sys.stderr)
            # Rolled-out por uso de disco
            removed = run_rolled_out(config)
            if removed > 0:
                print(f"Rolled-out: {removed} arquivo(s) removido(s) para liberar disco.", file=sys.stderr)
            events = collect_all(config, raw_output=True)
            if config.output_format == "ietf":
                count = write_ietf_events_to_log(config, events)
            elif config.output_format == "raw":
                count = write_raw_events_to_log(config, events)
            elif config.output_format == "jsonl":
                count = write_jsonl_events(config, events)
            elif config.output_format == "cef":
                count = write_cef_events_to_log(config, events)
            else:
                count = write_raw_events_to_log(config, events)
            total_events += count
            ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            print(f"[{ts}] poll done | events={count} | total={total_events} | pass={pass_num}", flush=True)
            if not loop_forever:
                if deadline is None or time.time() >= deadline:
                    break
            time.sleep(config.polling_interval)
        if not daemon_mode:
            print(f"Eventos gravados: {total_events} em {config.output_dir}" + (f" ({pass_num} passadas)" if pass_num > 1 else ""))
        return 0
    except Exception as e:
        print(f"Erro: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
