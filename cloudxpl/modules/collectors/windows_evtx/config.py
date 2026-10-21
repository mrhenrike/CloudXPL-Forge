"""
Modelo de configuração alinhado às telas NW Platform: Event Categories + Hosts.
Domínio, hosts, auth, porta, transport, filtros, SID, locale, etc.
"""
from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict, Tuple
from enum import Enum


class AuthMethod(str, Enum):
    NEGOTIATE = "negotiate"  # NTLM/Kerberos
    BASIC = "basic"
    CERTIFICATE = "certificate"  # Certificado cliente (crt/pem + key); opcional senha na key


class Transport(str, Enum):
    HTTP = "http"
    HTTPS = "https"


# Portas padrão WinRM
DEFAULT_PORT_HTTP = 5985
DEFAULT_PORT_HTTPS = 5986


@dataclass
class TargetHost:
    """
    Um host Windows alvo (Event Source Address).
    NW: Hosts table + Edit Source (por host).
    Preferir FQDN; para Basic Auth o NW exige FQDN e entrada em /etc/hosts.
    """
    hostname: str  # Event Source Address (FQDN ou nome do host)
    domain: Optional[str] = None
    ip: Optional[str] = None  # Para hosts fora do domínio: IP obrigatório; script garante entrada em /etc/hosts
    port: Optional[int] = None
    transport: Transport = Transport.HTTP
    auth: AuthMethod = AuthMethod.NEGOTIATE
    # Por-host (NW Advanced)
    enabled: bool = True
    event_filter: Optional[str] = None  # XPath ou FilterHashtable para Get-WinEvent
    validate_server: Optional[bool] = None  # None = usa global verify_ssl
    debug: str = "off"  # off | low | medium | high
    render_locale: Optional[str] = None  # en-US, pt-BR
    windows_type: Optional[str] = None  # Domain Controller, Member Server, etc.
    resolve_sids: bool = True
    sid_enumeration_interval: Optional[int] = None  # segundos
    sid_enumeration_timeout: Optional[int] = None   # segundos
    override_channels: Optional[str] = None  # ex: "System^(101|201), Security(4672)"
    certificate_name: Optional[str] = None  # nome/caminho cert para HTTPS (legado)
    # Certificados HTTPS: validar servidor e/ou autenticar com cert cliente
    ca_trust_path: Optional[str] = None    # CA ou cert do servidor (.crt, .pem) quando verify_ssl
    client_cert_pem: Optional[str] = None  # Certificado cliente (.crt, .pem) para auth
    client_cert_key_pem: Optional[str] = None  # Chave privada (.key, .pem)
    client_cert_key_password: Optional[str] = None  # Senha da chave (se criptografada); opcional

    def effective_port(self) -> int:
        if self.port is not None:
            return self.port
        return DEFAULT_PORT_HTTPS if self.transport == Transport.HTTPS else DEFAULT_PORT_HTTP

    def endpoint(self) -> str:
        port = self.effective_port()
        scheme = "https" if self.transport == Transport.HTTPS else "http"
        return f"{scheme}://{self.hostname}:{port}/wsman"


@dataclass
class EventSourceCategory:
    """
    Categoria de evento (NW: Event Categories). Define defaults aplicados a vários hosts.
    Alias, auth, channels, user, read_all_events, max_duration_poll, etc.
    """
    alias: str  # Nome lógico da fonte (ex: ADM.BANCOAMAZONIA.SA)
    authorization_method: AuthMethod = AuthMethod.BASIC
    channel: str = "Security,System,Application"  # vírgula ou formato Override Channels
    user_name: str = ""
    password: str = ""
    read_all_events: bool = True
    max_duration_poll: int = 120       # segundos (timeout por operação)
    max_events_per_cycle: int = 150000
    polling_interval: int = 180        # segundos entre ciclos
    render_events: bool = True


@dataclass
class CollectorConfig:
    """
    Configuração do coletor: credenciais, alvos, saída.
    Pode ser construída por CLI (args) ou por config_loader (YAML).
    """
    username: str
    password: str
    targets: List[TargetHost] = field(default_factory=list)
    log_names: List[str] = field(default_factory=lambda: ["Security", "System", "Application"])
    max_events_per_log: int = 1000
    # Base da saída: default = <cwd>/logs; arquivos em output_dir/hostname/<filename>.log
    output_dir: str = ""
    # Padrão do nome do arquivo (sem extensão). Placeholders: {hostname}, {channel}, {YYYY}, {MM}, {DD}, {HHMMSS}
    # Default: hostname_channel_yyyy-mm-dd-HHMMSSZ.log
    output_filename_pattern: str = "{hostname}_{channel}_{YYYY}-{MM}-{DD}-{HHMMSS}Z"
    # Extensão sempre .log
    output_extension: str = ".log"
    # Nome no header IETF (app-name RFC 5424); default harpiawincollector
    app_name: str = "harpiawincollector"
    # ietf | raw | jsonl | cef. raw = XML em linha (sem conversão); default raw
    output_format: str = "raw"
    verify_ssl: bool = False
    # Coleta: quando True, descobre e coleta de todos os logs do Event Viewer (não só log_names)
    collect_all_logs: bool = False
    # Certificados HTTPS (valores default; podem ser sobrescritos por host)
    ca_trust_path: Optional[str] = None       # CA ou cert servidor para validar (obrigatório se verify_ssl)
    client_cert_pem: Optional[str] = None     # Cert cliente para auth certificate
    client_cert_key_pem: Optional[str] = None
    client_cert_key_password: Optional[str] = None  # Senha da chave privada (opcional)
    # NW Advanced (global / category level)
    max_duration_poll: int = 120
    polling_interval: int = 60  # intervalo entre ciclos de coleta (default 1 min)
    read_all_events: bool = True
    render_events: bool = True
    # Rotação de arquivo: o que atingir primeiro vira novo arquivo
    rotation_interval_sec: int = 60  # janela de tempo (segundos) por arquivo; 0 = só por dia/linhas
    rotation_max_lines: int = 10000  # máximo de linhas por arquivo; 0 = desliga rotação por linhas
    # Rolled-out: limpeza por uso de disco (apenas em output_dir)
    disk_threshold_percent: float = 98.0  # acima disso inicia exclusão dos mais antigos
    disk_target_percent: float = 80.0  # parar quando uso cair para este valor
    # Idades para exclusão em etapas (segundos): primeiro >24h, depois >3h, >1h, >30min, depois tudo
    retention_tiers_sec: Tuple[int, ...] = (86400, 10800, 3600, 1800, 0)
    # Retenção por tempo: apaga arquivos mais antigos que retention_days dias (0 = desligado)
    retention_days: int = 15
    # Backfill: no primeiro run (sem bookmark), coleta eventos dos últimos N dias (0 = sem limite)
    backfill_days: int = 30
    # Caminho do arquivo de bookmark para coleta incremental (apenas eventos novos após primeira passada)
    bookmark_path: Optional[str] = None
