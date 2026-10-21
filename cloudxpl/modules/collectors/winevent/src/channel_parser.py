"""
Parse de Override Channels (formato NW): "System^(101|201), Security(4672), Application".
Retorna lista de (log_name, ids_opcional) para Get-WinEvent -LogName X -Id ...
"""
import re
from typing import List, Optional, Tuple


def parse_override_channels(override: Optional[str]) -> List[Tuple[str, Optional[List[int]]]]:
    """
    Converte string tipo "System^(101|201), Security(4672), Application" em
    [("System", [101, 201]), ("Security", [4672]), ("Application", None)].
    None = sem filtro de ID (coleta todos).
    """
    if not override or not override.strip():
        return []
    result: List[Tuple[str, Optional[List[int]]]] = []
    for part in override.split(","):
        part = part.strip()
        if not part:
            continue
        # Ex: "System^(101|201)" ou "Security(4672)" ou "Application"
        match = re.match(r"^(.+?)\^?\(([\d\s|]+)\)\s*$", part)
        if match:
            log_name = match.group(1).strip().rstrip("^").strip()
            ids_str = match.group(2)
            ids = [int(x.strip()) for x in ids_str.split("|") if x.strip().isdigit()]
            result.append((log_name, ids if ids else None))
        else:
            result.append((part, None))
    return result


def channels_from_config(
    override_channels: Optional[str],
    default_log_names: List[str],
) -> List[Tuple[str, Optional[List[int]]]]:
    """
    Se override_channels estiver definido, usa parse_override_channels;
    senão retorna (log_name, None) para cada default_log_names.
    """
    if override_channels and override_channels.strip():
        return parse_override_channels(override_channels)
    return [(name, None) for name in default_log_names]
