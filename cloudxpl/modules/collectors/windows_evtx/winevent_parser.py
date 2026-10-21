"""
Parse de XML de Windows Event Log (estrutura baseada em OpenWEC/core/app/src/winevent.py).
Namespace: http://schemas.microsoft.com/win/2004/08/events/event
"""
from typing import Any, Dict, Optional
import xml.etree.ElementTree as ET

EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
NS = {"e": EVENT_NS}


def _text(el: Optional[ET.Element]) -> Optional[str]:
    if el is None or el.text is None:
        return None
    return el.text.strip()


def parse_event_xml(raw: str, keep_rendered: bool = True) -> Dict[str, Any]:
    """
    Converte XML de um evento Windows (formato ToXml() do .NET) em dicionário.
    """
    root = ET.fromstring(raw)
    out: Dict[str, Any] = {"data": {}}

    # System
    system = root.find("e:System", NS)
    if system is not None:
        prov_el = system.find("e:Provider", NS)
        provider_name = prov_el.get("Name") if prov_el is not None else _text(prov_el)
        time_el = system.find("e:TimeCreated", NS)
        time_created = time_el.get("SystemTime") if time_el is not None else None
        out["system"] = {
            "Provider": provider_name,
            "EventID": _text(system.find("e:EventID", NS)),
            "Version": _text(system.find("e:Version", NS)),
            "Level": _text(system.find("e:Level", NS)),
            "Task": _text(system.find("e:Task", NS)),
            "Opcode": _text(system.find("e:Opcode", NS)),
            "Keywords": _text(system.find("e:Keywords", NS)),
            "TimeCreated": time_created,
            "Computer": _text(system.find("e:Computer", NS)),
            "Channel": _text(system.find("e:Channel", NS)),
        }
        # EventRecordID quando existir
        rec = system.find("e:EventRecordID", NS)
        if rec is not None and rec.text:
            out["system"]["EventRecordID"] = rec.text.strip()

    # EventData/Data (com ou sem Name)
    data_idx = 0
    for data in root.iterfind(".//e:EventData/e:Data", NS):
        name = data.get("Name")
        if not name:
            name = f"Data_{data_idx}"
            data_idx += 1
        val = (data.text or "").strip()
        if val.isdigit():
            try:
                val = int(val)
            except ValueError:
                pass
        elif val == "-":
            val = None
        out["data"][name] = val

    # RenderingInfo (Message, Level text, etc.)
    if keep_rendered:
        ri = root.find("e:RenderingInfo", NS)
        if ri is not None:
            msg = ri.find("e:Message", NS)
            level = ri.find("e:Level", NS)
            channel = ri.find("e:Channel", NS)
            provider = ri.find("e:Provider", NS)
            out["rendered"] = {
                "Message": _text(msg) if msg is not None else None,
                "Level": _text(level) if level is not None else None,
                "Channel": _text(channel) if channel is not None else None,
                "Provider": _text(provider) if provider is not None else None,
            }

    return out


def get_time_created_from_raw_xml(raw_xml: str) -> Optional[str]:
    """
    Extrai o SystemTime do TimeCreated do XML bruto (para bookmark incremental).
    Retorna None se não encontrar.
    """
    if not raw_xml or "TimeCreated" not in raw_xml:
        return None
    try:
        root = ET.fromstring(raw_xml)
        system = root.find("e:System", NS)
        if system is None:
            return None
        time_el = system.find("e:TimeCreated", NS)
        if time_el is None:
            return None
        return time_el.get("SystemTime")
    except Exception:
        return None
