"""Collect Trend Micro Vision One alerts and detections with checkpoint resume."""

import math
from datetime import timedelta
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

from collector_common import (
    LOGGER,
    api_get,
    format_api_datetime,
    load_config,
    load_state,
    max_item_datetime,
    parse_api_datetime,
    resolve_start_datetime,
    resolve_state_path,
    send_udp,
    set_checkpoint,
    setup_logging,
    utc_now,
)

ALERTS_PAGE_SIZE = 10
DETECTIONS_PAGE_SIZE = 200


def _send_and_checkpoint(
    host: str,
    port: int,
    items: List[Dict[str, Any]],
    datetime_field: str,
    stream: str,
    state: Dict[str, Any],
    state_path,
) -> Optional[str]:
    """Send one page via UDP and advance checkpoint on success."""
    if not items:
        return None
    send_udp(host, port, items)
    newest = max_item_datetime(items, datetime_field)
    if newest is None:
        LOGGER.warning(
            "No usable %s in %s items for stream %s",
            datetime_field,
            len(items),
            stream,
        )
        return None
    set_checkpoint(state, stream, newest, state_path)
    stamped = format_api_datetime(newest)
    LOGGER.info(
        "Sent %s %s event(s); checkpoint=%s",
        len(items),
        stream,
        stamped,
    )
    return stamped


def _next_start(last_stamp: str) -> str:
    return format_api_datetime(
        parse_api_datetime(last_stamp) + timedelta(seconds=1)
    )


def fetch_alerts(
    bearer_token: str,
    base_url: str,
    minutes: int,
    udp_host: str,
    udp_port: int,
    state: Dict[str, Any],
    state_path,
) -> None:
    """Fetch alerts from checkpoint (or lookback) to now."""
    start_dt = resolve_start_datetime(state, "alerts", minutes)
    end_dt = utc_now()
    if start_dt >= end_dt:
        LOGGER.info("Alerts: start >= end; nothing to fetch")
        return

    start_date_time = format_api_datetime(start_dt)
    end_date_time = format_api_datetime(end_dt)
    LOGGER.info("Alerts window: %s -> %s", start_date_time, end_date_time)

    query = urlencode(
        {
            "dateTimeTarget": "createdDateTime",
            "orderBy": "createdDateTime ASC",
            "startDateTime": start_date_time,
            "endDateTime": end_date_time,
        }
    )
    data = api_get(f"{base_url}?{query}", bearer_token)
    if data is None:
        return

    items = data.get("items") or []
    if not isinstance(items, list):
        LOGGER.error("Alerts: unexpected items type")
        return

    total_events = int(data.get("totalCount") or 0)
    LOGGER.info("Alerts totalCount=%s page_items=%s", total_events, len(items))
    if not items:
        return

    last_stamp = _send_and_checkpoint(
        udp_host,
        udp_port,
        items,
        "createdDateTime",
        "alerts",
        state,
        state_path,
    )
    if last_stamp is None or total_events <= ALERTS_PAGE_SIZE:
        return

    pages = math.ceil(total_events / ALERTS_PAGE_SIZE)
    for page in range(2, pages + 1):
        query = urlencode(
            {
                "dateTimeTarget": "createdDateTime",
                "orderBy": "createdDateTime ASC",
                "startDateTime": _next_start(last_stamp),
                "endDateTime": end_date_time,
            }
        )
        data = api_get(f"{base_url}?{query}", bearer_token)
        if data is None:
            break
        items = data.get("items") or []
        if not items:
            break
        last_stamp = _send_and_checkpoint(
            udp_host,
            udp_port,
            items,
            "createdDateTime",
            "alerts",
            state,
            state_path,
        )
        if last_stamp is None:
            break
        LOGGER.info("Alerts page %s/%s", page, pages)


def fetch_detections(
    bearer_token: str,
    base_url: str,
    minutes: int,
    udp_host: str,
    udp_port: int,
    state: Dict[str, Any],
    state_path,
) -> None:
    """Fetch detections from checkpoint (or lookback) to now."""
    start_dt = resolve_start_datetime(state, "detections", minutes)
    end_dt = utc_now()
    if start_dt >= end_dt:
        LOGGER.info("Detections: start >= end; nothing to fetch")
        return

    start_date_time = format_api_datetime(start_dt)
    end_date_time = format_api_datetime(end_dt)
    LOGGER.info(
        "Detections window: %s -> %s",
        start_date_time,
        end_date_time,
    )

    query = urlencode(
        {
            "detectedStartDateTime": start_date_time,
            "detectedEndDateTime": end_date_time,
            "top": DETECTIONS_PAGE_SIZE,
        }
    )
    data = api_get(f"{base_url}?{query}", bearer_token)
    if data is None:
        return

    items = data.get("items") or []
    if not isinstance(items, list):
        LOGGER.error("Detections: unexpected items type")
        return

    total_events = int(data.get("totalCount") or 0)
    LOGGER.info(
        "Detections totalCount=%s page_items=%s",
        total_events,
        len(items),
    )
    if not items:
        return

    last_stamp = _send_and_checkpoint(
        udp_host,
        udp_port,
        items,
        "detectedDateTime",
        "detections",
        state,
        state_path,
    )
    if last_stamp is None or total_events <= DETECTIONS_PAGE_SIZE:
        return

    pages = math.ceil(total_events / DETECTIONS_PAGE_SIZE)
    for page in range(2, pages + 1):
        query = urlencode(
            {
                "detectedStartDateTime": _next_start(last_stamp),
                "detectedEndDateTime": end_date_time,
                "top": DETECTIONS_PAGE_SIZE,
            }
        )
        data = api_get(f"{base_url}?{query}", bearer_token)
        if data is None:
            break
        items = data.get("items") or []
        if not items:
            break
        last_stamp = _send_and_checkpoint(
            udp_host,
            udp_port,
            items,
            "detectedDateTime",
            "detections",
            state,
            state_path,
        )
        if last_stamp is None:
            break
        LOGGER.info("Detections page %s/%s", page, pages)


def main() -> None:
    setup_logging()
    config = load_config()
    state_path = resolve_state_path(config)
    state = load_state(state_path)

    LOGGER.info("State file: %s", state_path)
    fetch_alerts(
        str(config["bearer_token"]),
        str(config["base_url_alerts"]),
        int(config["minutes"]),
        str(config["udp_host"]),
        int(config["udp_port"]),
        state,
        state_path,
    )
    fetch_detections(
        str(config["bearer_token"]),
        str(config["base_url_detections"]),
        int(config["minutes"]),
        str(config["udp_host"]),
        int(config["udp_port"]),
        state,
        state_path,
    )
    LOGGER.info("Run finished")


if __name__ == "__main__":
    main()
