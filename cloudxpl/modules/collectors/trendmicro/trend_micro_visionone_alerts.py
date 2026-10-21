"""Collect Trend Micro Vision One alerts with checkpoint resume."""

from collector_common import (
    LOGGER,
    load_config,
    load_state,
    resolve_state_path,
    setup_logging,
)
from trend_micro_visionone_alerts_detections import fetch_alerts


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
    LOGGER.info("Alerts run finished")


if __name__ == "__main__":
    main()
