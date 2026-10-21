"""Collect Trend Micro Vision One detections with checkpoint resume."""

from collector_common import (
    LOGGER,
    load_config,
    load_state,
    resolve_state_path,
    setup_logging,
)
from trend_micro_visionone_alerts_detections import fetch_detections


def main() -> None:
    setup_logging()
    config = load_config()
    state_path = resolve_state_path(config)
    state = load_state(state_path)

    LOGGER.info("State file: %s", state_path)
    fetch_detections(
        str(config["bearer_token"]),
        str(config["base_url_detections"]),
        int(config["minutes"]),
        str(config["udp_host"]),
        int(config["udp_port"]),
        state,
        state_path,
    )
    LOGGER.info("Detections run finished")


if __name__ == "__main__":
    main()
