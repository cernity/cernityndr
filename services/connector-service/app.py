"""Connector-service entrypoint (entity-graph U4). Periodically runs the NetBox CMDB sync
(netbox.run), which is itself a clean no-op when NETBOX_URL is unset. Poll interval is
env-tunable (NETBOX_SYNC_SECS)."""
import os
import signal
import time

import netbox

_running = True


def _stop(*_):
    global _running
    _running = False


def main():
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    interval = int(float(os.environ.get("NETBOX_SYNC_SECS", "300")))
    while _running:
        netbox.run()
        # ponytail: fixed-interval poll; a webhook-driven sync is a follow-up if freshness matters.
        for _ in range(max(interval, 1)):
            if not _running:
                break
            time.sleep(1)


if __name__ == "__main__":
    main()
