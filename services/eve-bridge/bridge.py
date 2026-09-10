"""Pure helpers for the EVE bridge: turn a bus EVE record into a Suricata
eve.json line, and decide when to roll the output file.

SLIPS ingests a Suricata eve.json. The Cernity bus already carries the sensor's
EVE records (the shipper puts them there), so the bridge re-materialises them as a
growing eve.json that SLIPS reads -- feeding SLIPS without touching the sensor.
"""
import json


def eve_line(record):
    """One compact newline-delimited JSON record (SLIPS reads NDJSON eve)."""
    return json.dumps(record, separators=(",", ":")) + "\n"


def should_rotate(bytes_written, max_bytes):
    """Roll the file once it passes max_bytes. max_bytes <= 0 disables rotation."""
    return max_bytes > 0 and bytes_written >= max_bytes
