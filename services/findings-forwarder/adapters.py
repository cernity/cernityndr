"""Pluggable finding sinks. Select with CERNITY_SINK. Phase 1 ships the file
adapter; OpenSearch, Splunk HEC, webhook, and syslog/CEF adapters are added
later. Each adapter exposes emit(finding: dict) -> None."""
import json
import os


class FileAdapter:
    """Append each finding as one JSON object per line (JSONL)."""

    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def emit(self, finding):
        with open(self.path, "a") as fh:
            fh.write(json.dumps(finding) + "\n")


def get_adapter():
    kind = os.environ.get("CERNITY_SINK", "file")
    if kind == "file":
        return FileAdapter(os.environ.get("CERNITY_SINK_FILE", "/var/lib/cernity/findings.jsonl"))
    raise ValueError(f"unknown CERNITY_SINK: {kind}")
