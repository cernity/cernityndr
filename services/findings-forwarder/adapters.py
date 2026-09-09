"""Pluggable finding sinks. Select with CERNITY_SINK. Each adapter exposes
emit(finding) and optionally emit_batch(findings) for efficient bulk delivery."""
import base64
import json
import logging
import os
import ssl
import urllib.request
from datetime import datetime, timezone

log = logging.getLogger("findings-forwarder")


class FileAdapter:
    """Append each finding as one JSON object per line (JSONL)."""

    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def emit(self, finding):
        with open(self.path, "a") as fh:
            fh.write(json.dumps(finding) + "\n")


class ElasticsearchAdapter:
    """Bulk-index findings into Elasticsearch or OpenSearch (same _bulk API).
    Findings land in a daily index (ES_INDEX_PREFIX-YYYY.MM.DD)."""

    def __init__(self):
        self.endpoint = os.environ.get("ES_ENDPOINT", "http://localhost:9200").rstrip("/")
        user = os.environ.get("ES_USER", "")
        pw = os.environ.get("ES_PASSWORD", "")
        self.auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode() if user else None
        self.prefix = os.environ.get("ES_INDEX_PREFIX", "ndr-findings")
        # Verify TLS by default; set ES_TLS_VERIFY=false for an internal/self-signed CA.
        self.ctx = None if os.environ.get("ES_TLS_VERIFY", "true").lower() != "false" \
            else ssl._create_unverified_context()

    @staticmethod
    def _doc(f):
        # ES/OpenSearch date fields want ISO-8601 'T', not "YYYY-MM-DD HH:MM:SS".
        for k in ("first_seen", "last_seen"):
            v = f.get(k)
            if isinstance(v, str) and " " in v and "T" not in v:
                f[k] = v.replace(" ", "T")
        f["@timestamp"] = f.get("last_seen") or f.get("first_seen")
        return f

    def emit(self, finding):
        self.emit_batch([finding])

    def emit_batch(self, findings):
        findings = [f for f in findings if f.get("state") != "SUPPRESSED"]
        if not findings:
            return
        idx = self.prefix + "-" + datetime.now(timezone.utc).strftime("%Y.%m.%d")
        lines = []
        for f in findings:
            d = self._doc(f)
            lines.append(json.dumps({"index": {"_index": idx, "_id": d.get("finding_id")}}))
            lines.append(json.dumps(d))
        body = ("\n".join(lines) + "\n").encode()
        headers = {"Content-Type": "application/x-ndjson"}
        if self.auth:
            headers["Authorization"] = self.auth
        req = urllib.request.Request(self.endpoint + "/_bulk", data=body, method="POST", headers=headers)
        with urllib.request.urlopen(req, context=self.ctx, timeout=20) as r:
            res = json.load(r)
        if res.get("errors"):
            log.warning("bulk index had errors -> %s", idx)
        else:
            log.info("indexed %d finding(s) -> %s", len(findings), idx)


def get_adapter():
    kind = os.environ.get("CERNITY_SINK", "file")
    if kind == "file":
        return FileAdapter(os.environ.get("CERNITY_SINK_FILE", "/var/lib/cernity/findings.jsonl"))
    if kind in ("elasticsearch", "opensearch", "es"):
        return ElasticsearchAdapter()
    raise ValueError(f"unknown CERNITY_SINK: {kind}")
