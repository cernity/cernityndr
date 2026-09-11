"""Pluggable finding sinks. Select with CERNITY_SINK — a single name, or a
comma-separated list to fan out to several SIEMs at once (failures isolated per
sink). Each adapter exposes emit(finding) and emit_batch(findings); payload
building is factored into pure helpers so formats are testable without a live SIEM.

Supported: file, elasticsearch/opensearch, splunk, webhook, syslog, devo."""
import base64
import json
import logging
import os
import socket
import ssl
import urllib.request
from datetime import datetime, timezone

import cef

log = logging.getLogger("findings-forwarder")
import time                                        # noqa: E402 (kept near the durable-delivery code)

MAX_RETRIES = int(os.environ.get("CERNITY_DELIVER_RETRIES", "4"))
BACKOFF_SECS = float(os.environ.get("CERNITY_DELIVER_BACKOFF_SECS", "1.0"))
DLQ_DIR = os.environ.get("CERNITY_DLQ_DIR", "/var/lib/cernity/dlq")
DEDUP_MAX = int(os.environ.get("CERNITY_DEDUP_MAX", "100000"))


def _live(findings):
    """Drop SUPPRESSED findings — they stay on the bus for correlation but must
    not reach the analyst plane."""
    return [f for f in findings if f.get("state") != "SUPPRESSED"]


class DurableSink:
    """Durable per-sink delivery (F07): wraps one sink adapter with retry + dead-letter
    + idempotent admission. Each sink is INDEPENDENT — a finding already delivered here
    is recorded (by finding_id) so a Kafka replay (offsets are committed only after
    delivery) or a duplicate is never re-sent, and a sink outage retries with bounded
    backoff, then dead-letters the batch to a file (never silently dropped). Because the
    retry is per-sink, a partial multi-sink outage never re-delivers to the healthy sinks.
    ponytail: the dedup set is in-memory (bounded FIFO); a stable finding_id (F13) makes an
    idempotent sink like ES dedup across restarts on its own — add a persistent dedup only
    if a non-idempotent sink needs cross-restart exactly-once."""

    def __init__(self, inner, name, dlq_dir=DLQ_DIR, retries=MAX_RETRIES,
                 backoff=BACKOFF_SECS, sleep=time.sleep, dedup_max=DEDUP_MAX, on_health=None):
        self.inner, self.name = inner, name
        self._dlq_path = os.path.join(dlq_dir, f"dlq-{name}.jsonl")
        self._retries, self._backoff, self._sleep = retries, backoff, sleep
        self._dedup_max = dedup_max
        self._seen: dict = {}                       # finding_id -> None (insertion-ordered FIFO)
        # F15: report real backend health — a delivery flips readiness true, an exhausted
        # dead-letter flips it false, so the /readyz probe reflects a wedged sink.
        self._on_health = on_health or (lambda ok: None)

    def _mark(self, findings):
        for f in findings:
            fid = f.get("finding_id")
            if fid is not None:
                self._seen[fid] = None
        while len(self._seen) > self._dedup_max:
            self._seen.pop(next(iter(self._seen)))

    def _dlq(self, findings, err):
        os.makedirs(os.path.dirname(self._dlq_path) or ".", exist_ok=True)
        with open(self._dlq_path, "a") as fh:
            for f in findings:
                fh.write(json.dumps({"sink": self.name, "error": str(err), "finding": f}) + "\n")
        log.error("%s: dead-lettered %d finding(s) after %d retries: %s",
                  self.name, len(findings), self._retries, err)

    def emit(self, finding):
        self.emit_batch([finding])

    def emit_batch(self, findings):
        fresh = [f for f in findings if f.get("finding_id") not in self._seen]
        if not fresh:
            return
        for attempt in range(self._retries + 1):
            try:
                self.inner.emit_batch(fresh)
                self._mark(fresh)                   # delivered: don't re-send on replay
                self._on_health(True)
                return
            except Exception as e:                  # noqa: BLE001
                if attempt >= self._retries:
                    self._dlq(fresh, e)             # dead-lettered = durably handled
                    self._mark(fresh)
                    self._on_health(False)          # backend down -> readiness false (F15)
                    return
                log.warning("%s: delivery failed (attempt %d/%d), retrying: %s",
                            self.name, attempt + 1, self._retries, e)
                self._sleep(self._backoff * (2 ** attempt))


class FileAdapter:
    def __init__(self, path, max_bytes=None):
        self.path = path
        # Size-cap rotation (F15): when the sink file exceeds max_bytes it is rotated to
        # `<path>.1` (single generation, overwritten) so an unattended file sink can't fill
        # the disk. 0/None disables. Default 100 MiB.
        self.max_bytes = int(os.environ.get("CERNITY_SINK_FILE_MAX_BYTES", "104857600")
                             if max_bytes is None else max_bytes)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    def _rotate_if_needed(self):
        if self.max_bytes and os.path.exists(self.path) \
                and os.path.getsize(self.path) >= self.max_bytes:
            os.replace(self.path, self.path + ".1")   # atomic; keeps one prior generation

    def emit(self, finding):
        self.emit_batch([finding])

    def emit_batch(self, findings):
        self._rotate_if_needed()
        with open(self.path, "a") as fh:
            for f in _live(findings):
                fh.write(json.dumps(f) + "\n")


class ElasticsearchAdapter:
    """Elasticsearch / OpenSearch (same _bulk API). Daily index."""

    def __init__(self):
        self.endpoint = os.environ.get("ES_ENDPOINT", "http://localhost:9200").rstrip("/")
        user, pw = os.environ.get("ES_USER", ""), os.environ.get("ES_PASSWORD", "")
        self.auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode() if user else None
        self.prefix = os.environ.get("ES_INDEX_PREFIX", "ndr-findings")
        self.ctx = None if os.environ.get("ES_TLS_VERIFY", "true").lower() != "false" \
            else ssl._create_unverified_context()

    @staticmethod
    def _doc(f):
        for k in ("first_seen", "last_seen"):
            v = f.get(k)
            if isinstance(v, str) and " " in v and "T" not in v:
                f[k] = v.replace(" ", "T")
        f["@timestamp"] = f.get("last_seen") or f.get("first_seen")
        return f

    def emit(self, finding):
        self.emit_batch([finding])

    def emit_batch(self, findings):
        findings = _live(findings)
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


class SplunkAdapter:
    """Splunk HTTP Event Collector (HEC)."""

    def __init__(self):
        self.url = os.environ["SPLUNK_HEC_URL"].rstrip("/")
        self.token = os.environ["SPLUNK_HEC_TOKEN"]
        self.sourcetype = os.environ.get("SPLUNK_SOURCETYPE", "cernity:finding")
        self.ctx = None if os.environ.get("SPLUNK_TLS_VERIFY", "true").lower() != "false" \
            else ssl._create_unverified_context()

    def _body(self, findings):
        return "".join(json.dumps({"event": f, "sourcetype": self.sourcetype}) for f in findings).encode()

    def emit(self, finding):
        self.emit_batch([finding])

    def emit_batch(self, findings):
        findings = _live(findings)
        if not findings:
            return
        req = urllib.request.Request(self.url, data=self._body(findings), method="POST",
                                     headers={"Authorization": "Splunk " + self.token})
        with urllib.request.urlopen(req, context=self.ctx, timeout=20):
            pass
        log.info("sent %d finding(s) -> Splunk HEC", len(findings))


class WebhookAdapter:
    """Generic JSON POST to any URL (Slack, ticketing, SOAR, custom)."""

    def __init__(self):
        self.url = os.environ["WEBHOOK_URL"]
        self.auth = os.environ.get("WEBHOOK_AUTH", "")   # full header value, e.g. "Bearer x"
        self.ctx = None if os.environ.get("WEBHOOK_TLS_VERIFY", "true").lower() != "false" \
            else ssl._create_unverified_context()

    def _body(self, findings):
        return json.dumps({"findings": findings}).encode()

    def emit(self, finding):
        self.emit_batch([finding])

    def emit_batch(self, findings):
        findings = _live(findings)
        if not findings:
            return
        headers = {"Content-Type": "application/json"}
        if self.auth:
            headers["Authorization"] = self.auth
        req = urllib.request.Request(self.url, data=self._body(findings), method="POST", headers=headers)
        with urllib.request.urlopen(req, context=self.ctx, timeout=20):
            pass
        log.info("posted %d finding(s) -> webhook", len(findings))


def _syslog_frame(cef_line, host="cernity", pri=134, tag=None):
    """RFC-ish syslog frame carrying a CEF payload. `tag` (Devo table) is
    appended before the payload when set."""
    ts = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
    prefix = f"<{pri}>{ts} {host} "
    return prefix + (f"{tag}: " if tag else "") + cef_line


class SyslogCefAdapter:
    """CEF over syslog (TCP, optionally TLS) — QRadar, ArcSight, most on-prem."""

    def __init__(self):
        self.host = os.environ["SYSLOG_HOST"]
        self.port = int(os.environ.get("SYSLOG_PORT", "514"))
        self.tls = os.environ.get("SYSLOG_TLS", "false").lower() == "true"
        self.hostname = os.environ.get("NDR_SENSOR", "cernity")

    def _frame(self, finding):
        return _syslog_frame(cef.to_cef(finding), host=self.hostname)

    def _send(self, frames):
        s = socket.create_connection((self.host, self.port), timeout=20)
        if self.tls:
            s = ssl.create_default_context().wrap_socket(s, server_hostname=self.host)
        try:
            for fr in frames:
                s.sendall((fr + "\n").encode())
        finally:
            s.close()

    def emit(self, finding):
        self.emit_batch([finding])

    def emit_batch(self, findings):
        findings = _live(findings)
        if not findings:
            return
        self._send([self._frame(f) for f in findings])
        log.info("sent %d finding(s) -> syslog/CEF", len(findings))


class DevoAdapter:
    """Devo via syslog-over-TLS relay (mutual TLS, tagged to a table) or the
    Devo HTTP ingestion API. Payload JSON (default) or CEF."""

    def __init__(self):
        self.transport = os.environ.get("DEVO_TRANSPORT", "syslog").lower()
        self.fmt = os.environ.get("DEVO_FORMAT", "json").lower()
        self.tag = os.environ.get("DEVO_TAG", "my.app.cernity.findings")
        if self.transport == "http":
            self.endpoint = os.environ["DEVO_ENDPOINT"].rstrip("/")
            self.token = os.environ["DEVO_TOKEN"]
        else:
            self.relay = os.environ["DEVO_RELAY"]
            self.port = int(os.environ.get("DEVO_PORT", "443"))
            self.cert = os.environ["DEVO_CERT"]
            self.key = os.environ["DEVO_KEY"]
            self.chain = os.environ.get("DEVO_CHAIN", "")

    def _payload(self, finding):
        return cef.to_cef(finding) if self.fmt == "cef" else json.dumps(finding)

    def _frame(self, finding):
        return _syslog_frame(self._payload(finding), tag=self.tag)

    def emit(self, finding):
        self.emit_batch([finding])

    def emit_batch(self, findings):
        findings = _live(findings)
        if not findings:
            return
        if self.transport == "http":
            body = "".join(json.dumps({"tag": self.tag, "message": self._payload(f)}) + "\n"
                           for f in findings).encode()
            req = urllib.request.Request(self.endpoint, data=body, method="POST",
                                         headers={"Content-Type": "application/json",
                                                  "Authorization": "Bearer " + self.token})
            with urllib.request.urlopen(req, timeout=20):
                pass
        else:
            ctx = ssl.create_default_context()
            ctx.load_cert_chain(certfile=self.cert, keyfile=self.key)
            if self.chain:
                ctx.load_verify_locations(self.chain)
            raw = socket.create_connection((self.relay, self.port), timeout=20)
            s = ctx.wrap_socket(raw, server_hostname=self.relay)
            try:
                for f in findings:
                    s.sendall((self._frame(f) + "\n").encode())
            finally:
                s.close()
        log.info("sent %d finding(s) -> Devo (%s)", len(findings), self.transport)


class MultiAdapter:
    """Fan out to several sinks; a failure in one never blocks the others."""

    def __init__(self, adapters):
        self.adapters = adapters

    def emit(self, finding):
        self.emit_batch([finding])

    def emit_batch(self, findings):
        for a in self.adapters:
            try:
                a.emit_batch(findings)
            except Exception as e:
                log.error("sink %s failed (continuing): %s", type(a).__name__, e)


def _make(kind):
    kind = kind.strip().lower()
    if kind == "file":
        return FileAdapter(os.environ.get("CERNITY_SINK_FILE", "/var/lib/cernity/findings.jsonl"))
    if kind in ("elasticsearch", "opensearch", "es"):
        return ElasticsearchAdapter()
    if kind == "splunk":
        return SplunkAdapter()
    if kind == "webhook":
        return WebhookAdapter()
    if kind in ("syslog", "cef"):
        return SyslogCefAdapter()
    if kind == "devo":
        return DevoAdapter()
    raise ValueError(f"unknown CERNITY_SINK: {kind}")


def get_adapter(on_health=None):
    names = [n.strip() for n in os.environ.get("CERNITY_SINK", "file").split(",") if n.strip()] or ["file"]
    # Each sink retries + dead-letters + dedups independently (F07 durable delivery) and
    # reports its own health to readiness (F15) via on_health(name, ok).
    def _h(name):
        return (lambda ok: on_health(name, ok)) if on_health else None
    sinks = [DurableSink(_make(n), n, on_health=_h(n)) for n in names]
    return sinks[0] if len(sinks) == 1 else MultiAdapter(sinks)
