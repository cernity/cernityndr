"""Reconstruction service (plan U19). Two jobs:
  1) background: consume ndr.session.v1 -> persist ndr.session (ClickHouse).
  2) HTTP API: reconstruct-by-source timeline + entity graph from ClickHouse.

Assembly logic is covered by test_reconstruct.py; this is the I/O shell.
  GET /health
  GET /reconstruct?tenant=homelab&asset=<ip>&window_min=60
  GET /graph?tenant=homelab&asset=<ip>&window_min=60
"""
import json
import logging
import os
import ndr_runtime
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from kafka import KafkaConsumer
import clickhouse_connect

import reconstruct as rc

log = ndr_runtime.setup_logging("reconstruction")

BOOTSTRAP = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
CH_HOST = os.environ.get("CLICKHOUSE_HOST", "clickhouse")
CH_USER = os.environ.get("CLICKHOUSE_USER", "ndr")
CH_PASS = os.environ["CLICKHOUSE_PASSWORD"]
PORT = int(os.environ.get("PORT", "8090"))
SESSION_COLS = ["session_id", "tenant_id", "session_type", "src_ip", "dst_ip",
                "app_proto", "started", "ended", "community_ids", "flows", "bytes_total"]


def ch():
    return clickhouse_connect.get_client(host=CH_HOST, username=CH_USER, password=CH_PASS)


def _dt(s):
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return datetime.now(timezone.utc)


def session_consumer():
    client = ch()
    consumer = KafkaConsumer("ndr.session.v1", bootstrap_servers=BOOTSTRAP,
                             group_id="ndr-reconstruction", auto_offset_reset="earliest",
                             enable_auto_commit=True,
                             value_deserializer=lambda b: json.loads(b.decode()))
    log.info("session consumer up")
    for msg in consumer:
        s = msg.value
        cids = [c for c in (s.get("community_ids") or "").split(",") if c]
        client.insert("ndr.session", [[
            s.get("session_id"), os.environ.get("NDR_TENANT", "default"),
            s.get("session_type", "host_pair"), s.get("src_ip", ""), s.get("dst_ip", ""),
            s.get("app_proto", ""), _dt(s.get("started")), _dt(s.get("ended")),
            cids, int(s.get("flows", 0) or 0), int(s.get("bytes", 0) or 0)]],
            column_names=SESSION_COLS)


def _rows(client, sql, params):
    r = client.query(sql, parameters=params)
    return [dict(zip(r.column_names, row)) for row in r.result_rows]


def gather(tenant, asset, win):
    rc.safe_param(tenant); rc.safe_param(asset)
    p = {"t": tenant, "a": asset, "w": win}
    c = ch()
    flows = _rows(c, "SELECT event_time, src_ip, dst_ip, dst_port, app_proto, ndpi_protocol "
                     "FROM ndr.network_flow WHERE tenant_id={t:String} AND (src_ip={a:String} "
                     "OR dst_ip={a:String}) AND event_time > now()-INTERVAL {w:UInt32} MINUTE "
                     "ORDER BY event_time LIMIT 500", p)
    sessions = _rows(c, "SELECT session_type, src_ip, dst_ip, app_proto, started, flows "
                        "FROM ndr.session WHERE tenant_id={t:String} AND (src_ip={a:String} "
                        "OR dst_ip={a:String}) ORDER BY started LIMIT 200", p)
    findings = _rows(c, "SELECT finding_id, category, detector_id, severity, state, first_seen "
                        "FROM ndr.finding WHERE tenant_id={t:String} AND entities LIKE {like:String} "
                        "ORDER BY first_seen LIMIT 200", {**p, "like": f"%{asset}%"})
    return flows, sessions, findings


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, obj):
        body = json.dumps(obj, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path == "/health":
            return self._send(200, {"status": "ok"})
        tenant = q.get("tenant", ["default"])[0]
        asset = q.get("asset", [""])[0]
        win = int(q.get("window_min", ["60"])[0])
        try:
            flows, sessions, findings = gather(tenant, asset, win)
        except ValueError as e:
            return self._send(400, {"error": str(e)})
        if u.path == "/reconstruct":
            return self._send(200, {"asset": asset, "window_min": win,
                                    "timeline": rc.build_timeline(flows, sessions, findings)})
        if u.path == "/graph":
            return self._send(200, rc.build_graph(asset, flows, findings))
        return self._send(404, {"error": "not found"})


def main():
    threading.Thread(target=session_consumer, daemon=True).start()
    log.info("reconstruction API on :%d", PORT)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
