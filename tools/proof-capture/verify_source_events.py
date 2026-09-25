"""U6 acceptance check: confirm a finding delivered to the live SIEM carries source_events
(the originating Suricata EVE). Run against the real ES the forwarder delivers to.

Usage: ES_ENDPOINT=https://192.168.222.141:9200 ES_USER=elastic ES_PASSWORD=... \
       python3 verify_source_events.py [finding_id_substring]

Queries ndr-findings-* for a finding where `source_events` exists (optionally matching a
finding_id), prints its _id + the native EVE fields carried (event_type/community_id/ja4/ndpi).
Exit 0 if found, 1 otherwise. No fabrication — reports exactly what the SIEM returned.
"""
import base64
import json
import os
import ssl
import sys
import urllib.request

ENDPOINT = os.environ["ES_ENDPOINT"].rstrip("/")
USER, PW = os.environ.get("ES_USER", "elastic"), os.environ.get("ES_PASSWORD", "")
FID = sys.argv[1] if len(sys.argv) > 1 else None

must = [{"exists": {"field": "source_events"}}]
if FID:
    must.append({"wildcard": {"finding_id": f"*{FID}*"}})
query = {"size": 1, "query": {"bool": {"must": must}},
         "sort": [{"@timestamp": {"order": "desc"}}]}

req = urllib.request.Request(
    ENDPOINT + "/ndr-findings-*/_search",
    data=json.dumps(query).encode(), method="POST",
    headers={"Content-Type": "application/json",
             "Authorization": "Basic " + base64.b64encode(f"{USER}:{PW}".encode()).decode()})
ctx = ssl._create_unverified_context()
with urllib.request.urlopen(req, context=ctx, timeout=15) as r:
    res = json.load(r)

hits = res.get("hits", {}).get("hits", [])
if not hits:
    print("NO finding with source_events found — deploy the branch and feed a real event first.")
    sys.exit(1)
h = hits[0]
src = h["_source"]
se = src.get("source_events") or []
rec = (se[0] or {}).get("record", {}) if se else {}
print(f"FOUND _id={h['_id']} finding_id={src.get('finding_id')} detector={src.get('detector_id')}")
print(f"source_events[0]: event_type={rec.get('event_type')} community_id={se[0].get('community_id') if se else None}")
q = rec.get("quic") or rec.get("tls") or {}
print(f"  ja4={q.get('ja4')} sni={q.get('sni')} ndpi.proto={(rec.get('ndpi') or {}).get('proto')}")
print("PASS: the SIEM finding carries the originating Suricata EVE.")
