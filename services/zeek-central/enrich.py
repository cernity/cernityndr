"""Central Zeek enrichment (plan U11; deepened). Consumes ndr.enrichment.request.v1,
pulls the bounded PCAP from MinIO, runs Zeek, and summarizes the THREAT-relevant
Zeek logs — not just conn.log counts:

  conn      : connection/service/protocol shape
  ssl       : TLS incl. JA3/JA3S fingerprints, SNI, cert validation failures
  x509      : certificate subject/issuer/validity, self-signed detection
  files     : mime + md5/sha1/sha256 (feeds malware-hash matching / G2)
  smb       : file/share operations (lateral movement)
  kerberos  : AS/TGS/SPN/encryption, with a kerberoast heuristic

Emits ndr.enrichment.result.v1 with the rich summary plus extracted IOCs (file
hashes, JA3s, self-signed certs) for the finding's evidence and the reconstruction
graph. A failed/empty PCAP yields status=failed — never a crash, never a silent
drop (v2 §17); the finding still FINALizes.
"""
import json
import logging
import os
import signal
import subprocess
import tempfile

log = logging.getLogger("zeek-central")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


# ------------------------------------------------------------- generic Zeek TSV
def parse_zeek_tsv(text: str) -> list[dict]:
    """Parse a Zeek TSV log (#fields header) into a list of row dicts. Pure."""
    fields: list[str] = []
    rows: list[dict] = []
    for line in text.splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if line.startswith("#") or not line.strip():
            continue
        cols = line.split("\t")
        rows.append({fields[i]: cols[i] for i in range(min(len(fields), len(cols)))} if fields else {})
    return rows


def _v(x):
    """Normalize Zeek unset markers to None."""
    return None if x in (None, "", "-", "(empty)") else x


# --------------------------------------------------------------- per-log summaries
def summarize_conn_log(text: str) -> dict:
    rows = parse_zeek_tsv(text)
    services: dict = {}
    protos: dict = {}
    for r in rows:
        svc = r.get("service", "-") or "-"
        p = r.get("proto", "-") or "-"
        services[svc] = services.get(svc, 0) + 1
        protos[p] = protos.get(p, 0) + 1
    return {"connections": len(rows), "services": services, "protocols": protos}


def summarize_ssl(text: str) -> dict:
    rows = parse_zeek_tsv(text)
    ja3, ja4, ja4s_set, sni, details, bad = set(), set(), set(), set(), [], 0
    for r in rows:
        vs = _v(r.get("validation_status"))
        if vs and vs.lower() != "ok":
            bad += 1
        j, s = _v(r.get("ja3")), _v(r.get("server_name"))
        # JA4+ (client + server TLS fingerprints) from the FoxIO ja4 Zeek package.
        j4, j4s = _v(r.get("ja4")), _v(r.get("ja4s"))
        if j:
            ja3.add(j)
        if j4:
            ja4.add(j4)
        if j4s:
            ja4s_set.add(j4s)
        if s:
            sni.add(s)
        details.append({"server_name": s, "ja3": j, "ja3s": _v(r.get("ja3s")),
                        "ja4": j4, "ja4s": j4s,
                        "version": _v(r.get("version")), "validation_status": vs,
                        "subject": _v(r.get("subject")), "issuer": _v(r.get("issuer"))})
    return {"tls_connections": len(rows), "unique_ja3": sorted(ja3),
            "unique_ja4": sorted(ja4), "unique_ja4s": sorted(ja4s_set),
            "server_names": sorted(sni), "validation_failures": bad, "details": details[:50]}


def summarize_x509(text: str) -> dict:
    rows = parse_zeek_tsv(text)
    details, selfsigned = [], 0
    for r in rows:
        subj = _v(r.get("certificate.subject"))
        iss = _v(r.get("certificate.issuer"))
        ss = bool(subj and iss and subj == iss)
        if ss:
            selfsigned += 1
        details.append({"subject": subj, "issuer": iss, "self_signed": ss,
                        "ja4x": _v(r.get("ja4x")),   # cert fingerprint (JA4+)
                        "not_valid_before": _v(r.get("certificate.not_valid_before")),
                        "not_valid_after": _v(r.get("certificate.not_valid_after")),
                        "san": _v(r.get("san.dns"))})
    return {"certificates": len(rows), "self_signed": selfsigned, "details": details[:50]}


def summarize_http(text: str) -> dict:
    """HTTP requests + JA4H (HTTP client fingerprint, JA4+)."""
    rows = parse_zeek_tsv(text)
    ja4h, details = set(), []
    for r in rows:
        h = _v(r.get("ja4h"))
        if h:
            ja4h.add(h)
        details.append({"host": _v(r.get("host")), "uri": _v(r.get("uri")),
                        "method": _v(r.get("method")), "user_agent": _v(r.get("user_agent")),
                        "status_code": _v(r.get("status_code")), "ja4h": h})
    return {"http_requests": len(rows), "unique_ja4h": sorted(ja4h), "details": details[:50]}


def summarize_ssh(text: str) -> dict:
    """SSH sessions + JA4SSH (SSH fingerprint, JA4+)."""
    rows = parse_zeek_tsv(text)
    ja4ssh, details = set(), []
    for r in rows:
        s = _v(r.get("ja4ssh"))
        if s:
            ja4ssh.add(s)
        details.append({"client": _v(r.get("client")), "server": _v(r.get("server")),
                        "auth_success": _v(r.get("auth_success")), "ja4ssh": s})
    return {"ssh_sessions": len(rows), "unique_ja4ssh": sorted(ja4ssh), "details": details[:50]}


def summarize_files(text: str) -> dict:
    rows = parse_zeek_tsv(text)
    details, hashes = [], []
    for r in rows:
        h = {k: _v(r.get(k)) for k in ("md5", "sha1", "sha256")}
        for alg in ("sha256", "sha1", "md5"):
            if h.get(alg):
                hashes.append(h[alg])
        details.append({"mime_type": _v(r.get("mime_type")),
                        "filename": _v(r.get("filename")) or _v(r.get("extracted")),
                        "source": _v(r.get("source")), "seen_bytes": _v(r.get("seen_bytes")), **h})
    return {"files": len(rows), "hashes": sorted(set(hashes)), "details": details[:50]}


def summarize_smb(text: str) -> dict:
    rows = parse_zeek_tsv(text)
    details = [{"action": _v(r.get("action")), "path": _v(r.get("path")),
                "name": _v(r.get("name")), "share_type": _v(r.get("share_type"))} for r in rows]
    return {"smb_events": len(rows), "details": details[:50]}


def summarize_kerberos(text: str) -> dict:
    rows = parse_zeek_tsv(text)
    details, tgs, weak, spns = [], 0, 0, set()
    for r in rows:
        rt, svc, ci = _v(r.get("request_type")), _v(r.get("service")), _v(r.get("cipher"))
        if rt == "TGS":
            tgs += 1
        if svc:
            spns.add(svc)
        if ci and ("rc4" in ci.lower() or "des" in ci.lower()):
            weak += 1
        details.append({"request_type": rt, "client": _v(r.get("client")), "service": svc,
                        "success": _v(r.get("success")), "error_msg": _v(r.get("error_msg")), "cipher": ci})
    # Kerberoast tell: many TGS requests spanning many distinct SPNs (often weak enc).
    kerberoast = tgs >= 8 and len(spns) >= 8
    return {"kerberos_events": len(rows), "tgs_requests": tgs, "distinct_spns": len(spns),
            "weak_encryption": weak, "kerberoast_suspected": kerberoast, "details": details[:50]}


_LOGS = [
    ("conn", "conn.log", summarize_conn_log),
    ("ssl", "ssl.log", summarize_ssl),
    ("x509", "x509.log", summarize_x509),
    ("http", "http.log", summarize_http),
    ("ssh", "ssh.log", summarize_ssh),
    ("files", "files.log", summarize_files),
    ("smb_files", "smb_files.log", summarize_smb),
    ("smb_mapping", "smb_mapping.log", summarize_smb),
    ("kerberos", "kerberos.log", summarize_kerberos),
]


def extract_iocs(summary: dict) -> dict:
    """Pull actionable IOCs out of the summary for the finding's evidence."""
    iocs: dict = {}
    if summary.get("files", {}).get("hashes"):
        iocs["file_hashes"] = summary["files"]["hashes"]
    if summary.get("ssl", {}).get("unique_ja3"):
        iocs["ja3"] = summary["ssl"]["unique_ja3"]
    # JA4+ fingerprints (client/server TLS, HTTP, SSH) as pivotable IOCs.
    if summary.get("ssl", {}).get("unique_ja4"):
        iocs["ja4"] = summary["ssl"]["unique_ja4"]
    if summary.get("ssl", {}).get("unique_ja4s"):
        iocs["ja4s"] = summary["ssl"]["unique_ja4s"]
    if summary.get("http", {}).get("unique_ja4h"):
        iocs["ja4h"] = summary["http"]["unique_ja4h"]
    if summary.get("ssh", {}).get("unique_ja4ssh"):
        iocs["ja4ssh"] = summary["ssh"]["unique_ja4ssh"]
    if summary.get("x509", {}).get("self_signed"):
        iocs["self_signed_certs"] = summary["x509"]["self_signed"]
    if summary.get("kerberos", {}).get("kerberoast_suspected"):
        iocs["kerberoast_suspected"] = True
    return iocs


def run_zeek(pcap_path: str) -> dict:
    """Run Zeek over a pcap in an isolated dir; summarize every threat-relevant log
    that Zeek produced. JA3/JA4 come from the ja3/ja4 packages installed in the image
    (auto-loaded via zkg), so they ride ssl.log when present."""
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(["zeek", "-r", pcap_path], cwd=d, check=True,
                       capture_output=True, timeout=120)
        summary: dict = {}
        for key, fname, fn in _LOGS:
            p = os.path.join(d, fname)
            if os.path.exists(p):
                with open(p, errors="ignore") as f:
                    summary[key] = fn(f.read())
        return summary or {"conn": {"connections": 0, "services": {}, "protocols": {}}}


def _main():  # pragma: no cover (I/O shell)
    from kafka import KafkaConsumer, KafkaProducer
    import boto3

    bootstrap = os.environ.get("REDPANDA_BOOTSTRAP", "redpanda:9092")
    s3 = boto3.client("s3", endpoint_url=os.environ.get("MINIO_ENDPOINT", "http://minio:9000"),
                      aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
                      aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"])
    producer = KafkaProducer(bootstrap_servers=bootstrap,
                             value_serializer=lambda v: json.dumps(v).encode())
    consumer = KafkaConsumer("ndr.enrichment.request.v1", bootstrap_servers=bootstrap,
                             group_id="ndr-zeek-central", auto_offset_reset="earliest",
                             enable_auto_commit=True,
                             value_deserializer=lambda b: json.loads(b.decode()))
    log.info("zeek-central up (deep: conn/ssl/x509/http/ssh/files/smb/kerberos + JA3 + JA4+)")
    running = True

    def stop(*_):
        nonlocal running
        running = False
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    while running:
        for _tp, records in consumer.poll(timeout_ms=1000, max_records=20).items():
            for rec in records:
                req = rec.value
                ref = req.get("pcap_ref", "")
                bucket, _, key = ref.partition("/")
                result = {"finding_id": req.get("finding_id"), "pcap_ref": ref}
                try:
                    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmp:
                        s3.download_fileobj(bucket, key, tmp)
                        tmp.flush()
                        summary = run_zeek(tmp.name)
                    result.update(status="ok", summary=summary,
                                  iocs=extract_iocs(summary),
                                  evidence_refs=[f"minio://{ref}"])
                    log.info("ENRICHED %s: %s", req.get("finding_id"),
                             {k: (v.get("connections") or v.get("tls_connections")
                                  or v.get("files") or v.get("kerberos_events") or len(v))
                              for k, v in summary.items()})
                except Exception as e:
                    result.update(status="failed", error=str(e))
                    log.warning("ENRICHMENT_FAILED %s: %s", req.get("finding_id"), e)
                producer.send("ndr.enrichment.result.v1", result)
        producer.flush()


if __name__ == "__main__":
    _main()
