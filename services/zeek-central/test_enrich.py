"""zeek-central deep-summary parser tests (pure)."""
import enrich

CONN = "\n".join(["#fields\tts\tuid\tproto\tservice",
                  "1\tC1\ttcp\tssl", "2\tC2\tudp\tdns", "3\tC3\ttcp\tssl", "#close\tx"])
SSL = "\n".join(["#fields\tserver_name\tja3\tja3s\tversion\tvalidation_status\tsubject\tissuer",
                 "evil.com\tabc123\tdef456\tTLSv13\tself signed certificate\tCN=evil\tCN=evil",
                 "ok.com\tzzz\t-\tTLSv12\tok\tCN=ok\tCN=DigiCert", "#close\tx"])
X509 = "\n".join(["#fields\tcertificate.subject\tcertificate.issuer\tcertificate.not_valid_after",
                  "CN=evil\tCN=evil\t2026-01-01", "CN=ok\tCN=DigiCert\t2027-01-01", "#close\tx"])
FILES = "\n".join(["#fields\tmime_type\tfilename\tsource\tseen_bytes\tmd5\tsha1\tsha256",
                   "application/x-dosexec\tbad.exe\tHTTP\t4096\tm1\ts1\tSHA256BAD",
                   "text/plain\t-\tHTTP\t10\t-\t-\t-", "#close\tx"])
KRB = "\n".join(["#fields\trequest_type\tclient\tservice\tsuccess\tcipher"] +
                ["TGS\tu\tHTTP/spn%d\tT\trc4-hmac" % i for i in range(9)] + ["#close\tx"])


def test_conn():
    s = enrich.summarize_conn_log(CONN)
    assert s["connections"] == 3 and s["protocols"] == {"tcp": 2, "udp": 1}
    assert s["services"]["ssl"] == 2


def test_ssl_ja3_and_validation():
    s = enrich.summarize_ssl(SSL)
    assert s["tls_connections"] == 2 and "abc123" in s["unique_ja3"]
    assert s["validation_failures"] == 1 and "evil.com" in s["server_names"]


def test_x509_self_signed():
    s = enrich.summarize_x509(X509)
    assert s["certificates"] == 2 and s["self_signed"] == 1


def test_files_hashes():
    s = enrich.summarize_files(FILES)
    assert s["files"] == 2 and "SHA256BAD" in s["hashes"]
    assert s["details"][0]["mime_type"] == "application/x-dosexec"


def test_kerberos_kerberoast():
    s = enrich.summarize_kerberos(KRB)
    assert s["tgs_requests"] == 9 and s["distinct_spns"] == 9
    assert s["kerberoast_suspected"] is True and s["weak_encryption"] == 9


def test_extract_iocs():
    summ = {"files": enrich.summarize_files(FILES), "ssl": enrich.summarize_ssl(SSL),
            "x509": enrich.summarize_x509(X509), "kerberos": enrich.summarize_kerberos(KRB)}
    iocs = enrich.extract_iocs(summ)
    assert "SHA256BAD" in iocs["file_hashes"] and "abc123" in iocs["ja3"]
    assert iocs["self_signed_certs"] == 1 and iocs["kerberoast_suspected"] is True


def test_empty_log():
    assert enrich.summarize_conn_log("#fields\tts\n#close\tx")["connections"] == 0


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print("ok ", fn.__name__)
    print("all %d enrich tests passed" % len(fns))
