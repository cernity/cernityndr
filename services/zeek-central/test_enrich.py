"""zeek-central deep-summary parser tests (pure)."""
import enrich

CONN = "\n".join(["#fields\tts\tuid\tproto\tservice",
                  "1\tC1\ttcp\tssl", "2\tC2\tudp\tdns", "3\tC3\ttcp\tssl", "#close\tx"])
SSL = "\n".join(["#fields\tserver_name\tja3\tja3s\tja4\tja4s\tversion\tvalidation_status\tsubject\tissuer",
                 "evil.com\tabc123\tdef456\tt13d1516h2_ja4client\tt130200_ja4server\tTLSv13\tself signed certificate\tCN=evil\tCN=evil",
                 "ok.com\tzzz\t-\t-\t-\tTLSv12\tok\tCN=ok\tCN=DigiCert", "#close\tx"])
HTTP = "\n".join(["#fields\thost\turi\tmethod\tuser_agent\tstatus_code\tja4h",
                  "evil.com\t/gate\tPOST\tcurl/8\t200\tge11nn08_ja4h",
                  "ok.com\t/\tGET\tMozilla\t200\t-", "#close\tx"])
SSH = "\n".join(["#fields\tclient\tserver\tauth_success\tja4ssh",
                 "SSH-2.0-OpenSSH\tSSH-2.0-libssh\tT\tc36s36_ja4ssh", "#close\tx"])
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


def test_ssl_ja4_plus():
    s = enrich.summarize_ssl(SSL)
    assert "t13d1516h2_ja4client" in s["unique_ja4"]
    assert "t130200_ja4server" in s["unique_ja4s"]
    assert s["details"][0]["ja4"] == "t13d1516h2_ja4client"


def test_http_ja4h():
    s = enrich.summarize_http(HTTP)
    assert s["http_requests"] == 2 and "ge11nn08_ja4h" in s["unique_ja4h"]
    assert s["details"][0]["host"] == "evil.com"


def test_ssh_ja4ssh():
    s = enrich.summarize_ssh(SSH)
    assert s["ssh_sessions"] == 1 and "c36s36_ja4ssh" in s["unique_ja4ssh"]


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
            "http": enrich.summarize_http(HTTP), "ssh": enrich.summarize_ssh(SSH),
            "x509": enrich.summarize_x509(X509), "kerberos": enrich.summarize_kerberos(KRB)}
    iocs = enrich.extract_iocs(summ)
    assert "SHA256BAD" in iocs["file_hashes"] and "abc123" in iocs["ja3"]
    assert "t13d1516h2_ja4client" in iocs["ja4"] and "t130200_ja4server" in iocs["ja4s"]
    assert "ge11nn08_ja4h" in iocs["ja4h"] and "c36s36_ja4ssh" in iocs["ja4ssh"]
    assert iocs["self_signed_certs"] == 1 and iocs["kerberoast_suspected"] is True


def test_empty_log():
    assert enrich.summarize_conn_log("#fields\tts\n#close\tx")["connections"] == 0


def test_security_kwargs_none_is_plaintext():
    # No SASL mechanism -> local/insecure bus, no auth kwargs (handoff §4 secure-bus gate).
    assert enrich._security_kwargs({}) == {}


def test_security_kwargs_partial_raises():
    # A mechanism without user+password must fail loudly, never silently fall back to plaintext.
    try:
        enrich._security_kwargs({"NDR_BUS_SASL_MECHANISM": "SCRAM-SHA-512"})
        raised = False
    except SystemExit:
        raised = True
    assert raised


def test_security_kwargs_sasl_plaintext_and_ssl():
    base = {"NDR_BUS_SASL_MECHANISM": "SCRAM-SHA-512",
            "NDR_BUS_SASL_USER": "cernity-central", "NDR_BUS_SASL_PASSWORD": "pw"}
    kw = enrich._security_kwargs(dict(base))
    assert kw["security_protocol"] == "SASL_PLAINTEXT" and kw["sasl_plain_username"] == "cernity-central"
    kw_tls = enrich._security_kwargs(dict(base, NDR_BUS_TLS_CA="/certs/ca.pem"))
    assert kw_tls["security_protocol"] == "SASL_SSL" and kw_tls["ssl_cafile"] == "/certs/ca.pem"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn(); print("ok ", fn.__name__)
    print("all %d enrich tests passed" % len(fns))
