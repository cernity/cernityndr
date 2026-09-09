"""HTTP detections (Tier-1 detection-gap fill).

The protocol-detectors service only checks the user-agent today. HTTP is a large
detection surface we already collect in full on `suricata.http.v1`. This adds
precise, low-false-positive detections on the request URI and method:

  - http_webshell        : known webshell / backdoor URIs.
  - http_sqli            : SQL-injection patterns in the URI.
  - http_cmd_injection   : OS command-injection patterns in the URI.
  - http_path_traversal  : path traversal / LFI (../.. , /etc/passwd, php://).
  - http_cred_in_url     : credentials passed in the query string.
  - http_suspicious_method: uncommon/risky HTTP methods (PUT/DELETE/PROPFIND/...).

Pure and testable; app.py is the Kafka I/O shell.
"""
import re

_WEBSHELL = re.compile(
    r"(?:/(?:c99|r57|b374k|wso|c100|shell|cmd|backdoor|webshell|antichat|mini[_-]?shell)\b"
    r"|/(?:tmp|uploads?|images?)/[a-z0-9_]+\.(?:php|jsp|asp|aspx)\b"
    r"|\.(?:php|asp|aspx|jsp);\b)", re.I)
_SQLI = re.compile(
    r"(?:union(?:\s|/\*.*?\*/|\+)+select|'\s*or\s*'?\d'?\s*=\s*'?\d|\bor\s+1\s*=\s*1\b"
    r"|sleep\(\s*\d|benchmark\(\s*\d|information_schema|;\s*drop\s+table|waitfor\s+delay)", re.I)
_CMDI = re.compile(
    r"(?:;\s*(?:cat|wget|curl|nc|bash|sh|powershell|whoami|id|uname)\b"
    r"|\|\s*(?:nc|bash|sh|powershell)\b|\$\([^)]+\)|%0a(?:cat|wget|curl|id)\b)", re.I)
_TRAVERSAL = re.compile(
    r"(?:\.\./\.\./|\.\.\\|\.\.%2f|%2e%2e%2f|/etc/passwd|/proc/self/environ"
    r"|php://(?:filter|input)|file:///|data://text)", re.I)
_CRED_IN_URL = re.compile(
    r"[?&](?:password|passwd|pwd|token|apikey|api_key|secret|access_key|auth)=[^&\s]+", re.I)
_RISKY_METHODS = frozenset({"PUT", "DELETE", "PROPFIND", "PROPPATCH", "MKCOL",
                            "COPY", "MOVE", "TRACE", "CONNECT", "SEARCH"})


def http_findings(method: str = "", url: str = "", host: str = "",
                  content_type: str = "") -> list[tuple[str, str, int, str]]:
    """Return a list of (detector_id, category, severity, why) for one HTTP request.
    Empty list when nothing matches. Precise by design; HTTP is noisy, so each
    pattern is specific enough to keep false positives low."""
    out = []
    u = url or ""
    if _WEBSHELL.search(u):
        out.append(("http_webshell", "malware", 8, "webshell / backdoor URI"))
    if _SQLI.search(u):
        out.append(("http_sqli", "exploit", 7, "SQL-injection pattern in URI"))
    if _CMDI.search(u):
        out.append(("http_cmd_injection", "exploit", 8, "command-injection pattern in URI"))
    if _TRAVERSAL.search(u):
        out.append(("http_path_traversal", "exploit", 7, "path-traversal / LFI pattern"))
    if _CRED_IN_URL.search(u):
        out.append(("http_cred_in_url", "credential_access", 5, "credential in URL query"))
    if (method or "").upper() in _RISKY_METHODS:
        out.append(("http_suspicious_method", "c2", 5, f"uncommon HTTP method {method.upper()}"))
    return out
