"""Refresh open YARA rulesets (plan U6). Returns the paths of all .yar files to
compile: the bundled baseline plus any remote rules fetched into a writable
cache. Set YARA_RULES_URLS to a comma-separated list of raw .yar URLs (for
example open rules from YARA-Rules or a signature-base mirror). Falls back to
the bundled rules when the network is unavailable, so the scanner always has at
least one rule loaded.
"""
import logging
import os
import urllib.request

log = logging.getLogger("file-yara.rules")
UA = "ndr-file-yara"
MAX_RULE_BYTES = 8 * 1024 * 1024        # cap a single fetched ruleset at 8 MiB


def _remote_urls():
    raw = os.environ.get("YARA_RULES_URLS", "").strip()
    return [u.strip() for u in raw.split(",") if u.strip()]


def ensure_rules(bundled_dir="/app/rules", cache_dir="/tmp/yara-rules"):
    os.makedirs(cache_dir, exist_ok=True)
    for i, url in enumerate(_remote_urls()):
        if not url.startswith("https://"):          # require TLS for remote rules
            log.warning("skipping non-https rule url: %s", url)
            continue
        dest = os.path.join(cache_dir, f"remote_{i}.yar")
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = r.read(MAX_RULE_BYTES + 1)
            if len(data) > MAX_RULE_BYTES:
                log.warning("rule %s exceeds %d bytes; skipping", url, MAX_RULE_BYTES)
                continue
            with open(dest, "wb") as fh:
                fh.write(data)
        except Exception as e:                       # keep whatever we already have
            log.warning("rule fetch %s failed: %s", url, e)
    paths = []
    for d in (bundled_dir, cache_dir):
        if os.path.isdir(d):
            paths += [os.path.join(d, f) for f in sorted(os.listdir(d)) if f.endswith(".yar")]
    return paths
