"""Refresh open YARA rulesets (plan U6; Unit U3 registry-backed).

Two entrypoints, one trust boundary:

`refresh_to_registry` STAGES untrusted REMOTE rulesets: it fetches any remote rules
(YARA_RULES_URLS — a comma-separated list of raw .yar URLs, e.g. open rules from a
signature-base mirror) and writes each as a DRAFT row in the RulesetRegistry. A
fetched ruleset enters staging as a draft and reaches the scan worker ONLY after an
AUTHORIZED promotion, so a swapped upstream file cannot silently become active. It
is idempotent by content sha256 — re-running does not spam duplicate drafts, and a
deliberate retire (a row already exists for those bytes) is not undone by a re-fetch.

`ensure_rules` is the COMPILE path used by app.py's refresh loop. It returns only
the .yar paths a worker may compile:

  * registry rulesets an authorized caller PROMOTED to active/shadow, whose bytes are
    re-verified against their registered sha256 before use; and
  * the bundled, in-repo baseline (authored under §26 IP; always available with no
    network and no registry) — served straight from the image, UNLESS an AUTHORIZED
    transition has brought those exact bytes under registry control. A bundled
    ruleset an operator promoted is served from the object store while active/shadow
    and excluded once retired, so the lifecycle — including retirement — applies to
    bundled rules too. An anonymous draft does NOT suppress the bundled baseline
    (register_draft is not authz-gated), so unauthenticated draft registration — or a
    remote copy staged by refresh_to_registry — cannot disable a bundled rule.

Remote rules are NEVER fetched or compiled by ensure_rules — they reach the scanner
only via refresh_to_registry staging + an authorized promotion (poisoned-rule guard).
The cache is repopulated from the registry each call, so an unpromoted remote_*.yar
left by an older build is purged and can never enter the compile path.
"""
import hashlib
import logging
import os
import urllib.request

log = logging.getLogger("file-yara.rules")
UA = "ndr-file-yara"
MAX_RULE_BYTES = 8 * 1024 * 1024        # cap a single fetched ruleset at 8 MiB


def _remote_urls():
    raw = os.environ.get("YARA_RULES_URLS", "").strip()
    return [u.strip() for u in raw.split(",") if u.strip()]


def _fetch_remote(url):
    """Fetch one remote ruleset over TLS, size-capped. Returns bytes, or None on a
    non-https url, an oversize body, or any network error (caller keeps going)."""
    if not url.startswith("https://"):              # require TLS for remote rules
        log.warning("skipping non-https rule url: %s", url)
        return None
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = r.read(MAX_RULE_BYTES + 1)
    except Exception as e:
        log.warning("rule fetch %s failed: %s", url, e)
        return None
    if len(data) > MAX_RULE_BYTES:
        log.warning("rule %s exceeds %d bytes; skipping", url, MAX_RULE_BYTES)
        return None
    return data


def refresh_to_registry(registry, source="rules-refresh",
                        target_mime_types=None, max_file_size=64 * 1024 * 1024):
    """Stage every reachable REMOTE ruleset (YARA_RULES_URLS) as a DRAFT row in
    `registry`. Remote rules are untrusted: they enter as drafts and reach the scan
    worker ONLY after an authorized promotion (poisoned-rule guard). Idempotent by
    content sha256 — a ruleset whose bytes already have a row (ANY status, so a
    deliberate retire is not undone) is skipped. Returns the ids of the NEW drafts.

    The bundled in-repo baseline is intentionally NOT staged here: it is served
    directly from the image by ensure_rules (the always-available, no-network
    baseline). An operator who wants a bundled rule to follow the lifecycle
    registers it explicitly; ensure_rules then honors that row's status."""
    existing = {r["sha256"] for r in registry.list_rulesets()}
    ids = []
    for i, url in enumerate(_remote_urls()):
        data = _fetch_remote(url)
        if data is None:
            continue
        sha = hashlib.sha256(data).hexdigest()
        if sha in existing:                         # content already staged/promoted/retired
            continue
        row = registry.register_draft(
            name=f"remote_{i}:{url}", version=sha[:12], data=data, source=source,
            target_mime_types=target_mime_types, max_file_size=max_file_size)
        existing.add(sha)
        ids.append(row["id"])
    log.info("staged %d new remote ruleset draft(s)", len(ids))
    return ids


def ensure_rules(registry=None, bundled_dir="/app/rules", cache_dir="/tmp/yara-rules"):
    """Return the .yar paths a scan worker may COMPILE — the trust boundary for the
    scanner. Two kinds of rules reach here:

      * registry rulesets an authorized caller PROMOTED to active/shadow, whose bytes
        are re-verified against their registered sha256 (materialised into cache_dir);
      * the bundled, in-repo baseline, served straight from the image — UNLESS an
        AUTHORIZED transition has brought those exact bytes under registry control.
        A bundled ruleset an operator promoted is compiled while served (active/
        shadow) and its disk copy excluded once retired, so the lifecycle (including
        retirement) applies to bundled rules too. An anonymous draft does NOT
        suppress the bundled baseline: register_draft is not authz-gated, so an
        unauthenticated draft (or a remote copy staged by refresh_to_registry) can
        never disable a bundled rule. A bundled file no NON-draft row governs is the
        always-available baseline.

    Remote rules are NEVER fetched or compiled here (poisoned-rule guard). The cache
    is repopulated from the registry each call, so a stale materialised ruleset (e.g.
    a remote_*.yar written by an older build) is purged and cannot be compiled."""
    os.makedirs(cache_dir, exist_ok=True)
    for f in os.listdir(cache_dir):                 # drop stale materialized rulesets
        if f.endswith(".yar"):
            os.remove(os.path.join(cache_dir, f))
    paths = []
    governed = set()                                # sha256s the registry has an opinion on
    if registry is not None:
        for row in registry.active_for_scan():      # active/shadow only
            data = registry.load_bytes(row["id"])   # sha256-verified integrity check
            p = os.path.join(cache_dir, f"served_{row['id']}.yar")
            with open(p, "wb") as fh:
                fh.write(data)
            paths.append(p)
        # A bundled rule leaves the always-available baseline and comes under
        # registry lifecycle control ONLY through an AUTHORIZED transition out of
        # draft (promote() is authz-gated; register_draft is not). An anonymous
        # draft — including a remote copy of a bundled rule staged by
        # refresh_to_registry — must NOT suppress the bundled baseline, or
        # unauthenticated draft registration would silently disable bundled
        # detection. So only NON-draft rows govern the disk baseline.
        governed = {r["sha256"] for r in registry.list_rulesets() if r["status"] != "draft"}
    if os.path.isdir(bundled_dir):
        for f in sorted(os.listdir(bundled_dir)):
            if not f.endswith(".yar"):
                continue
            fp = os.path.join(bundled_dir, f)
            with open(fp, "rb") as fh:
                sha = hashlib.sha256(fh.read()).hexdigest()
            if sha in governed:                     # authorized non-draft row governs:
                continue                            # served from store, or excluded if retired
            paths.append(fp)
    return paths
