"""coverage-service (U4): ATT&CK coverage map from detector metadata + findings.

Two signals, kept distinct in the output — never conflated:

* COVERED (fleet-global): a detector *exists* for a technique. Sourced from the
  detector->technique metadata, which is the same across every tenant (a fleet's
  detector set is not tenant-specific). Surfaces as `covered` / `detectors`.
* OBSERVED (tenant-scoped): the technique actually *fired* in this tenant's
  production, read from findings' `mitre` field. Surfaces as `observed`, and is
  derived server-side from the caller's bearer-token tenant grants (§21) — one
  tenant's firings never leak into another tenant's map.

The set of techniques the report *ranges over* is a fleet-global **catalog**
(the reporting universe), independent of both signals: a catalogued technique
with no detector is a gap whether or not it has ever fired, so gap reporting is a
property of the fleet, never of a tenant's observations. Detectors and observed
firings extend that universe (you always want to see a firing or a detector even
for an off-catalog technique), but they cannot shrink it — an uncatalogued,
undetected, unobserved technique is simply unknown to the report.

Malformed detector metadata is skipped, never fatal: one bad entry must not
blank the whole coverage report. Query logic lives here (unit-tested against a
fake ClickHouse client in test_coverage.py); app.py is the HTTP + ClickHouse
shell, mirroring evidence-service.
"""
import re

# ATT&CK technique or sub-technique id, e.g. T1046 or T1558.003.
TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def load_detector_map(config):
    """Fleet-global detector metadata -> {technique: sorted[detector_id]}.

    config: iterable of {"detector_id": str, "techniques": [technique-id, ...]}.
    Malformed entries — non-dict, missing/blank detector_id, non-list
    techniques, non-matching technique ids — are skipped, not fatal. Good
    techniques inside an otherwise-fine entry are kept; a bad technique in the
    list is dropped without discarding the rest.
    """
    mapping = {}
    for entry in config or []:
        if not isinstance(entry, dict):
            continue
        detector_id = entry.get("detector_id")
        techniques = entry.get("techniques")
        if not isinstance(detector_id, str) or not detector_id.strip():
            continue
        if not isinstance(techniques, list):
            continue
        for t in techniques:
            if isinstance(t, str) and TECHNIQUE_RE.match(t):
                mapping.setdefault(t, set()).add(detector_id)
    return {t: sorted(ds) for t, ds in mapping.items()}


def grants_for_token(tokens, auth_header):
    """Caller's granted tenants, derived server-side from the bearer token.
    None => unauthenticated (401). Same contract as evidence-service (§21);
    tenant is never a query param."""
    token = auth_header[7:] if (auth_header or "").startswith("Bearer ") else None
    return tokens.get(token) if token else None


def observed_query(grants):
    """SQL + bound params for the tenant-scoped observed overlay: the distinct
    ATT&CK techniques that appear in this tenant's findings' `mitre` field.
    tenant_id is a BOUND parameter (never interpolated) and restricted to the
    caller's grants, so one tenant's firings can never surface in another's map."""
    sql = ("SELECT DISTINCT arrayJoin(mitre) AS technique "
           "FROM ndr.finding WHERE tenant_id IN %(tenants)s AND notEmpty(mitre)")
    return sql, {"tenants": list(grants)}


def observed_from_rows(rows):
    """Well-formed ATT&CK ids from raw finding `mitre` values — a malformed
    `mitre` value in a finding is skipped, not fatal."""
    return {r for r in (rows or []) if isinstance(r, str) and TECHNIQUE_RE.match(r)}


def build_coverage(detector_map, observed, catalog=()):
    """Merge the fleet-global detector_map with a tenant's observed technique set
    into the coverage report. `covered` = a detector exists (fleet-global);
    `observed` = fired in this tenant (tenant-scoped).

    `catalog` is the fleet-global reporting universe (also fleet config): every
    catalogued technique appears, so a catalogued technique with no detector is a
    gap even when it has never fired — gap reporting does not depend on tenant
    observations. The report ranges over catalog ∪ detectors ∪ observed, so an
    observed-but-uncovered technique still surfaces as a firing gap and a
    covered-but-never-observed one as latent coverage. Malformed catalog entries
    are skipped, not fatal — consistent with detector metadata and findings."""
    observed = observed_from_rows(observed)
    catalog = {t for t in (catalog or ()) if isinstance(t, str) and TECHNIQUE_RE.match(t)}
    techniques = sorted(catalog | set(detector_map) | observed)
    rows = [{
        "technique": t,
        "covered": bool(detector_map.get(t)),
        "detectors": detector_map.get(t, []),
        "observed": t in observed,
    } for t in techniques]
    return {
        "techniques": rows,
        "gaps": [r["technique"] for r in rows if not r["covered"]],
        "summary": {
            "total": len(rows),
            "covered": sum(1 for r in rows if r["covered"]),
            "gaps": sum(1 for r in rows if not r["covered"]),
            "observed": sum(1 for r in rows if r["observed"]),
        },
    }
