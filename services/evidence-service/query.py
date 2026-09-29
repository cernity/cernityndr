"""evidence-service (U5) query logic: authz/tenant-scoping, the half-open window
query builder, and result shaping. All the logic lives here (unit-tested against a
fake ClickHouse client in test_query.py); app.py is the HTTP + ClickHouse I/O shell.

Backing store is U4's `ndr.evidence_observations` VIEW (deploy/clickhouse/init/
05-evidence.sql): a DISTINCT union over the typed observation tables exposing
tenant_id, obs_id, normalized_time, entity_values, type, ..., and `observation`
(the canonical observation.v1 JSON). We select the canonical JSON and return it —
a product API over evidence, not a raw column passthrough (design §7.1/§7.5).

Two rules mirror U3a's sensor-registry:
  * tenant is SERVER-DERIVED from the bearer token, NEVER a caller query param (§21).
  * callers pass an entity + a time window, never SQL; every user value is bound as
    a parameter, never interpolated.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone

VIEW = "ndr.evidence_observations"
OBS_TYPES = ("conn", "dns", "tls", "http")     # observation.v1 type enum (contracts/observation.schema.json)

MAX_PAGE_SIZE = 1000
DEFAULT_PAGE_SIZE = 500
MAX_WINDOW = timedelta(days=1)                  # oversize [from,to) is capped to this; caller pages via `next`

# entity is the only user string that ends up as a WHERE *value*. It's bound as a
# parameter (never interpolated), but validate its shape so a malformed entity is a
# clean 400 rather than a surprise full scan. Covers ip / domain / asset:... ids and
# IPv6 (colons). Mirrors reconstruct.safe_param.
_ENTITY_RE = re.compile(r"^[A-Za-z0-9_.:%\-\[\]]{1,255}$")


def grants_for_token(tokens, auth_header):
    """The caller's granted tenants, derived server-side from the bearer token.
    None => unauthenticated (missing/unknown token) -> the caller gets 401. Same
    contract as sensor-registry.app._grants (§21). Tenant is never a query param."""
    token = auth_header[7:] if (auth_header or "").startswith("Bearer ") else None
    return tokens.get(token) if token else None


def _parse_ts(s):
    """ISO8601 -> aware UTC datetime. `Z` and naive inputs are treated as UTC."""
    dt = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def parse_window(frm, to):
    """Parse [from,to) into aware UTC datetimes. Raises ValueError on a missing,
    unparseable, or non-positive window."""
    if not frm or not to:
        raise ValueError("from and to are required")
    try:
        a, b = _parse_ts(frm), _parse_ts(to)
    except (ValueError, TypeError):
        raise ValueError("from/to must be ISO8601 datetimes")
    if b <= a:
        raise ValueError("to must be after from")
    return a, b


def clamp_page_size(raw):
    """Bounded page size: default when unset, hard cap at MAX_PAGE_SIZE, >=1."""
    if raw in (None, ""):
        return DEFAULT_PAGE_SIZE
    try:
        n = int(raw)
    except (TypeError, ValueError):
        raise ValueError("page_size must be an integer")
    if n < 1:
        raise ValueError("page_size must be >= 1")
    return min(n, MAX_PAGE_SIZE)


def validate_entity(entity):
    if not entity or not _ENTITY_RE.match(entity):
        raise ValueError("entity is required and must be a valid identifier")
    return entity


def validate_type(obs_type):
    if obs_type in (None, ""):
        return None
    if obs_type not in OBS_TYPES:
        raise ValueError(f"type must be one of {OBS_TYPES}")
    return obs_type


def build_query(grants, entity, frm, until, obs_type, page_size, after=""):
    """Build the half-open [frm,until) query, tenant-scoped to the caller's grants,
    paged by a (normalized_time, obs_id) keyset cursor.

    The cursor `(frm, after)` is EXCLUSIVE of the row it names but INCLUSIVE of `frm`
    itself when `after` is empty (obs_id > '' matches every row), so the first page of
    a window starts exactly at `frm`. A (time, obs_id) keyset — not a bare time —
    is what lets consecutive pages walk THROUGH rows that share a timestamp without
    ever double-counting or dropping one. Fetches page_size+1 rows so the caller can
    tell whether the page is full. Every user value is a bound parameter."""
    where = [
        "tenant_id IN {tenants:Array(String)}",
        "has(entity_values, {entity:String})",
        "normalized_time < {until:DateTime64(3, 'UTC')}",      # half-open upper bound (exclusive)
        # keyset lower bound: strictly after (frm, after); with after='' this is >= frm.
        "(normalized_time > {frm:DateTime64(3, 'UTC')} OR "
        "(normalized_time = {frm:DateTime64(3, 'UTC')} AND obs_id > {after:String}))",
    ]
    params = {"tenants": list(grants), "entity": entity, "frm": frm,
              "until": until, "after": after, "limit": page_size + 1}
    if obs_type:
        where.append("type = {type:String}")
        params["type"] = obs_type
    sql = (f"SELECT obs_id, normalized_time, observation FROM {VIEW} "
           f"WHERE {' AND '.join(where)} "
           f"ORDER BY normalized_time, obs_id LIMIT {{limit:UInt32}}")
    return sql, params


def fetch_observations(client, grants, entity, frm, to, obs_type=None,
                       page_size=DEFAULT_PAGE_SIZE, after=""):
    """Serve one page of the evidence query and shape the result.

    Bounding is two-layered (§7.5), and continuation is a half-open keyset cursor so
    consecutive pages never double-count nor drop a row:
      * window cap: an oversize [frm,to) is capped to [frm, frm+MAX_WINDOW).
      * page cap:   at most page_size rows are returned.
    When a bound bites, the response carries `next` (a time) plus `next_after` (an
    obs_id); the caller resumes by passing them back as `from` and `after`. `next` is
    None on the last page. `next_after=''` when resuming at a fresh window boundary.
    """
    capped = min(to, frm + MAX_WINDOW)
    sql, params = build_query(grants, entity, frm, capped, obs_type, page_size, after)
    result = client.query(sql, parameters=params)
    rows = [dict(zip(result.column_names, r)) for r in result.result_rows]

    next_from = next_after = None
    if len(rows) > page_size:
        # Page cap hit: more rows remain in [frm,capped). Resume strictly after the
        # last returned row's (time, obs_id) — ties and all.
        rows = rows[:page_size]
        next_from, next_after = rows[-1]["normalized_time"], rows[-1]["obs_id"]
    elif capped < to:
        # Window cap bit before the page filled: resume at the fresh cap boundary.
        next_from, next_after = capped, ""

    observations = [json.loads(r["observation"]) for r in rows]
    caps = sorted({c for o in observations for c in o.get("capabilities", [])})
    out = {
        "observations": observations,
        "capabilities": caps,                          # union across the page — fidelity at a glance
        "next": None,
    }
    if next_from is not None:
        out["next"], out["next_after"] = _iso(next_from), next_after
    return out


def _iso(dt):
    if isinstance(dt, str):
        return dt
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
