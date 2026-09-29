"""One bounded evidence page per invocation, with durable, retryable checkpoints."""
import copy
import hashlib
import importlib.util
import ipaddress
import json
from datetime import timedelta
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


query = load_module("hunt_evidence_query", ROOT / "services/evidence-service/query.py")
lifecycle = load_module("hunt_lifecycle", ROOT / "services/threat-intel/lifecycle.py")
ti = load_module("hunt_dimensions", ROOT / "services/threat-intel/ti.py")
validator = Draft202012Validator(json.loads((ROOT / "contracts/hunt.schema.json").read_text()),
                                 format_checker=FormatChecker())
SUPPORTED = {"ip", "domain", "ja3", "ja4", "cert"}


class EvidenceClient:
    def __init__(self, clickhouse):
        self.clickhouse = clickhouse

    def page(self, tenant, frm, to, page_size, after):
        return query.fetch_hunt_page(self.clickhouse, tenant, frm, to, page_size, after)


def saved_indicators(records, tenant):
    """Snapshot U1 records, using local acquisition provenance, never first_seen.

    Feed first_seen may predate acquisition. U1 refresh replaces provenance, so
    this timestamp is the earliest acquisition retained in the supplied snapshot.
    """
    if not isinstance(records, list) or not 1 <= len(records) <= 100:
        raise ValueError("saved intel set must contain 1..100 records")
    out = []
    for record in records:
        if record.get("tenant") != tenant:
            raise ValueError("saved intel set tenant mismatch")
        dates = [p["observed_at"] for p in record.get("provenance", []) if p.get("observed_at")]
        if not dates:
            raise ValueError("saved intel lacks acquisition timestamp (provenance.observed_at)")
        out.append({"type": record["type"], "indicator": record["indicator"],
                    "intel_known_at": min(dates, key=query._parse_ts)})
    return out


def prepare(job, tenant, saved_sets):
    validator.validate(job)
    if job["tenant"] != tenant:
        raise PermissionError("hunt tenant mismatch")
    frm, to = query.parse_window(job["from"], job["to"])
    if to - frm > timedelta(days=31):
        raise ValueError("hunt window must not exceed 31 days")
    indicators = copy.deepcopy(job.get("indicators"))
    if indicators is None:
        records = saved_sets.get(tenant, {}).get(job["intel_set"])
        if records is None:
            raise ValueError("saved intel set not found")
        indicators = saved_indicators(records, tenant)
    # Validate resolved snapshots using the same contract as explicit indicators.
    resolved = {k: v for k, v in job.items() if k != "intel_set"}
    resolved["indicators"] = indicators
    validator.validate(resolved)
    for ind in indicators:
        query._parse_ts(ind["intel_known_at"])
        ind["indicator"] = lifecycle.norm_indicator(ind["type"], ind["indicator"])
        if not ind["indicator"]:
            raise ValueError("empty indicator")
        if ind["type"] == "ip":
            ipaddress.ip_network(ind["indicator"], strict=False)
    return indicators


def matches(ind, kind, value):
    if ind["type"] != kind:
        return False
    if kind == "ip":
        try:
            return ipaddress.ip_address(value) in ipaddress.ip_network(ind["indicator"], strict=False)
        except ValueError:
            return False
    return lifecycle.norm_indicator(kind, value) == ind["indicator"]


class HuntWorker:
    def __init__(self, evidence, store, saved_sets=None):
        self.evidence, self.store = evidence, store
        self.saved_sets = saved_sets or {}

    def step(self, job, tenant):
        validator.validate(job)
        if job["tenant"] != tenant:
            raise PermissionError("hunt tenant mismatch")
        # Serialize a single worker's progress. SQLite persists both snapshots and
        # checkpoints; failed evidence reads leave the last checkpoint unchanged.
        with self.store.lock:
            previous = self.store.load(tenant, job["hunt_id"])
            if previous:
                original, state = previous
                if original != job:
                    raise ValueError("hunt_id already belongs to a different request")
            else:
                indicators = prepare(job, tenant, self.saved_sets)
                unsupported = [{**i, "status": "dimension not yet supported"}
                               for i in indicators if i["type"] not in SUPPORTED]
                state = {"status": "pending", "from": job["from"], "after": "",
                         "indicators": [i for i in indicators if i["type"] in SUPPORTED],
                         "unsupported": unsupported}
                self.store.save(tenant, job["hunt_id"], job, state)
            if state["status"] == "complete":
                return self.store.results(tenant, job["hunt_id"])
            hits = []
            if state["indicators"]:
                page = self.evidence.page(tenant, state["from"], job["to"],
                                          job.get("page_size", 500), state["after"])
                frm, to = query.parse_window(job["from"], job["to"])
                for obs in page["observations"]:
                    if obs["tenant"] != tenant:
                        raise ValueError("evidence tenant mismatch")
                    if not frm <= query._parse_ts(obs["ts"]["normalized"]) < to:
                        raise ValueError("evidence outside hunt window")
                    if obs["type"] not in query.OBS_TYPES:
                        continue
                    for ind in state["indicators"]:
                        fields = sorted({field for kind, field, value in ti.dimensions(obs["fields"])
                                         if kind in SUPPORTED and matches(ind, kind, value)})
                        if not fields:
                            continue
                        identity = [tenant, job["hunt_id"], obs["obs_id"], ind]
                        observed = obs["ts"]["sensor"]
                        hits.append({"hit_id": hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest(),
                                     "tenant": tenant, "obs_id": obs["obs_id"], **ind,
                                     "observed_at": observed, "observation_ts": obs["ts"],
                                     "source_ref": obs["source_ref"], "matched_fields": fields,
                                     "learned_after_observation": query._parse_ts(ind["intel_known_at"]) > query._parse_ts(observed)})
                nxt = page.get("next")
                if nxt is not None:
                    cursor = (query._parse_ts(nxt), page.get("next_after", ""))
                    if not (query._parse_ts(state["from"]), state["after"]) < cursor < (to, ""):
                        raise ValueError("evidence cursor did not advance within window")
                    state["from"], state["after"] = nxt, cursor[1]
                else:
                    state["status"] = "complete"
            else:
                state["status"] = "complete"
            self.store.save(tenant, job["hunt_id"], job, state, hits)
            return self.store.results(tenant, job["hunt_id"])
