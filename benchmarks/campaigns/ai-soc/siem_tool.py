"""Read-only SIEM tool the investigator uses (§44.3). It is the ONLY evidence surface the
investigator is given, and it is bound to exactly ONE arm's exposed findings/alerts — it holds no
episode truth, no rubric, and no other arm's output. It is read-only by construction (no mutating
method exists) and it LOGS every query, so the evaluator can check that every cited record was
actually RETRIEVED (§57.3) — a citation the investigator never fetched is not supported evidence.

Isolation is enforced structurally, not by asking the investigator to behave: the runner hands the
investigator this object and nothing else, and this object can only reach `records` (one arm's
evidence). Field VALUES are returned verbatim, including any attacker-controlled text — the tool
never interprets a field as an instruction; that discipline is the investigator's, and §44.6 tests it.

The query budget is ENFORCED here at the gateway (§57.4), not audited after the fact: once the budget
is spent the tool refuses further reads (logged as `rejected: budget`) so an investigator cannot buy
extra evidence by ignoring the cap. `budget_exhausted` records that it happened."""
from __future__ import annotations


class BudgetExceeded(RuntimeError):
    pass


def _entity_values(rec):
    out = []
    for e in rec.get("entities") or []:
        if isinstance(e, dict) and e.get("value") is not None:
            out.append(str(e["value"]))
    return out


class ReadOnlySiemTool:
    SCHEMA_VERSION = "1"

    def __init__(self, arm: str, records: list[dict], budget: int | None = None):
        self.arm = arm
        # defensive copy; the investigator cannot mutate the backing evidence
        self._records = [dict(r) for r in records]
        self.query_log: list[dict] = []
        self.retrieved_ids: set[str] = set()      # ids the investigator actually surfaced (§57.3)
        self.budget = budget                       # None = unbounded (evaluator's verification tool)
        self.budget_exhausted = False

    def _spend(self) -> bool:
        if self.budget is None:
            return True
        if len(self.query_log) >= self.budget:
            self.budget_exhausted = True
            return False
        return True

    # --- the investigator-facing surface (read-only) ---------------------------------------------
    def search(self, entity: str | None = None, category: str | None = None,
               min_severity: int | None = None) -> list[dict]:
        """Return findings matching the filters. Every call is logged and counts against the budget;
        an over-budget call is refused (empty result, logged rejection). Records are returned as
        shallow copies so the investigator cannot alter shared evidence."""
        if not self._spend():
            self.query_log.append({"op": "search", "rejected": "budget"})
            return []
        hits = []
        for r in self._records:
            if entity is not None and entity not in _entity_values(r):
                continue
            if category is not None and r.get("category") != category:
                continue
            if min_severity is not None and int(r.get("severity", 0) or 0) < min_severity:
                continue
            hits.append(dict(r))
        for h in hits:
            if h.get("finding_id") is not None:
                self.retrieved_ids.add(h["finding_id"])
        self.query_log.append({"op": "search", "entity": entity, "category": category,
                               "min_severity": min_severity, "hits": [h.get("finding_id") for h in hits]})
        return hits

    def get(self, finding_id: str) -> dict | None:
        """Fetch one record by id (for citing/quoting). Logged, budget-counted. None if it does not
        exist — an investigator that cites a non-existent id will get None here and the evaluator will
        catch the fabricated citation."""
        if not self._spend():
            self.query_log.append({"op": "get", "finding_id": finding_id, "rejected": "budget"})
            return None
        rec = next((dict(r) for r in self._records if r.get("finding_id") == finding_id), None)
        if rec is not None:
            self.retrieved_ids.add(finding_id)
        self.query_log.append({"op": "get", "finding_id": finding_id, "found": rec is not None})
        return rec

    def exists(self, finding_id: str) -> bool:
        return any(r.get("finding_id") == finding_id for r in self._records)
