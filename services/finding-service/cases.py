"""Multi-analyst case model (plan U7; Addendum A6).

A case (case.v1) links findings/entities under one owner with a status lifecycle
and an append-only audit trail. This module is PURE: it builds and mutates case
dicts and appends audit events; SQLite persistence lives in store.py (CaseStore),
the status transition table in state_machine.py. Same split as state_machine.py
(logic) vs the I/O shell.

Two rules the callers rely on:
  * Every ownership / assignment / status / note / link change appends exactly one
    audit event and bumps `updated`. No mutation is silent.
  * A case resolution (resolved/closed) is a *disposition input* to the Inc-1
    feedback loop (disposition.v1), advisory only — case_dispositions() shapes
    those records; nothing here auto-suppresses (that stays the analyst's call,
    matching feedback-service's advisory contract).
"""
from __future__ import annotations

from state_machine import valid_case_transition

# The disposition.v1 verdicts the feedback loop accepts (contracts/disposition.schema.json).
# `allowlist` is special: the schema requires it to carry scope='entity' (it suppresses an
# entity, not a single finding); every other verdict is finding-scope.
_DISPOSITION_VERDICTS = {"true_positive", "false_positive", "benign", "allowlist"}


def _audit(event: str, actor: str, ts: str, **detail) -> dict:
    ev = {"event": event, "actor": actor, "ts": ts}
    if detail:
        ev["detail"] = detail
    return ev


def _touch(case: dict, event: dict) -> dict:
    """Return a copy of `case` with one audit event appended and `updated` bumped
    to that event's ts. Mutating a copy (not in place) keeps callers that hold the
    prior version — e.g. an optimistic read — uncorrupted."""
    c = dict(case)
    c["audit"] = list(case.get("audit", [])) + [event]
    c["updated"] = event["ts"]
    return c


def new_case(case_id: str, tenant: str, title: str, owner, actor: str, ts: str) -> dict:
    """A fresh case in status `new`, owned by `owner` (may be None = unowned),
    with a single `created` audit event. `actor` is who created it (audit), which
    is usually but not necessarily the owner."""
    return {
        "case_id": case_id,
        "tenant": tenant,
        "title": title,
        "owner": owner,
        "assignees": [],
        "status": "new",
        "notes": [],
        "linked_findings": [],
        "linked_entities": [],
        "created": ts,
        "updated": ts,
        "audit": [_audit("created", actor, ts, owner=owner, title=title)],
    }


def change_owner(case: dict, owner, actor: str, ts: str) -> dict:
    """Reassign case ownership (owner may be None to unassign)."""
    c = _touch(case, _audit("owner_changed", actor, ts,
                            **{"from": case.get("owner"), "to": owner}))
    c["owner"] = owner
    return c


def assign(case: dict, assignee: str, actor: str, ts: str) -> dict:
    """Add a working analyst. Idempotent: assigning someone already on the case is
    a no-op with no audit event (nothing changed)."""
    if assignee in case.get("assignees", []):
        return dict(case)
    c = _touch(case, _audit("assignee_added", actor, ts, assignee=assignee))
    c["assignees"] = list(case.get("assignees", [])) + [assignee]
    return c


def unassign(case: dict, assignee: str, actor: str, ts: str) -> dict:
    """Remove a working analyst. No-op (no audit) if they were not assigned."""
    if assignee not in case.get("assignees", []):
        return dict(case)
    c = _touch(case, _audit("assignee_removed", actor, ts, assignee=assignee))
    c["assignees"] = [a for a in case["assignees"] if a != assignee]
    return c


def add_note(case: dict, author: str, text: str, ts: str) -> dict:
    """Append an analyst note (and its own note_added audit event)."""
    note = {"author": author, "text": text, "ts": ts}
    c = _touch(case, _audit("note_added", author, ts))
    c["notes"] = list(case.get("notes", [])) + [note]
    return c


def transition(case: dict, status: str, actor: str, ts: str) -> dict:
    """Move the case to `status`, validated against state_machine.CASE_TRANSITIONS.
    Raises ValueError on an illegal move (e.g. new -> resolved) so an invalid
    transition can never reach the store or the audit trail."""
    current = case.get("status")
    if not valid_case_transition(current, status):
        raise ValueError(f"illegal case transition {current!r} -> {status!r}")
    c = _touch(case, _audit("status_changed", actor, ts,
                            **{"from": current, "to": status}))
    c["status"] = status
    return c


def link_finding(case: dict, finding_id: str, actor: str, ts: str) -> dict:
    """Attach a finding. Idempotent: relinking an already-linked finding is a no-op."""
    if finding_id in case.get("linked_findings", []):
        return dict(case)
    c = _touch(case, _audit("finding_linked", actor, ts, finding_id=finding_id))
    c["linked_findings"] = list(case.get("linked_findings", [])) + [finding_id]
    return c


def unlink_finding(case: dict, finding_id: str, actor: str, ts: str) -> dict:
    if finding_id not in case.get("linked_findings", []):
        return dict(case)
    c = _touch(case, _audit("finding_unlinked", actor, ts, finding_id=finding_id))
    c["linked_findings"] = [f for f in case["linked_findings"] if f != finding_id]
    return c


def link_entity(case: dict, entity: dict, actor: str, ts: str) -> dict:
    """Attach a typed entity ({type, value}). Idempotent on an identical entity."""
    if entity in case.get("linked_entities", []):
        return dict(case)
    c = _touch(case, _audit("entity_linked", actor, ts, entity=entity))
    c["linked_entities"] = list(case.get("linked_entities", [])) + [entity]
    return c


def unlink_entity(case: dict, entity: dict, actor: str, ts: str) -> dict:
    if entity not in case.get("linked_entities", []):
        return dict(case)
    c = _touch(case, _audit("entity_unlinked", actor, ts, entity=entity))
    c["linked_entities"] = [e for e in case["linked_entities"] if e != entity]
    return c


def case_dispositions(case: dict, verdicts: list[dict]) -> list[dict]:
    """Shape EXPLICIT per-finding analyst verdicts on a resolved/closed case into
    disposition.v1 records for the Inc-1 feedback loop (advisory — feedback-service
    never auto-suppresses).

    `verdicts` is a list of {finding_id, entity, verdict, reason, analyst, ts}: the
    analyst's own call on ONE finding attributed to ONE entity. No verdict is
    inferred, and no finding is auto-paired to an arbitrary entity — the caller
    states the finding->entity attribution and it is VERIFIED here: the referenced
    finding and entity must both be linked to the case, else ValueError (a
    misattributed verdict is rejected, never silently emitted to the loop).

    A verdict outside the disposition.v1 set is rejected (ValueError) before any record
    is shaped, so an unsupported verdict can never reach the outbox. An `allowlist`
    verdict is emitted at scope='entity' (the schema requires it — it suppresses the
    entity, not one finding); every other verdict is finding-scope.

    Returns [] when the case is not in a resolution state (resolved/closed) — a
    resolution verdict needs a resolved case — or when no verdicts are supplied.
    """
    if case.get("status") not in ("resolved", "closed"):
        return []
    linked_findings = set(case.get("linked_findings") or [])
    linked_entities = case.get("linked_entities") or []
    records = []
    for v in verdicts:
        fid, entity, verdict = v["finding_id"], v["entity"], v["verdict"]
        if verdict not in _DISPOSITION_VERDICTS:
            raise ValueError(f"unsupported disposition verdict {verdict!r}")
        if fid not in linked_findings:
            raise ValueError(
                f"verdict finding {fid!r} not linked to case {case.get('case_id')!r}")
        if entity not in linked_entities:
            raise ValueError(
                f"verdict entity {entity!r} not linked to case {case.get('case_id')!r}")
        records.append({
            "finding_id": fid,
            "entity": entity,
            "verdict": verdict,
            "reason": v["reason"],
            "analyst": v["analyst"],
            "tenant": case["tenant"],
            "ts": v["ts"],
            # allowlist suppresses an entity, not a finding: the schema mandates
            # scope='entity' for it. All other verdicts stay finding-scope.
            "scope": "entity" if verdict == "allowlist" else "finding",
        })
    return records
