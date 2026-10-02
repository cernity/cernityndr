"""Registry-only lifecycle (025 U2), over the existing U1 store.

Uses file-yara.registry's staged promotion/authorizer pattern and finding-service's
explicit transition-table check. U2 is forward-only (unlike YARA's demotion).
No sensor delivery, bundle generation, or entity scope belongs in this layer.
The store remains trusted internal CRUD; external status changes must use promote.
Like the U1 store this facade requires one writer, not concurrent request threads.
"""
from collections.abc import Callable
from datetime import datetime, timezone

from authz import Unauthorized, allow_actors
from store import RegistryStore


TRANSITIONS = {
    "draft": frozenset({"shadow", "retired"}),
    "shadow": frozenset({"active", "retired"}),
    "active": frozenset({"retired"}),
    "retired": frozenset(),
}


class IllegalTransition(ValueError):
    """An unlisted status move, including a no-op, is forbidden."""


class RegistryLifecycle:
    def __init__(self, store: RegistryStore, authorize: Callable[[str], bool] | None = None):
        # Policy is bound by server composition, never supplied per request.
        self._store = store
        self._authorize = authorize if authorize is not None else allow_actors()

    def promote(self, detection_id: str, to_status: str, actor: str) -> dict:
        """Change state and append attribution using an authenticated server actor.

        Every move, including retirement, requires promoter authorization. Denied
        attempts leave the entry unchanged; change_history records actual changes.
        """
        if not isinstance(actor, str) or not actor.strip() or len(actor) > 256:
            raise Unauthorized("a valid authenticated actor is required")
        if not self._authorize(actor):
            raise Unauthorized(f"{actor!r} is not authorized to change registry state")
        entry = self._store.get(detection_id)
        if entry is None:
            raise KeyError(detection_id)
        current = entry["status"]
        if to_status not in TRANSITIONS.get(current, frozenset()):
            raise IllegalTransition(f"illegal transition {current!r} -> {to_status!r}")
        entry["status"] = to_status
        entry["change_history"].append({
            "ts": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "actor": actor,
            "from": current,
            "to": to_status,
        })
        return self._store.update(entry)
