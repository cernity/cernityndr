"""Server-owned promoter policy, following file-yara.registry.allow_actors.

Construct from trusted server configuration, never request roles or filters.
The actor passed by the service must come from its authenticated identity layer,
not a request-body actor field. There is no HTTP authentication adapter in U2.
"""
from collections.abc import Callable


class Unauthorized(PermissionError):
    """The authenticated actor is not a configured promoter."""


def allow_actors(*actors: str) -> Callable[[str], bool]:
    """Deny by default; snapshot the server's promoter identities."""
    allowed = frozenset(actors)
    return lambda actor: actor in allowed
