"""Server-owned reader sessions. Never derive tenant or roles from a request."""
import math
import time


def authorize(sessions, header, now=None):
    token = header[7:] if header.startswith('Bearer ') else None
    session = sessions.get(token) if token else None
    if not isinstance(session, dict):
        raise PermissionError('unauthorized')
    tenant, expiry = session.get('tenant'), session.get('expires_at')
    if (not isinstance(tenant, str) or not tenant.strip()
            or type(expiry) not in (int, float) or not math.isfinite(expiry)
            or (time.time() if now is None else now) >= expiry):
        raise PermissionError('unauthorized')
    if session.get('investigation_read') is not True:
        raise PermissionError('forbidden')
    return tenant
