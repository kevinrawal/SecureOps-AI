"""RBAC: Role hierarchy, JWT decode, FastAPI dependency, graph-level enforcement.

Two enforcement points (design principle #4):
  API level  — ``require_role(minimum_role)`` FastAPI dependency injected into
               route handlers. Rejects requests with a 403 before they touch the graph.
  Graph level — ``assert_graph_role(state, minimum_role)`` called at the start of
               privileged nodes (e.g. human_review is ANALYST+). Raises PermissionError
               on violation so the graph terminates cleanly.

JWT tokens are HS256-signed with ``settings.JWT_SECRET_KEY``. The payload must
carry ``sub`` (user_id) and ``role`` (Role enum value).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import structlog
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt

from src.core.config import settings
from src.core.schema import Role, ThreatState

logger = structlog.get_logger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=True)

# Privilege levels — higher value = more privilege.
ROLE_HIERARCHY: dict[Role, int] = {
    Role.ANALYST: 1,
    Role.ENGINEER: 2,
    Role.ADMIN: 3,
}


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def create_access_token(user_id: str, role: Role) -> str:
    """Sign and return a JWT access token for ``user_id`` with ``role``."""
    payload: dict[str, Any] = {
        "sub": user_id,
        "role": role.value,
        "iat": datetime.now(timezone.utc).timestamp(),
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_jwt_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT token; raise HTTPException 401 on failure.

    Returns the decoded payload dict including ``sub`` and ``role``.
    """
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        if "sub" not in payload or "role" not in payload:
            raise JWTError("Missing required claims")
        return payload
    except JWTError as exc:
        logger.warning("jwt_decode_failed", error=str(exc))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ---------------------------------------------------------------------------
# FastAPI API-level dependency
# ---------------------------------------------------------------------------

def require_role(minimum_role: Role):
    """Return a FastAPI dependency that enforces ``minimum_role``.

    Usage::

        @router.post("/threats/approve")
        async def approve(payload=Depends(require_role(Role.ENGINEER))):
            user_id = payload["sub"]
    """
    async def _dependency(token: str = Depends(oauth2_scheme)) -> dict[str, Any]:
        payload = decode_jwt_token(token)
        try:
            user_role = Role(payload["role"])
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Unknown role in token: {payload.get('role')}",
            ) from exc

        if ROLE_HIERARCHY[user_role] < ROLE_HIERARCHY[minimum_role]:
            logger.warning(
                "rbac_denied",
                user_id=payload.get("sub"),
                user_role=user_role.value,
                required_role=minimum_role.value,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{user_role.value}' insufficient; requires '{minimum_role.value}'",
            )

        logger.debug(
            "rbac_granted",
            user_id=payload.get("sub"),
            user_role=user_role.value,
        )
        return payload

    return _dependency


# ---------------------------------------------------------------------------
# Graph-level enforcement
# ---------------------------------------------------------------------------

def assert_graph_role(state: ThreatState, minimum_role: Role) -> None:
    """Raise PermissionError if the state's role is below ``minimum_role``.

    Called at the start of privileged graph nodes. Uses the ``role`` field
    carried in ThreatState (set during graph invocation from the JWT payload).
    """
    role_str: str = state.get("role", Role.ANALYST.value)
    try:
        user_role = Role(role_str)
    except ValueError:
        raise PermissionError(f"Unknown role in graph state: {role_str!r}")

    if ROLE_HIERARCHY[user_role] < ROLE_HIERARCHY[minimum_role]:
        raise PermissionError(
            f"Graph role '{user_role.value}' insufficient; "
            f"node requires '{minimum_role.value}'"
        )
