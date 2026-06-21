"""POST /auth/token — demo token endpoint (dev/testing only).

Issues signed JWTs for hardcoded demo users so the OAuth2 password flow works
without an external IdP. In production this endpoint is replaced by an external
identity provider (Okta, Auth0, etc.); the JWT format and ``require_role``
dependency remain unchanged.

The ``tokenUrl="/auth/token"`` in ``OAuth2PasswordBearer`` points here.
"""
from __future__ import annotations

import structlog
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from src.core.schema import Role
from src.security.rbac import create_access_token

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Demo user store — never use in production.
_DEMO_USERS: dict[str, dict] = {
    "analyst":  {"password": "analyst",  "role": Role.ANALYST},
    "engineer": {"password": "engineer", "role": Role.ENGINEER},
    "admin":    {"password": "admin",    "role": Role.ADMIN},
}


@router.post("/token")
async def get_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> dict[str, str]:
    """Issue a signed JWT for a demo user.

    Accepts OAuth2 password-flow form fields (``username``, ``password``).
    Returns ``{"access_token": "...", "token_type": "bearer"}``.
    """
    user = _DEMO_USERS.get(form_data.username)
    if not user or user["password"] != form_data.password:
        logger.warning("auth_failed", username=form_data.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(form_data.username, user["role"])
    logger.info("token_issued", username=form_data.username, role=user["role"].value)
    return {"access_token": token, "token_type": "bearer"}
