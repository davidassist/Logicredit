"""API dependencies."""
from __future__ import annotations

import uuid
from datetime import datetime

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db.session import get_db_session
from app.models import Session as SessionModel
from app.models import User, UserRole
from app.services import csrf as csrf_service
from app.services import session as session_service
from app.services.session import session_expired

settings = get_settings()


async def require_session(
    request: Request,
    db: AsyncSession = Depends(get_db_session),
) -> tuple[User, SessionModel]:
    cookie_value = request.cookies.get(settings.session_cookie_name)
    if not cookie_value:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="session_missing")
    try:
        session_id = uuid.UUID(cookie_value)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_session") from exc

    session = await session_service.get_session(db, session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="session_not_found")

    if session_expired(session):
        await session_service.revoke_session(db, session)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="session_expired")

    await session_service.refresh_session(session)
    await db.flush()
    user = session.user
    request.state.session = session
    request.state.user = user
    return user, session


async def require_csrf(request: Request) -> None:
    cookie_value = request.cookies.get(settings.session_cookie_name)
    header_value = request.headers.get("x-csrf-token")
    if not cookie_value:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="missing_session")
    if not await csrf_service.validate_csrf_token(cookie_value, header_value):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="invalid_csrf")


def require_role(required_role: UserRole):
    async def dependency(
        user_session: tuple[User, SessionModel] = Depends(require_session),
    ) -> User:
        user, _ = user_session
        role_order = [UserRole.USER.value, UserRole.STAFF.value, UserRole.ADMIN.value]
        if role_order.index(user.role) < role_order.index(required_role.value):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="insufficient_role")
        return user

    return dependency


async def require_recent_mfa(
    user_session: tuple[User, SessionModel] = Depends(require_session),
) -> User:
    user, session = user_session
    if not session.mfa_last_verified_at:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="mfa_required")
    if (datetime.utcnow() - session.mfa_last_verified_at).total_seconds() > settings.mfa_recent_timeout_seconds:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="mfa_stale")
    return user
