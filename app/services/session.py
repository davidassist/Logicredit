"""Session management service."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from fastapi import Response
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.models import Session as SessionModel
from app.models import User
from app.services import csrf

settings = get_settings()


async def create_session(
    db: AsyncSession,
    *,
    user: User,
    ip: str | None,
    user_agent: str | None,
    mfa_verified: bool,
) -> SessionModel:
    session = SessionModel(
        id=uuid.uuid4(),
        user=user,
        ip=ip,
        user_agent=user_agent,
        created_at=datetime.utcnow(),
        last_used_at=datetime.utcnow(),
        mfa_last_verified_at=datetime.utcnow() if mfa_verified else None,
    )
    if mfa_verified:
        user.last_mfa_at = datetime.utcnow()
    db.add(session)
    await db.flush()
    return session


def set_session_cookie(response: Response, session_id: uuid.UUID) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=str(session_id),
        max_age=settings.session_idle_timeout_seconds,
        httponly=True,
        secure=True,
        samesite="strict",
    )


async def attach_session_to_response(response: Response, session: SessionModel) -> str:
    set_session_cookie(response, session.id)
    csrf_token = await csrf.issue_csrf_token(str(session.id))
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=csrf_token,
        max_age=settings.csrf_token_ttl_seconds,
        httponly=False,
        secure=True,
        samesite="strict",
    )
    return csrf_token


async def get_session(db: AsyncSession, session_id: uuid.UUID) -> SessionModel | None:
    result = await db.execute(select(SessionModel).where(SessionModel.id == session_id))
    return result.scalar_one_or_none()


async def refresh_session(session: SessionModel) -> None:
    session.last_used_at = datetime.utcnow()


async def revoke_session(db: AsyncSession, session: SessionModel) -> None:
    await csrf.revoke_csrf_token(str(session.id))
    await db.delete(session)
    await db.flush()


async def revoke_other_sessions(db: AsyncSession, user: User, current_session_id: uuid.UUID | None = None) -> None:
    stmt = delete(SessionModel).where(SessionModel.user_id == user.id)
    if current_session_id:
        stmt = stmt.where(SessionModel.id != current_session_id)
    await db.execute(stmt)
    await db.flush()


async def revoke_all_sessions(db: AsyncSession, user: User) -> None:
    await revoke_other_sessions(db, user, current_session_id=None)


def session_expired(session: SessionModel) -> bool:
    now = datetime.utcnow()
    return (now - session.last_used_at) > timedelta(seconds=settings.session_idle_timeout_seconds)


async def issue_new_csrf(response: Response, session: SessionModel) -> str:
    csrf_token = await csrf.issue_csrf_token(str(session.id))
    response.set_cookie(
        key=settings.csrf_cookie_name,
        value=csrf_token,
        max_age=settings.csrf_token_ttl_seconds,
        httponly=False,
        secure=True,
        samesite="strict",
    )
    return csrf_token
