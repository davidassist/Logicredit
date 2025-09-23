"""Email verification token management."""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import security_manager
from app.models import EmailVerifyToken, User

settings = get_settings()


async def create_email_verification_token(db: AsyncSession, user: User) -> tuple[EmailVerifyToken, str]:
    token = security_manager.generate_email_token()
    token_hash = security_manager.hash_token(token)
    expires_at = datetime.utcnow() + timedelta(hours=settings.email_verification_token_ttl_hours)
    await db.execute(delete(EmailVerifyToken).where(EmailVerifyToken.user_id == user.id))
    record = EmailVerifyToken(token_hash=token_hash, user=user, expires_at=expires_at, created_at=datetime.utcnow())
    db.add(record)
    await db.flush()
    return record, token


async def verify_token(db: AsyncSession, token: str) -> User | None:
    token_hash = security_manager.hash_token(token)
    result = await db.execute(select(EmailVerifyToken).where(EmailVerifyToken.token_hash == token_hash))
    record = result.scalar_one_or_none()
    if not record:
        return None
    if record.expires_at < datetime.utcnow():
        return None
    user = record.user
    user.email_verified_at = datetime.utcnow()
    await db.delete(record)
    await db.flush()
    return user
