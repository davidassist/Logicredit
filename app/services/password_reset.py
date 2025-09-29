"""Password reset token service."""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import security_manager
from app.models import PasswordResetToken, User

settings = get_settings()


async def create_password_reset_token(db: AsyncSession, user: User) -> PasswordResetToken:
    token = security_manager.generate_email_token()
    token_hash = security_manager.hash_token(token)
    expires_at = datetime.utcnow() + timedelta(minutes=settings.password_reset_token_ttl_minutes)
    record = PasswordResetToken(
        token_hash=token_hash,
        user=user,
        expires_at=expires_at,
        created_at=datetime.utcnow(),
    )
    db.add(record)
    await db.flush()
    record.plain_token = token  # type: ignore[attr-defined]
    return record


async def fetch_valid_token(db: AsyncSession, token: str) -> PasswordResetToken | None:
    token_hash = security_manager.hash_token(token)
    result = await db.execute(select(PasswordResetToken).where(PasswordResetToken.token_hash == token_hash))
    record = result.scalar_one_or_none()
    if not record:
        return None
    if record.used_at is not None or record.expires_at < datetime.utcnow():
        return None
    return record


async def mark_token_used(db: AsyncSession, record: PasswordResetToken) -> None:
    record.used_at = datetime.utcnow()
    await db.flush()
