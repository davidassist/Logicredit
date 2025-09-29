"""TOTP service."""
from __future__ import annotations

from datetime import datetime

import pyotp
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import SecurityManager, security_manager
from app.models import TOTPSecret, User


async def ensure_totp_secret(db: AsyncSession, user: User, manager: SecurityManager = security_manager) -> tuple[TOTPSecret, str]:
    if user.totp_secret:
        secret = manager.decrypt_secret(user.totp_secret.secret_encrypted)
        return user.totp_secret, secret
    secret_raw = manager.generate_totp_secret()
    encrypted = manager.encrypt_secret(secret_raw)
    totp_secret = TOTPSecret(user=user, secret_encrypted=encrypted, created_at=datetime.utcnow())
    db.add(totp_secret)
    await db.flush()
    return totp_secret, secret_raw


async def verify_totp(db: AsyncSession, user: User, code: str, manager: SecurityManager = security_manager) -> bool:
    if not user.totp_secret:
        return False
    secret = manager.decrypt_secret(user.totp_secret.secret_encrypted)
    totp = pyotp.TOTP(secret)
    if totp.verify(code, valid_window=1):
        user.totp_enabled = True
        user.last_mfa_at = datetime.utcnow()
        await db.flush()
        return True
    return False
