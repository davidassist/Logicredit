"""Audit logging service."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AuditLog, User


async def log_audit_event(
    db: AsyncSession,
    *,
    event_type: str,
    user: User | None,
    ip: str | None,
    user_agent: str | None,
    meta: dict[str, Any] | None = None,
) -> None:
    audit = AuditLog(
        user=user,
        type=event_type,
        ip=ip,
        user_agent=user_agent,
        created_at=datetime.utcnow(),
        meta=meta or {},
    )
    db.add(audit)
    await db.flush()
