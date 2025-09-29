"""User schemas."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr

from app.models import UserRole


class UserRead(BaseModel):
    id: str
    email: EmailStr
    email_verified_at: datetime | None
    role: UserRole
    totp_enabled: bool
    name: str | None
    created_at: datetime

    class Config:
        orm_mode = True
