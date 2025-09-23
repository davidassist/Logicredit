"""Authentication schemas."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, EmailStr, Field

from app.models import UserRole


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=10)
    name: str | None = None


class RegisterResponse(BaseModel):
    ok: bool = True
    message: str = "verification_email_sent"


class VerifyEmailRequest(BaseModel):
    token: str


class GenericResponse(BaseModel):
    ok: bool = True


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    remember_me: bool | None = False


class LoginSuccessResponse(BaseModel):
    ok: bool = True
    csrf_token: str


class MFARequiredResponse(BaseModel):
    mfa_required: bool = True
    methods: list[Literal["totp", "webauthn"]]


class TOTPSetupResponse(BaseModel):
    provisioning_uri: str


class TOTPVerifyRequest(BaseModel):
    code: str
    email: EmailStr | None = None


class PasswordResetRequest(BaseModel):
    email: EmailStr


class PasswordResetConfirmRequest(BaseModel):
    token: str
    new_password: str = Field(min_length=10)


class SessionInfo(BaseModel):
    id: str
    created_at: datetime
    last_used_at: datetime
    ip: str | None
    user_agent: str | None
    mfa_last_verified_at: datetime | None


class SessionsResponse(BaseModel):
    sessions: list[SessionInfo]


class WebAuthnStartResponse(BaseModel):
    publicKey: dict[str, Any]


class WebAuthnFinishRequest(BaseModel):
    credential: dict[str, Any]


class WebAuthnLoginStartRequest(BaseModel):
    email: EmailStr


class WebAuthnLoginFinishRequest(BaseModel):
    email: EmailStr
    credential: dict[str, Any]


class CSRFTokenResponse(BaseModel):
    csrf_token: str


class RoleProtectedResponse(BaseModel):
    role: UserRole
    message: str
