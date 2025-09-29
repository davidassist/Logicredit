"""Authentication API routes."""
from __future__ import annotations

from datetime import datetime, timedelta

import pyotp
from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import require_csrf, require_recent_mfa, require_role, require_session
from app.core.config import get_settings
from app.core.email import get_email_service
from app.core.security import PasswordValidationError, security_manager
from app.db.session import get_db_session
from app.models import Session as SessionModel
from app.models import User, UserRole
from app.schemas import (
    CSRFTokenResponse,
    GenericResponse,
    LoginRequest,
    LoginSuccessResponse,
    MFARequiredResponse,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    RegisterRequest,
    RegisterResponse,
    RoleProtectedResponse,
    SessionInfo,
    SessionsResponse,
    TOTPSetupResponse,
    TOTPVerifyRequest,
    UserRead,
    VerifyEmailRequest,
    WebAuthnFinishRequest,
    WebAuthnLoginFinishRequest,
    WebAuthnLoginStartRequest,
    WebAuthnStartResponse,
)
from app.services import email_verification, password_reset, session as session_service, totp, webauthn
from app.services.audit import log_audit_event
from app.utils.request import get_client_ip, get_user_agent
from app.core.rate_limit import limiter

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


def _mfa_methods(user: User) -> list[str]:
    methods: list[str] = []
    if user.totp_enabled or user.totp_secret is not None:
        methods.append("totp")
    if user.webauthn_credentials:
        methods.append("webauthn")
    return methods


async def _record_login_failure(db: AsyncSession, user: User | None, request: Request) -> None:
    if user:
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= settings.brute_force_max_attempts:
            user.lockout_until = datetime.utcnow() + timedelta(minutes=settings.brute_force_lockout_minutes)
        await log_audit_event(
            db,
            event_type="login_failed",
            user=user,
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            meta={"attempts": user.failed_login_attempts},
        )
        await db.flush()
        security_manager.delay_for_failed_login(user.failed_login_attempts)
    else:
        security_manager.delay_for_failed_login(1)


def _reset_login_attempts(user: User) -> None:
    user.failed_login_attempts = 0
    user.lockout_until = None


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(settings.rate_limit_per_ip)
async def register(
    request: Request,
    payload: RegisterRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
) -> RegisterResponse:
    email = payload.email.lower()
    existing = await db.execute(select(User).where(User.email == email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="email_exists")
    try:
        password_hash = security_manager.hash_password(payload.password)
    except PasswordValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    user = User(email=email, password_hash=password_hash, name=payload.name)
    db.add(user)
    await db.flush()
    _, token = await email_verification.create_email_verification_token(db, user)
    verify_link = f"{settings.origin_url}/auth/verify-email?token={token}"
    email_service = get_email_service()
    background_tasks.add_task(
        email_service.send_email,
        subject="Verify your email",
        recipient=user.email,
        body=f"Welcome! Please verify your email by visiting {verify_link}",
    )
    await log_audit_event(
        db,
        event_type="register",
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        meta={"email": user.email},
    )
    await db.commit()
    return RegisterResponse()


@router.post("/verify-email", response_model=GenericResponse)
@limiter.limit(settings.rate_limit_per_ip)
async def verify_email(
    request: Request,
    payload: VerifyEmailRequest,
    db: AsyncSession = Depends(get_db_session),
) -> GenericResponse:
    user = await email_verification.verify_token(db, payload.token)
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_or_expired_token")
    await log_audit_event(
        db,
        event_type="email_verified",
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        meta={},
    )
    await db.commit()
    return GenericResponse()


@router.post("/login", response_model=LoginSuccessResponse | MFARequiredResponse)
@limiter.limit(settings.rate_limit_per_ip)
async def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
    db: AsyncSession = Depends(get_db_session),
) -> LoginSuccessResponse | MFARequiredResponse:
    email = payload.email.lower()
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        security_manager.delay_for_failed_login(1)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials")

    if user.lockout_until and user.lockout_until > datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="account_locked")

    if not security_manager.verify_password(payload.password, user.password_hash):
        await _record_login_failure(db, user, request)
        await db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid_credentials")

    _reset_login_attempts(user)
    await db.flush()

    methods = _mfa_methods(user)
    if methods:
        await log_audit_event(
            db,
            event_type="login_mfa_required",
            user=user,
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            meta={"methods": methods},
        )
        await db.commit()
        return MFARequiredResponse(methods=methods)

    session = await session_service.create_session(
        db,
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        mfa_verified=False,
    )
    csrf_token = await session_service.attach_session_to_response(response, session)
    await log_audit_event(
        db,
        event_type="login_success",
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        meta={"session_id": str(session.id)},
    )
    await db.commit()
    return LoginSuccessResponse(csrf_token=csrf_token)


@router.get("/me", response_model=UserRead)
async def me(user_session: tuple[User, SessionModel] = Depends(require_session)) -> UserRead:
    user, _ = user_session
    return UserRead.from_orm(user)


@router.get("/csrf", response_model=CSRFTokenResponse)
async def get_csrf_token(
    response: Response,
    user_session: tuple[User, SessionModel] = Depends(require_session),
) -> CSRFTokenResponse:
    _, session = user_session
    csrf_token = await session_service.issue_new_csrf(response, session)
    return CSRFTokenResponse(csrf_token=csrf_token)


@router.post("/mfa/totp/setup", response_model=TOTPSetupResponse, dependencies=[Depends(require_csrf)])
async def totp_setup(
    request: Request,
    user_session: tuple[User, SessionModel] = Depends(require_session),
    db: AsyncSession = Depends(get_db_session),
) -> TOTPSetupResponse:
    user, _ = user_session
    secret_record, secret = await totp.ensure_totp_secret(db, user)
    totp_obj = pyotp.TOTP(secret)
    provisioning_uri = totp_obj.provisioning_uri(name=user.email, issuer_name=settings.app_name)
    await log_audit_event(
        db,
        event_type="totp_setup",
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        meta={"secret_id": str(secret_record.user_id)},
    )
    await db.commit()
    return TOTPSetupResponse(provisioning_uri=provisioning_uri)


@router.post("/mfa/totp/verify", response_model=LoginSuccessResponse)
@limiter.limit(settings.rate_limit_per_ip)
async def totp_verify(
    request: Request,
    response: Response,
    payload: TOTPVerifyRequest,
    db: AsyncSession = Depends(get_db_session),
) -> LoginSuccessResponse:
    cookie_value = request.cookies.get(settings.session_cookie_name)
    if cookie_value:
        await require_csrf(request)
        user, session = await require_session(request=request, db=db)
        if not await totp.verify_totp(db, user, payload.code):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_totp")
        session.mfa_last_verified_at = datetime.utcnow()
        csrf_token = await session_service.issue_new_csrf(response, session)
        await log_audit_event(
            db,
            event_type="totp_verified",
            user=user,
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            meta={"context": "session_upgrade"},
        )
        await db.commit()
        return LoginSuccessResponse(csrf_token=csrf_token)

    if not payload.email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="email_required")
    result = await db.execute(select(User).where(User.email == payload.email.lower()))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user_not_found")
    if not await totp.verify_totp(db, user, payload.code):
        await log_audit_event(
            db,
            event_type="totp_failed",
            user=user,
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            meta={},
        )
        await db.commit()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_totp")

    _reset_login_attempts(user)
    await db.flush()
    session = await session_service.create_session(
        db,
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        mfa_verified=True,
    )
    csrf_token = await session_service.attach_session_to_response(response, session)
    await log_audit_event(
        db,
        event_type="login_success",
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        meta={"session_id": str(session.id), "method": "totp"},
    )
    await db.commit()
    return LoginSuccessResponse(csrf_token=csrf_token)


@router.post("/webauthn/register/start", response_model=WebAuthnStartResponse, dependencies=[Depends(require_csrf)])
async def webauthn_register_start(
    user_session: tuple[User, SessionModel] = Depends(require_session),
    db: AsyncSession = Depends(get_db_session),
) -> WebAuthnStartResponse:
    user, _ = user_session
    options = await webauthn.begin_registration(db, user)
    return WebAuthnStartResponse(publicKey=options)


@router.post("/webauthn/register/finish", response_model=GenericResponse, dependencies=[Depends(require_csrf)])
async def webauthn_register_finish(
    request: Request,
    payload: WebAuthnFinishRequest,
    user_session: tuple[User, SessionModel] = Depends(require_session),
    db: AsyncSession = Depends(get_db_session),
) -> GenericResponse:
    user, session = user_session
    await webauthn.complete_registration(db, user, payload.credential)
    session.mfa_last_verified_at = datetime.utcnow()
    await log_audit_event(
        db,
        event_type="webauthn_registered",
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        meta={},
    )
    await db.commit()
    return GenericResponse()


@router.post("/webauthn/login/start", response_model=WebAuthnStartResponse)
@limiter.limit(settings.rate_limit_per_ip)
async def webauthn_login_start(
    payload: WebAuthnLoginStartRequest,
    db: AsyncSession = Depends(get_db_session),
) -> WebAuthnStartResponse:
    result = await db.execute(select(User).where(User.email == payload.email.lower()))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user_not_found")
    options = await webauthn.begin_authentication(user)
    return WebAuthnStartResponse(publicKey=options)


@router.post("/webauthn/login/finish", response_model=LoginSuccessResponse)
@limiter.limit(settings.rate_limit_per_ip)
async def webauthn_login_finish(
    request: Request,
    response: Response,
    payload: WebAuthnLoginFinishRequest,
    db: AsyncSession = Depends(get_db_session),
) -> LoginSuccessResponse:
    result = await db.execute(select(User).where(User.email == payload.email.lower()))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="user_not_found")
    try:
        await webauthn.complete_authentication(db, user, payload.credential)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_webauthn") from exc
    _reset_login_attempts(user)
    await db.flush()
    session = await session_service.create_session(
        db,
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        mfa_verified=True,
    )
    csrf_token = await session_service.attach_session_to_response(response, session)
    await log_audit_event(
        db,
        event_type="login_success",
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        meta={"session_id": str(session.id), "method": "webauthn"},
    )
    await db.commit()
    return LoginSuccessResponse(csrf_token=csrf_token)


@router.post("/password/reset/request", response_model=GenericResponse)
@limiter.limit(settings.rate_limit_per_ip)
async def password_reset_request(
    request: Request,
    payload: PasswordResetRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
) -> GenericResponse:
    result = await db.execute(select(User).where(User.email == payload.email.lower()))
    user = result.scalar_one_or_none()
    if user:
        token_record = await password_reset.create_password_reset_token(db, user)
        token = token_record.plain_token  # type: ignore[attr-defined]
        reset_link = f"{settings.origin_url}/auth/password/reset/confirm?token={token}"
        email_service = get_email_service()
        background_tasks.add_task(
            email_service.send_email,
            subject="Password reset request",
            recipient=user.email,
            body=f"Reset your password using {reset_link}",
        )
        await log_audit_event(
            db,
            event_type="password_reset_requested",
            user=user,
            ip=get_client_ip(request),
            user_agent=get_user_agent(request),
            meta={},
        )
    await db.commit()
    return GenericResponse()


@router.post("/password/reset/confirm", response_model=GenericResponse)
@limiter.limit(settings.rate_limit_per_ip)
async def password_reset_confirm(
    request: Request,
    payload: PasswordResetConfirmRequest,
    db: AsyncSession = Depends(get_db_session),
) -> GenericResponse:
    record = await password_reset.fetch_valid_token(db, payload.token)
    if not record:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="invalid_or_expired_token")
    user = record.user
    try:
        user.password_hash = security_manager.hash_password(payload.new_password)
    except PasswordValidationError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    user.last_password_change_at = datetime.utcnow()
    await password_reset.mark_token_used(db, record)
    await session_service.revoke_all_sessions(db, user)
    await log_audit_event(
        db,
        event_type="password_reset_completed",
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        meta={},
    )
    await db.commit()
    return GenericResponse()


@router.get("/sessions", response_model=SessionsResponse)
async def list_sessions(
    user_session: tuple[User, SessionModel] = Depends(require_session),
) -> SessionsResponse:
    user, _ = user_session
    sessions = [
        SessionInfo(
            id=str(s.id),
            created_at=s.created_at,
            last_used_at=s.last_used_at,
            ip=s.ip,
            user_agent=s.user_agent,
            mfa_last_verified_at=s.mfa_last_verified_at,
        )
        for s in user.sessions
    ]
    return SessionsResponse(sessions=sessions)


@router.post("/logout", response_model=GenericResponse, dependencies=[Depends(require_csrf)])
async def logout(
    request: Request,
    response: Response,
    user_session: tuple[User, SessionModel] = Depends(require_session),
    db: AsyncSession = Depends(get_db_session),
) -> GenericResponse:
    user, session = user_session
    await session_service.revoke_session(db, session)
    response.delete_cookie(settings.session_cookie_name, httponly=True, secure=True, samesite="strict")
    response.delete_cookie(settings.csrf_cookie_name, httponly=False, secure=True, samesite="strict")
    await log_audit_event(
        db,
        event_type="logout",
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        meta={"session_id": str(session.id)},
    )
    await db.commit()
    return GenericResponse()


@router.post("/sessions/revoke-others", response_model=GenericResponse, dependencies=[Depends(require_csrf)])
async def revoke_other_sessions(
    request: Request,
    user_session: tuple[User, SessionModel] = Depends(require_session),
    db: AsyncSession = Depends(get_db_session),
) -> GenericResponse:
    user, session = user_session
    await session_service.revoke_other_sessions(db, user, current_session_id=session.id)
    await log_audit_event(
        db,
        event_type="sessions_revoked",
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        meta={},
    )
    await db.commit()
    return GenericResponse()


@router.post("/step-up/confirm", response_model=GenericResponse, dependencies=[Depends(require_csrf)])
async def confirm_step_up(
    request: Request,
    user: User = Depends(require_recent_mfa),
    db: AsyncSession = Depends(get_db_session),
) -> GenericResponse:
    await log_audit_event(
        db,
        event_type="step_up_confirmed",
        user=user,
        ip=get_client_ip(request),
        user_agent=get_user_agent(request),
        meta={"note": "Sensitive action approved"},
    )
    await db.commit()
    return GenericResponse()


@router.get("/admin/ping", response_model=RoleProtectedResponse)
async def admin_ping(user: User = Depends(require_role(UserRole.ADMIN))) -> RoleProtectedResponse:
    return RoleProtectedResponse(role=UserRole(user.role), message="admin_access_granted")
