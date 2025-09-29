"""End-to-end tests for the authentication API (synchronous)."""
from __future__ import annotations

import asyncio
import re
from datetime import datetime

import pyotp
import pytest
from sqlalchemy import select

from app.db.session import get_database
from app.models import Session, User, WebAuthnCredential


def extract_token_from_email(client, subject: str) -> str:
    for email in reversed(getattr(client, "sent_emails", [])):
        if email["subject"] == subject:
            match = re.search(r"token=([a-f0-9]+)", email["body"])
            if match:
                return match.group(1)
    raise AssertionError("Token not found in sent emails")


def run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def test_register_verify_login_flow(client) -> None:
    email = "user1@example.com"
    password = "VerySecurePass123!"

    response = client.post("/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201

    token = extract_token_from_email(client, "Verify your email")
    verify_response = client.post("/auth/verify-email", json={"token": token})
    assert verify_response.status_code == 200

    login_response = client.post("/auth/login", json={"email": email, "password": password})
    assert login_response.status_code == 200
    csrf_token = login_response.json()["csrf_token"]
    assert client.cookies.get("sid")

    me_response = client.get("/auth/me")
    assert me_response.status_code == 200
    assert me_response.json()["email"] == email

    logout_response = client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})
    assert logout_response.status_code == 200


def test_totp_flow(client) -> None:
    email = "totp@example.com"
    password = "AnotherSecurePass456!"

    client.post("/auth/register", json={"email": email, "password": password})
    token = extract_token_from_email(client, "Verify your email")
    client.post("/auth/verify-email", json={"token": token})

    login_response = client.post("/auth/login", json={"email": email, "password": password})
    csrf_token = login_response.json()["csrf_token"]

    initial_step_up = client.post("/auth/step-up/confirm", headers={"X-CSRF-Token": csrf_token})
    assert initial_step_up.status_code == 401

    setup_response = client.post("/auth/mfa/totp/setup", headers={"X-CSRF-Token": csrf_token})
    provisioning_uri = setup_response.json()["provisioning_uri"]
    secret = pyotp.parse_uri(provisioning_uri).secret
    code = pyotp.TOTP(secret).now()

    verify_response = client.post(
        "/auth/mfa/totp/verify",
        json={"code": code},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert verify_response.status_code == 200
    csrf_token = verify_response.json()["csrf_token"]

    client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})

    login_challenge = client.post("/auth/login", json={"email": email, "password": password})
    assert login_challenge.status_code == 200
    assert login_challenge.json()["mfa_required"] is True

    code = pyotp.TOTP(secret).now()
    mfa_login = client.post("/auth/mfa/totp/verify", json={"email": email, "code": code})
    assert mfa_login.status_code == 200
    csrf_token = mfa_login.json()["csrf_token"]

    me_response = client.get("/auth/me")
    assert me_response.status_code == 200
    assert me_response.json()["email"] == email

    step_up_success = client.post("/auth/step-up/confirm", headers={"X-CSRF-Token": csrf_token})
    assert step_up_success.status_code == 200

    client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})


def test_webauthn_flow(client, monkeypatch: pytest.MonkeyPatch) -> None:
    email = "passkey@example.com"
    password = "PasskeyPass789!"

    client.post("/auth/register", json={"email": email, "password": password})
    token = extract_token_from_email(client, "Verify your email")
    client.post("/auth/verify-email", json={"token": token})

    login_response = client.post("/auth/login", json={"email": email, "password": password})
    csrf_token = login_response.json()["csrf_token"]

    async def fake_begin_registration(db, user):  # type: ignore[override]
        return {"challenge": "fake-register"}

    async def fake_complete_registration(db, user, credential):  # type: ignore[override]
        credential_obj = WebAuthnCredential(
            id="cred1",
            user=user,
            public_key=b"key",
            sign_count=0,
            created_at=datetime.utcnow(),
        )
        db.add(credential_obj)
        await db.flush()
        return credential_obj

    async def fake_begin_authentication(user):  # type: ignore[override]
        return {"challenge": "fake-login"}

    async def fake_complete_authentication(db, user, credential):  # type: ignore[override]
        cred = user.webauthn_credentials[0]
        cred.sign_count += 1
        await db.flush()
        return cred

    monkeypatch.setattr("app.services.webauthn.begin_registration", fake_begin_registration)
    monkeypatch.setattr("app.services.webauthn.complete_registration", fake_complete_registration)
    monkeypatch.setattr("app.services.webauthn.begin_authentication", fake_begin_authentication)
    monkeypatch.setattr("app.services.webauthn.complete_authentication", fake_complete_authentication)

    start_resp = client.post("/auth/webauthn/register/start", headers={"X-CSRF-Token": csrf_token})
    assert start_resp.status_code == 200
    finish_resp = client.post(
        "/auth/webauthn/register/finish",
        json={"credential": {"response": "ok"}},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert finish_resp.status_code == 200

    client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})

    challenge = client.post("/auth/login", json={"email": email, "password": password})
    assert challenge.status_code == 200
    assert "webauthn" in challenge.json()["methods"]

    start_login = client.post("/auth/webauthn/login/start", json={"email": email})
    assert start_login.status_code == 200
    finish_login = client.post("/auth/webauthn/login/finish", json={"email": email, "credential": {}})
    assert finish_login.status_code == 200


def test_password_reset_flow(client) -> None:
    email = "reset@example.com"
    password = "InitialPass321!"

    client.post("/auth/register", json={"email": email, "password": password})
    token = extract_token_from_email(client, "Verify your email")
    client.post("/auth/verify-email", json={"token": token})

    login_response = client.post("/auth/login", json={"email": email, "password": password})
    csrf_token = login_response.json()["csrf_token"]

    client.post("/auth/password/reset/request", json={"email": email})
    reset_token = extract_token_from_email(client, "Password reset request")

    new_password = "NewSecurePass654!"
    confirm_resp = client.post(
        "/auth/password/reset/confirm",
        json={"token": reset_token, "new_password": new_password},
    )
    assert confirm_resp.status_code == 200

    database = get_database()

    async def fetch_sessions() -> list[Session]:
        async with database.session()() as session:
            user = (await session.execute(select(User).where(User.email == email))).scalar_one()
            result = await session.execute(select(Session).where(Session.user_id == user.id))
            return list(result.scalars())

    sessions = run_async(fetch_sessions())
    assert not sessions

    login_new = client.post("/auth/login", json={"email": email, "password": new_password})
    assert login_new.status_code == 200


def test_csrf_protection(client) -> None:
    email = "csrf@example.com"
    password = "CsrfPass987!"

    client.post("/auth/register", json={"email": email, "password": password})
    token = extract_token_from_email(client, "Verify your email")
    client.post("/auth/verify-email", json={"token": token})
    login_response = client.post("/auth/login", json={"email": email, "password": password})
    csrf_token = login_response.json()["csrf_token"]

    forbidden = client.post("/auth/sessions/revoke-others")
    assert forbidden.status_code == 403

    allowed = client.post("/auth/sessions/revoke-others", headers={"X-CSRF-Token": csrf_token})
    assert allowed.status_code == 200


def test_rate_limit_and_role_guard(client) -> None:
    email = "limit@example.com"
    password = "LimitPass321!"

    client.post("/auth/register", json={"email": email, "password": password})
    token = extract_token_from_email(client, "Verify your email")
    client.post("/auth/verify-email", json={"token": token})

    for _ in range(3):
        client.post("/auth/login", json={"email": email, "password": "wrong"})
    limited = client.post("/auth/login", json={"email": email, "password": "wrong"})
    assert limited.status_code == 429

    login_response = client.post("/auth/login", json={"email": email, "password": password})
    if login_response.status_code == 200:
        csrf_token = login_response.json()["csrf_token"]
        admin_ping = client.get("/auth/admin/ping")
        assert admin_ping.status_code == 403
        client.post("/auth/logout", headers={"X-CSRF-Token": csrf_token})
