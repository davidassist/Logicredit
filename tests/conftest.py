"""Test fixtures for the authentication service."""
from __future__ import annotations

import asyncio
import os
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from limits.storage import MemoryStorage

from app.core import rate_limit
from app.core.config import get_settings
from app.core.email import EmailService
from app.db.session import get_database
from app.main import create_app


class InMemoryRedis:
    """Minimal async Redis replacement for tests."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[str, float | None]] = {}

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        expires = None
        if ex is not None:
            expires = asyncio.get_event_loop().time() + ex
        self._store[key] = (value, expires)

    async def get(self, key: str) -> str | None:
        payload = self._store.get(key)
        if not payload:
            return None
        value, expires = payload
        if expires is not None and asyncio.get_event_loop().time() > expires:
            self._store.pop(key, None)
            return None
        return value

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)

    async def close(self) -> None:
        self._store.clear()


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory) -> Generator[TestClient, None, None]:
    tmp_dir = tmp_path_factory.mktemp("db")
    database_url = f"sqlite+aiosqlite:///{tmp_dir / 'test.db'}"
    env = {
        "APP_NAME": "Logicredit Test Auth",
        "ENVIRONMENT": "test",
        "DEBUG": "True",
        "DATABASE_URL": database_url,
        "REDIS_URL": "redis://localhost:6379/0",
        "SMTP_HOST": "localhost",
        "SMTP_PORT": "1025",
        "SMTP_USERNAME": "user",
        "SMTP_PASSWORD": "pass",
        "SMTP_USE_TLS": "False",
        "FROM_EMAIL": "noreply@example.com",
        "FRONTEND_ORIGINS": "http://localhost:3000",
        "SESSION_COOKIE_NAME": "sid",
        "SESSION_IDLE_TIMEOUT_SECONDS": "900",
        "CSRF_COOKIE_NAME": "csrf_token",
        "RATE_LIMIT_PER_IP": "3/minute",
        "ARGON2_MEMORY_COST": "19456",
        "ARGON2_TIME_COST": "3",
        "ARGON2_PARALLELISM": "1",
        "TOTP_ENCRYPTION_KEY": "A" * 32,
        "CSRF_REDIS_PREFIX": "csrf-test",
        "CSRF_TOKEN_TTL_SECONDS": "900",
        "EMAIL_VERIFICATION_TOKEN_TTL_HOURS": "24",
        "PASSWORD_RESET_TOKEN_TTL_MINUTES": "30",
        "CORS_ALLOW_CREDENTIALS": "True",
        "SECURITY_HEADERS_ENABLED": "True",
        "FIDO_RP_ID": "localhost",
        "FIDO_RP_NAME": "Logicredit Test",
        "ORIGIN_URL": "http://localhost",
        "MFA_RECENT_TIMEOUT_SECONDS": "300",
        "BRUTE_FORCE_MAX_ATTEMPTS": "3",
        "BRUTE_FORCE_LOCKOUT_MINUTES": "15",
    }
    for key, value in env.items():
        os.environ[key] = str(value)

    get_settings.cache_clear()
    from app.db.session import get_database as get_db_cached

    get_db_cached.cache_clear()
    from app.services.redis_client import get_redis_client as get_redis_cached

    get_redis_cached.cache_clear()

    fake_redis = InMemoryRedis()

    def fake_get_redis() -> InMemoryRedis:
        return fake_redis

    monkeypatch.setattr("app.services.redis_client.get_redis_client", fake_get_redis)

    sent_emails: list[dict[str, str]] = []

    class DummyEmailService(EmailService):
        async def send_email(self, subject: str, recipient: str, body: str) -> None:  # type: ignore[override]
            sent_emails.append({"subject": subject, "recipient": recipient, "body": body})

    monkeypatch.setattr("app.core.email.get_email_service", lambda: DummyEmailService())

    rate_limit.limiter.storage = MemoryStorage()
    app = create_app()
    database = get_database()
    asyncio.run(database.create_all())

    with TestClient(app) as test_client:
        setattr(test_client, "sent_emails", sent_emails)
        yield test_client

    asyncio.run(database.drop_all())
    asyncio.run(fake_redis.close())
    get_db_cached.cache_clear()
    get_redis_cached.cache_clear()
    get_settings.cache_clear()
