"""Application configuration management."""
from __future__ import annotations

import secrets
from functools import lru_cache
from typing import List

from pydantic import AnyHttpUrl, BaseSettings, Field, validator


class Settings(BaseSettings):
    """Runtime configuration derived from environment variables."""

    app_name: str = Field("Logicredit Auth Service", alias="APP_NAME")
    environment: str = Field("development", alias="ENVIRONMENT")
    debug: bool = Field(False, alias="DEBUG")
    database_url: str = Field(..., alias="DATABASE_URL")
    redis_url: str = Field(..., alias="REDIS_URL")
    smtp_host: str = Field(..., alias="SMTP_HOST")
    smtp_port: int = Field(587, alias="SMTP_PORT")
    smtp_username: str = Field(..., alias="SMTP_USERNAME")
    smtp_password: str = Field(..., alias="SMTP_PASSWORD")
    smtp_use_tls: bool = Field(True, alias="SMTP_USE_TLS")
    from_email: str = Field(..., alias="FROM_EMAIL")
    frontend_origins: List[AnyHttpUrl] = Field(..., alias="FRONTEND_ORIGINS")
    session_cookie_name: str = Field("sid", alias="SESSION_COOKIE_NAME")
    session_idle_timeout_seconds: int = Field(900, alias="SESSION_IDLE_TIMEOUT_SECONDS")
    csrf_cookie_name: str = Field("csrf_token", alias="CSRF_COOKIE_NAME")
    rate_limit_per_ip: str = Field("50/10minutes", alias="RATE_LIMIT_PER_IP")
    argon2_memory_cost: int = Field(19456, alias="ARGON2_MEMORY_COST")
    argon2_time_cost: int = Field(3, alias="ARGON2_TIME_COST")
    argon2_parallelism: int = Field(1, alias="ARGON2_PARALLELISM")
    totp_encryption_key: str = Field(..., alias="TOTP_ENCRYPTION_KEY")
    csrf_redis_prefix: str = Field("csrf", alias="CSRF_REDIS_PREFIX")
    csrf_token_ttl_seconds: int = Field(900, alias="CSRF_TOKEN_TTL_SECONDS")
    email_verification_token_ttl_hours: int = Field(24, alias="EMAIL_VERIFICATION_TOKEN_TTL_HOURS")
    password_reset_token_ttl_minutes: int = Field(30, alias="PASSWORD_RESET_TOKEN_TTL_MINUTES")
    cors_allow_credentials: bool = Field(True, alias="CORS_ALLOW_CREDENTIALS")
    security_headers_enabled: bool = Field(True, alias="SECURITY_HEADERS_ENABLED")
    fido_rp_id: str = Field(..., alias="FIDO_RP_ID")
    fido_rp_name: str = Field(..., alias="FIDO_RP_NAME")
    origin_url: AnyHttpUrl = Field(..., alias="ORIGIN_URL")
    mfa_recent_timeout_seconds: int = Field(300, alias="MFA_RECENT_TIMEOUT_SECONDS")
    brute_force_max_attempts: int = Field(5, alias="BRUTE_FORCE_MAX_ATTEMPTS")
    brute_force_lockout_minutes: int = Field(15, alias="BRUTE_FORCE_LOCKOUT_MINUTES")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    @validator("frontend_origins", pre=True)
    def split_frontend_origins(cls, value: str | List[AnyHttpUrl]) -> List[AnyHttpUrl]:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @validator("totp_encryption_key")
    def validate_totp_key(cls, value: str) -> str:
        if len(value) < 32:
            raise ValueError("TOTP_ENCRYPTION_KEY must be at least 32 characters")
        return value

    @property
    def csrf_secret(self) -> bytes:
        return self.totp_encryption_key.encode("utf-8")

    def build_csrf_cache_key(self, session_id: str) -> str:
        return f"{self.csrf_redis_prefix}:{session_id}"


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings instance."""

    return Settings()


def generate_secret_key(length: int = 32) -> str:
    """Generate a URL-safe secret key for encryption or CSRF tokens."""

    return secrets.token_urlsafe(length)
