"""CSRF token handling."""
from __future__ import annotations

import hashlib

from app.core.config import get_settings
from app.core.security import security_manager
from app.services.redis_client import get_redis_client


settings = get_settings()


async def issue_csrf_token(session_id: str) -> str:
    token = security_manager.generate_csrf_token()
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    redis = get_redis_client()
    await redis.set(settings.build_csrf_cache_key(session_id), token_hash, ex=settings.csrf_token_ttl_seconds)
    return token


async def validate_csrf_token(session_id: str, token: str | None) -> bool:
    if not token:
        return False
    redis = get_redis_client()
    token_hash = await redis.get(settings.build_csrf_cache_key(session_id))
    if not token_hash:
        return False
    candidate_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    return security_manager.constant_time_compare(token_hash, candidate_hash)


async def revoke_csrf_token(session_id: str) -> None:
    redis = get_redis_client()
    await redis.delete(settings.build_csrf_cache_key(session_id))
