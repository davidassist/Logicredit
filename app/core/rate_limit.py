"""Rate limiting utilities using slowapi and Redis."""
from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

from .config import get_settings


settings = get_settings()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.rate_limit_per_ip],
    storage_uri=settings.redis_url,
)
