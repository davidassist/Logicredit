"""FastAPI application entrypoint."""
from __future__ import annotations

from collections.abc import Awaitable, Callable

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.api.routes import auth
from app.core.config import get_settings
from app.core.rate_limit import limiter
from app.services.redis_client import get_redis_client


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title=settings.app_name, debug=settings.debug)

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_handler)
    app.add_middleware(SlowAPIMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.frontend_origins],
        allow_credentials=settings.cors_allow_credentials,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token"],
    )

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        if settings.security_headers_enabled:
            response.headers.setdefault("X-Content-Type-Options", "nosniff")
            response.headers.setdefault("X-Frame-Options", "DENY")
            response.headers.setdefault("Referrer-Policy", "no-referrer")
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.exception_handler(HTTPException)  # type: ignore[name-defined]
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:  # type: ignore[name-defined]
        detail = exc.detail if isinstance(exc.detail, str) else "error"
        return JSONResponse(status_code=exc.status_code, content={"error": True, "code": detail, "message": detail})

    app.include_router(auth.router)

    @app.on_event("shutdown")
    async def shutdown_event() -> None:
        redis = get_redis_client()
        await redis.close()

    return app


async def _rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    return JSONResponse(status_code=429, content={"error": True, "code": "rate_limited", "message": "Too many requests"})


app = create_app()
