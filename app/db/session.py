"""Database session handling."""
from __future__ import annotations

from collections.abc import AsyncIterator
from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import Settings, get_settings

from .base import Base


class Database:
    """Database configuration wrapper."""

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self.engine = create_async_engine(self.settings.database_url, echo=self.settings.debug, future=True)
        self._sessionmaker = async_sessionmaker(self.engine, expire_on_commit=False, class_=AsyncSession)

    async def create_all(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def drop_all(self) -> None:
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)

    def session(self) -> async_sessionmaker[AsyncSession]:
        return self._sessionmaker


@lru_cache(maxsize=1)
def get_database() -> Database:
    return Database()


async def get_db_session() -> AsyncIterator[AsyncSession]:
    database = get_database()
    async with database.session()() as session:
        yield session
