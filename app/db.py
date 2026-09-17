from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .config import get_settings


def _make_engine() -> Engine:
    return create_engine(
        get_settings().database_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )


engine: Engine = _make_engine()
SessionLocal: sessionmaker[Session] = sessionmaker(
    bind=engine, expire_on_commit=False, autoflush=False
)


def reset_engine(new_url: str | None = None) -> Engine:
    """Replace the global engine/session factory (used by tests)."""
    global engine, SessionLocal
    try:
        engine.dispose()
    except Exception:
        pass
    if new_url is not None:
        get_settings().database_url = new_url  # type: ignore[misc]
    engine = _make_engine()
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False)
    return engine


def init_db() -> None:
    from .models import Base

    Base.metadata.create_all(engine)
