import base64
import os
import sys
from urllib.parse import parse_qs, urlparse

import pgserver
import psycopg2
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_PGDATA = "/tmp/pgdata-artifactlog-test"


@pytest.fixture(scope="session")
def pg_admin_uri() -> str:
    server = pgserver.get_server(_PGDATA, cleanup_mode=None)
    return server.get_uri()


@pytest.fixture()
def client(pg_admin_uri):
    parsed = urlparse(pg_admin_uri)
    socket_dir = parse_qs(parsed.query)["host"][0]
    user = parsed.username or "postgres"
    db_name = f"t_{os.urandom(6).hex()}"

    conn = psycopg2.connect(pg_admin_uri)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(f"CREATE DATABASE {db_name}")
    conn.close()

    url = (
        "postgresql+psycopg2://"
        f"{user}@localhost/{db_name}?host={socket_dir}"
    )

    from sqlalchemy.pool import NullPool

    from app import db as db_mod
    from app.config import get_settings

    get_settings().database_url = url  # type: ignore[misc]
    db_mod.engine.dispose()
    db_mod.engine = db_mod.create_engine(url, poolclass=NullPool)
    db_mod.SessionLocal.configure(bind=db_mod.engine)
    db_mod.init_db()

    from fastapi.testclient import TestClient
    import app.main as main_mod

    with TestClient(main_mod.app, raise_server_exceptions=True) as c:
        yield c

    db_mod.engine.dispose()
    conn = psycopg2.connect(pg_admin_uri)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = %s AND pid <> pg_backend_pid()",
            (db_name,),
        )
        cur.execute(f"DROP DATABASE {db_name}")
    conn.close()


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()
