"""Concurrency stress test: many parallel appends must produce one dense,
gap-free, duplicate-free sequence of leaf indices with a correct root.
"""

import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, urlparse

import pgserver
import psycopg2

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_PGDATA = "/tmp/pgdata-artifactlog-test"
N_THREADS = 16
PER_THREAD = 25  # 400 appends total


def main() -> None:
    srv = pgserver.get_server(_PGDATA, cleanup_mode=None)
    admin = srv.get_uri()
    name = f"conc_{os.urandom(4).hex()}"
    conn = psycopg2.connect(admin)
    conn.autocommit = True
    conn.cursor().execute(f"CREATE DATABASE {name}")
    conn.close()
    sock = parse_qs(urlparse(admin).query)["host"][0]
    url = f"postgresql+psycopg2://postgres@localhost/{name}?host={sock}"

    from sqlalchemy.pool import NullPool

    from app import db as db_mod

    db_mod.engine = db_mod.create_engine(url, poolclass=NullPool)
    db_mod.SessionLocal.configure(bind=db_mod.engine)
    db_mod.init_db()

    import app.main as main_mod
    from fastapi.testclient import TestClient

    total = N_THREADS * PER_THREAD
    results: list[tuple[int, int]] = []
    errors: list[str] = []

    def worker(t: int) -> list[tuple[int, int]]:
        out = []
        with TestClient(main_mod.app, raise_server_exceptions=True) as client:
            for j in range(PER_THREAD):
                r = client.post(
                    "/v1/entries",
                    headers={"X-Tenant-ID": "concurrent"},
                    json={
                        "idempotency_key": f"t{t}-j{j}",
                        "claim": {"thread": t, "seq": j},
                    },
                )
                if r.status_code != 201:
                    errors.append(f"t{t} j{j} -> {r.status_code} {r.text}")
                else:
                    out.append((t * PER_THREAD + j, r.json()["leaf_index"]))
        return out

    # Simulate many different pipeline publishers at once. Also include a
    # second tenant to prove cross-tenant appends don't block correctness.
    with ThreadPoolExecutor(max_workers=N_THREADS + 1) as pool:
        futs = [pool.submit(worker, t) for t in range(N_THREADS)]

        def other_tenant() -> None:
            with TestClient(main_mod.app) as client:
                for j in range(PER_THREAD):
                    r = client.post(
                        "/v1/entries",
                        headers={"X-Tenant-ID": "other"},
                        json={"idempotency_key": f"o{j}", "claim": {"j": j}},
                    )
                    if r.status_code != 201:
                        errors.append(f"other {j} {r.status_code}")

        futs.append(pool.submit(other_tenant))
        for f in as_completed(futs):
            f.result()
        for f in futs[:-1]:
            results.extend(f.result())

    assert not errors, errors[:5]

    indices = sorted(idx for _, idx in results)
    assert indices == list(range(total)), "leaf indices must be dense 0..N-1"
    assert len(set(indices)) == total, "no duplicate leaf indices"

    # Cross-check the committed root against an independent recomputation.
    from app import merkle
    from app.models import Leaf

    s = db_mod.SessionLocal()
    rows = (
        s.query(Leaf.leaf_input)
        .filter(Leaf.tenant_id == "concurrent")
        .order_by(Leaf.leaf_index)
        .all()
    )
    s.close()
    leaf_inputs = [r[0] for r in rows]
    assert len(leaf_inputs) == total
    expected_root = merkle.mth(leaf_inputs)

    with TestClient(main_mod.app) as client:
        sth = client.get(
            "/v1/tree-head", headers={"X-Tenant-ID": "concurrent"}
        ).json()
    import base64

    assert base64.b64decode(sth["root_hash"]) == expected_root
    assert sth["tree_size"] == total

    # Idempotent concurrent double-submits with identical content: all but
    # one must return the original; none may error or grow the tree.
    def duplicate_submit() -> int:
        with TestClient(main_mod.app) as client:
            r = client.post(
                "/v1/entries",
                headers={"X-Tenant-ID": "concurrent"},
                json={
                    "idempotency_key": "same-key",
                    "claim": {"same": True},
                },
            )
            return r.status_code

    with ThreadPoolExecutor(max_workers=20) as pool:
        codes = list(pool.map(lambda _: duplicate_submit(), range(20)))
    assert set(codes) <= {200, 201}, codes
    assert codes.count(201) == 1, codes
    with TestClient(main_mod.app) as client:
        sth2 = client.get(
            "/v1/tree-head", headers={"X-Tenant-ID": "concurrent"}
        ).json()
    assert sth2["tree_size"] == total + 1

    # Concurrent same-key different-content must never silently overwrite.
    def conflict_submit(v: int):
        with TestClient(main_mod.app) as client:
            return client.post(
                "/v1/entries",
                headers={"X-Tenant-ID": "concurrent"},
                json={"idempotency_key": "conflict", "claim": {"v": v}},
            ).status_code

    with ThreadPoolExecutor(max_workers=10) as pool:
        ccodes = list(pool.map(conflict_submit, range(10)))
    assert 201 in ccodes and 409 in ccodes and not (set(ccodes) - {200, 201, 409})

    db_mod.engine.dispose()
    conn = psycopg2.connect(admin)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
            "WHERE datname = %s AND pid <> pg_backend_pid()",
            (name,),
        )
        cur.execute(f"DROP DATABASE {name}")
    conn.close()
    print(
        f"OK: {total} concurrent appends dense, root verified; "
        "idempotent/conflict races safe"
    )


if __name__ == "__main__":
    main()
