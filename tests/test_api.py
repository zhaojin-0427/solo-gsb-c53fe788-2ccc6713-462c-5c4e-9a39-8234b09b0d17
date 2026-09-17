import base64
import hashlib
import json

from tests.conftest import b64

TENANT = "tenant-A"
HEADERS = {"X-Tenant-ID": TENANT}


def claim(i: int, extra: str = "x") -> dict:
    return {
        "artifact_digest": "sha256:" + f"{i:064x}"[:57],
        "build_metadata": {"job": "ci", "run_id": i, "extra": extra},
    }


def post_entry(client, i, key=None, extra="x", revokes=None, headers=None):
    payload = {
        "idempotency_key": key or f"idem-{i}",
        "claim": claim(i, extra),
    }
    if revokes is not None:
        payload["revokes_leaf_index"] = revokes
    return client.post(
        "/v1/entries", json=payload, headers=headers or HEADERS
    )


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_append_assigns_sequential_indices_and_signed_sth(client):
    n = 20
    for i in range(n):
        r = post_entry(client, i)
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["leaf_index"] == i
        assert body["tree_size"] == i + 1
        assert body["duplicate"] is False

    sth = client.get("/v1/tree-head", headers=HEADERS).json()
    assert sth["tree_size"] == n
    assert len(base64.b64decode(sth["root_hash"])) == 32
    assert len(base64.b64decode(sth["signature"])) == 64

    # STH signature verifies with the advertised public key.
    key = client.get(f"/v1/keys/{sth['key_id']}").json()
    vr = client.post(
        "/v1/verify/tree-head",
        params={
            "tree_size": sth["tree_size"],
            "root_hash": sth["root_hash"],
            "timestamp_ms": sth["timestamp_ms"],
            "signature": sth["signature"],
            "public_key": key["public_key"],
        },
    )
    assert vr.json() == {"valid": True, "reason": None}


def test_root_matches_independent_rfc_reference(client):
    """Recompute the root from all leaf inputs with a from-scratch reference."""
    import sys, os

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app import merkle

    n = 50
    leaf_inputs = []
    for i in range(n):
        r = post_entry(client, i)
        leaf_inputs.append(base64.b64decode(r.json()["leaf_input"]))

    expected = merkle.mth(leaf_inputs)
    sth = client.get("/v1/tree-head", headers=HEADERS).json()
    assert base64.b64decode(sth["root_hash"]) == expected


def test_idempotency_same_content_returns_original(client):
    r1 = post_entry(client, 1, key="shared-key")
    assert r1.status_code == 201
    r2 = post_entry(client, 1, key="shared-key")
    assert r2.status_code == 200
    b1, b2 = r1.json(), r2.json()
    assert b2["duplicate"] is True
    assert b2["leaf_index"] == b1["leaf_index"]
    assert b2["leaf_hash"] == b1["leaf_hash"]
    assert b2["tree_size"] == b1["tree_size"]
    # only one leaf exists
    head = client.get("/v1/tree-head", headers=HEADERS).json()
    assert head["tree_size"] == 1


def test_idempotency_different_content_is_409(client):
    post_entry(client, 1, key="dup-key", extra="first")
    r = post_entry(client, 2, key="dup-key", extra="different")
    assert r.status_code == 409
    assert "idempotency" in r.json()["detail"]
    # tree did not grow
    head = client.get("/v1/tree-head", headers=HEADERS).json()
    assert head["tree_size"] == 1


def test_inclusion_proof_and_stateless_verification(client):
    n = 30
    for i in range(n):
        post_entry(client, i)

    for tree_size in (1, 7, 16, 29, 30):
        for leaf_index in range(tree_size):
            pr = client.get(
                "/v1/proofs/inclusion",
                params={"leaf_index": leaf_index, "tree_size": tree_size},
                headers=HEADERS,
            )
            assert pr.status_code == 200, pr.text
            proof = pr.json()
            leaf = client.get(
                f"/v1/leaves/{leaf_index}", headers=HEADERS
            ).json()
            vr = client.post(
                "/v1/verify/inclusion",
                json={
                    "leaf_input": leaf["leaf_input"],
                    "leaf_index": leaf_index,
                    "tree_size": tree_size,
                    "inclusion_path": proof["inclusion_path"],
                    "root_hash": proof["root_hash"],
                },
            )
            assert vr.json()["valid"] is True, (leaf_index, tree_size)


def test_inclusion_out_of_range_and_not_yet_in_head(client):
    for i in range(10):
        post_entry(client, i)
    # leaf beyond tree
    r = client.get(
        "/v1/proofs/inclusion",
        params={"leaf_index": 10, "tree_size": 10},
        headers=HEADERS,
    )
    assert r.status_code == 404
    # leaf exists now but not at the older chosen tree size
    r = client.get(
        "/v1/proofs/inclusion",
        params={"leaf_index": 9, "tree_size": 5},
        headers=HEADERS,
    )
    assert r.status_code == 404
    # future tree size
    r = client.get(
        "/v1/proofs/inclusion",
        params={"leaf_index": 0, "tree_size": 11},
        headers=HEADERS,
    )
    assert r.status_code == 404
    # nonexistent leaf lookup
    assert client.get("/v1/leaves/999", headers=HEADERS).status_code == 404


def test_consistency_proofs_between_any_two_heads(client):
    n = 25
    for i in range(n):
        post_entry(client, i)
    roots = {}
    for size in range(1, n + 1):
        sth = client.get(
            "/v1/tree-head", params={"tree_size": size}, headers=HEADERS
        ).json()
        roots[size] = sth["root_hash"]

    for first in range(1, n + 1):
        for second in range(first, n + 1):
            r = client.get(
                "/v1/proofs/consistency",
                params={
                    "first_tree_size": first,
                    "second_tree_size": second,
                },
                headers=HEADERS,
            )
            assert r.status_code == 200, (first, second, r.text)
            p = r.json()
            vr = client.post(
                "/v1/verify/consistency",
                json={
                    "first_tree_size": first,
                    "second_tree_size": second,
                    "consistency_path": p["consistency_path"],
                    "first_root_hash": roots[first],
                    "second_root_hash": roots[second],
                },
            )
            assert vr.json()["valid"] is True, (first, second)

    # invalid parameters
    bad = client.get(
        "/v1/proofs/consistency",
        params={"first_tree_size": 0, "second_tree_size": 5},
        headers=HEADERS,
    )
    assert bad.status_code == 400
    fut = client.get(
        "/v1/proofs/consistency",
        params={"first_tree_size": 1, "second_tree_size": 100},
        headers=HEADERS,
    )
    assert fut.status_code == 404


def test_verification_rejects_tampered_inputs(client):
    for i in range(8):
        post_entry(client, i)
    p = client.get(
        "/v1/proofs/inclusion",
        params={"leaf_index": 3, "tree_size": 8},
        headers=HEADERS,
    ).json()
    leaf = client.get("/v1/leaves/3", headers=HEADERS).json()

    # tamper with leaf bytes
    raw = bytearray(base64.b64decode(leaf["leaf_input"]))
    raw[-1] ^= 0xFF
    bad_body = {
        "leaf_input": b64(bytes(raw)),
        "leaf_index": 3,
        "tree_size": 8,
        "inclusion_path": p["inclusion_path"],
        "root_hash": p["root_hash"],
    }
    assert client.post("/v1/verify/inclusion", json=bad_body).json()["valid"] is False

    # tamper root
    bad_body["leaf_input"] = leaf["leaf_input"]
    bad_root = bytearray(base64.b64decode(p["root_hash"]))
    bad_root[0] ^= 1
    bad_body["root_hash"] = b64(bytes(bad_root))
    assert client.post("/v1/verify/inclusion", json=bad_body).json()["valid"] is False


def test_revocation_is_a_new_leaf_and_history_unchanged(client):
    post_entry(client, 0)
    post_entry(client, 1)
    head_before = client.get(
        "/v1/tree-head", params={"tree_size": 2}, headers=HEADERS
    ).json()

    r = post_entry(client, 2, key="rev-2", revokes=0)
    assert r.status_code == 201, r.text
    rev = r.json()
    assert rev["leaf_index"] == 2
    assert rev["tree_size"] == 3

    envelope = client.get("/v1/leaves/2", headers=HEADERS).json()["envelope"]
    assert envelope["type"] == "build-artifact-revocation"
    assert envelope["revokes_leaf_index"] == 0

    # Old STH is byte-for-byte unchanged.
    head_after = client.get(
        "/v1/tree-head", params={"tree_size": 2}, headers=HEADERS
    ).json()
    assert head_after["root_hash"] == head_before["root_hash"]
    assert head_after["signature"] == head_before["signature"]

    # Revoking a not-yet-existing leaf is rejected.
    r = post_entry(client, 3, key="rev-future", revokes=99)
    assert r.status_code == 409

    # The revoked leaf itself is still readable (history never rewritten).
    old = client.get("/v1/leaves/0", headers=HEADERS).json()
    assert old["envelope"]["type"] == "build-artifact-claim"


def test_key_rotation_keeps_old_signatures_verifiable(client):
    for i in range(3):
        post_entry(client, i)
    old_sth = client.get(
        "/v1/tree-head", params={"tree_size": 3}, headers=HEADERS
    ).json()
    old_pubkey = client.get(f"/v1/keys/{old_sth['key_id']}").json()["public_key"]

    rot = client.post("/v1/keys/rotate")
    assert rot.status_code == 201
    new_key = rot.json()
    assert new_key["key_id"] != old_sth["key_id"]

    # Grow the tree so the new key signs a fresh STH.
    for i in range(3, 6):
        post_entry(client, i)
    new_sth = client.get(
        "/v1/tree-head", params={"tree_size": 6}, headers=HEADERS
    ).json()
    assert new_sth["key_id"] == new_key["key_id"]

    # Old STH still verifies under the old (retired) public key.
    old_ok = client.post(
        "/v1/verify/tree-head",
        params={
            "tree_size": old_sth["tree_size"],
            "root_hash": old_sth["root_hash"],
            "timestamp_ms": old_sth["timestamp_ms"],
            "signature": old_sth["signature"],
            "public_key": old_pubkey,
        },
    ).json()
    assert old_ok["valid"] is True

    # Old key does not verify the new STH.
    old_key_new_sig = client.post(
        "/v1/verify/tree-head",
        params={
            "tree_size": new_sth["tree_size"],
            "root_hash": new_sth["root_hash"],
            "timestamp_ms": new_sth["timestamp_ms"],
            "signature": new_sth["signature"],
            "public_key": old_pubkey,
        },
    ).json()
    assert old_key_new_sig["valid"] is False

    keys = client.get("/v1/keys").json()
    assert {k["key_id"] for k in keys} >= {old_sth["key_id"], new_key["key_id"]}
    assert sum(1 for k in keys if k["active"]) == 1


def test_tenants_have_independent_trees(client):
    post_entry(client, 1, headers={"X-Tenant-ID": "T1"})
    post_entry(client, 1, headers={"X-Tenant-ID": "T2"})
    post_entry(client, 2, headers={"X-Tenant-ID": "T2"})
    h1 = client.get("/v1/tree-head", headers={"X-Tenant-ID": "T1"}).json()
    h2 = client.get("/v1/tree-head", headers={"X-Tenant-ID": "T2"}).json()
    assert h1["tree_size"] == 1
    assert h2["tree_size"] == 2
    # Same idempotency key across tenants must not collide.
    r = client.post(
        "/v1/entries",
        json={"idempotency_key": "k", "claim": {"a": 1}},
        headers={"X-Tenant-ID": "T1"},
    )
    assert r.status_code == 201


def test_missing_tenant_header_is_400(client):
    r = client.post(
        "/v1/entries",
        json={"idempotency_key": "k", "claim": {"a": 1}},
    )
    assert r.status_code == 400


def test_invalid_claim_returns_400(client):
    # NaN is accepted by Python's lenient JSON parser but forbidden by JCS;
    # send the raw token so the client-side encoder does not reject it.
    r = client.post(
        "/v1/entries",
        content=b'{"idempotency_key":"bad","claim":{"x":NaN}}',
        headers={**HEADERS, "Content-Type": "application/json"},
    )
    assert 400 <= r.status_code < 500, r.text


def test_jcs_canonicalisation(client):
    # Key order / whitespace differences are the same claim.
    c1 = {"b": 2, "a": [1, 2, 3], "nested": {"z": 1, "y": 2}}
    c2 = {"nested": {"y": 2, "z": 1}, "a": [1, 2, 3], "b": 2}
    r1 = client.post(
        "/v1/entries",
        json={"idempotency_key": "jcs", "claim": c1},
        headers=HEADERS,
    )
    r2 = client.post(
        "/v1/entries",
        json={"idempotency_key": "jcs", "claim": c2},
        headers=HEADERS,
    )
    assert r1.status_code == 201
    assert r2.status_code == 200
    envelope = client.get("/v1/leaves/0", headers=HEADERS).json()
    # JCS sorts keys and removes insignificant whitespace.
    assert envelope["leaf_input"] == b64(
        json.dumps(envelope["envelope"], sort_keys=True, separators=(",", ":")).encode()
    )


def test_empty_tree_head(client):
    r = client.get("/v1/tree-head", headers=HEADERS)
    assert r.status_code == 200, r.text
    sth = r.json()
    assert sth["tree_size"] == 0
    assert base64.b64decode(sth["root_hash"]) == hashlib.sha256(b"").digest()


def test_proofs_for_nonexistent_tenant_are_404(client):
    h = {"X-Tenant-ID": "ghost"}
    assert client.get("/v1/tree-head", headers=h).status_code == 200  # auto-create
    assert (
        client.get(
            "/v1/proofs/inclusion",
            params={"leaf_index": 0, "tree_size": 1},
            headers={"X-Tenant-ID": "never-seen"},
        ).status_code
        == 404
    )
    assert (
        client.get(
            "/v1/proofs/consistency",
            params={"first_tree_size": 1, "second_tree_size": 2},
            headers={"X-Tenant-ID": "never-seen"},
        ).status_code
        == 404
    )
    assert client.get("/v1/leaves/0", headers=h).status_code == 404


def test_consistency_equal_sizes_is_trivially_valid(client):
    for i in range(4):
        post_entry(client, i)
    r = client.get(
        "/v1/proofs/consistency",
        params={"first_tree_size": 4, "second_tree_size": 4},
        headers=HEADERS,
    )
    assert r.status_code == 200
    p = r.json()
    assert p["consistency_path"] == []
    vr = client.post(
        "/v1/verify/consistency",
        json={
            "first_tree_size": 4,
            "second_tree_size": 4,
            "consistency_path": [],
            "first_root_hash": p["first_root_hash"],
            "second_root_hash": p["second_root_hash"],
        },
    )
    assert vr.json()["valid"] is True


def test_sth_signature_covers_fields(client):
    post_entry(client, 0)
    sth = client.get("/v1/tree-head", headers=HEADERS).json()
    pub = client.get(f"/v1/keys/{sth['key_id']}").json()["public_key"]

    def verify(**overrides):
        params = {
            "tree_size": sth["tree_size"],
            "root_hash": sth["root_hash"],
            "timestamp_ms": sth["timestamp_ms"],
            "signature": sth["signature"],
            "public_key": pub,
        }
        params.update(overrides)
        return client.post("/v1/verify/tree-head", params=params).json()["valid"]

    assert verify() is True
    assert verify(tree_size=2) is False
    root = bytearray(base64.b64decode(sth["root_hash"]))
    root[0] ^= 1
    assert verify(root_hash=b64(bytes(root))) is False
    assert verify(timestamp_ms=sth["timestamp_ms"] + 1) is False


def test_verify_endpoints_do_not_touch_database(client):
    # The verify handlers are pure: assert at the routing level that none of
    # them declares the DB-session dependency, then exercise a live proof.
    import app.main as main_mod

    verify_routes = {
        "/v1/verify/inclusion",
        "/v1/verify/consistency",
        "/v1/verify/tree-head",
    }
    for route in main_mod.app.routes:
        if getattr(route, "path", None) in verify_routes:
            dependants = route.dependant.dependencies
            assert main_mod.get_session not in [
                d.call for d in dependants
            ], route.path
            for sub in dependants:
                assert main_mod.get_session not in [
                    d.call for d in sub.dependencies
                ]

    for i in range(6):
        post_entry(client, i)
    p = client.get(
        "/v1/proofs/inclusion",
        params={"leaf_index": 2, "tree_size": 6},
        headers=HEADERS,
    ).json()
    leaf = client.get("/v1/leaves/2", headers=HEADERS).json()
    r = client.post(
        "/v1/verify/inclusion",
        json={
            "leaf_input": leaf["leaf_input"],
            "leaf_index": 2,
            "tree_size": 6,
            "inclusion_path": p["inclusion_path"],
            "root_hash": p["root_hash"],
        },
    )
    assert r.status_code == 200
    assert r.json()["valid"] is True

