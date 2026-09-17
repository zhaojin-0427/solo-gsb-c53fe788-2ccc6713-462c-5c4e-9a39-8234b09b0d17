"""Ed25519 signing of tree heads, with key rotation support.

Keys are stored in the ``signing_keys`` table and the public half is also
served via the API. Rotating never deletes old keys, so STHs signed by
retired keys remain verifiable forever.

Signed payload (binary, unambiguous):

    ARTIFACTLOG-STH-v1 ||
    u64be(tree_size)   || 32-byte root_hash ||
    u64be(timestamp_ms)

A tree head signature therefore commits to the exact tree size, root and
timestamp.
"""

from __future__ import annotations

import base64
import secrets
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import SigningKey

DOMAIN_SEPARATOR = b"ARTIFACTLOG-STH-v1"


@dataclass(frozen=True)
class ActiveKey:
    key_id: str
    public_key: bytes
    private_key: Ed25519PrivateKey


def encode_private_seed(seed: bytes) -> str:
    return base64.b64encode(seed).decode("ascii")


def decode_private_seed(encoded: str) -> bytes:
    raw = base64.b64decode(encoded.encode("ascii"))
    if len(raw) != 32:
        raise ValueError("Ed25519 seed must decode to exactly 32 bytes")
    return raw


def sth_input_bytes(
    tree_size: int, root_hash: bytes, timestamp_ms: int
) -> bytes:
    if len(root_hash) != 32:
        raise ValueError("root_hash must be 32 bytes")
    return (
        DOMAIN_SEPARATOR
        + tree_size.to_bytes(8, "big")
        + root_hash
        + timestamp_ms.to_bytes(8, "big")
    )


def verify_sth_signature(
    public_key: bytes,
    tree_size: int,
    root_hash: bytes,
    timestamp_ms: int,
    signature: bytes,
) -> bool:
    """Pure verification -- no database access."""
    try:
        key = Ed25519PublicKey.from_public_bytes(public_key)
        key.verify(
            signature,
            sth_input_bytes(tree_size, root_hash, timestamp_ms),
        )
        return True
    except Exception:
        return False


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


def _new_key_id() -> str:
    return "key_" + secrets.token_hex(8)


def get_active_key(session: Session) -> ActiveKey:
    row = session.scalars(
        select(SigningKey).where(SigningKey.active.is_(True)).limit(1)
    ).first()
    if row is not None:
        return ActiveKey(
            key_id=row.key_id,
            public_key=row.public_key,
            private_key=Ed25519PrivateKey.from_private_bytes(row.private_key),
        )

    key_id, priv_raw, pub_raw = _generate_key_material()
    row = SigningKey(
        key_id=key_id,
        public_key=pub_raw,
        private_key=priv_raw,
        active=True,
        created_at=str(_now_ms()),
    )
    session.add(row)
    session.flush()
    return ActiveKey(
        key_id=key_id,
        public_key=pub_raw,
        private_key=Ed25519PrivateKey.from_private_bytes(priv_raw),
    )


def _generate_key_material() -> tuple[str, bytes, bytes]:
    key_id = _new_key_id()
    priv = Ed25519PrivateKey.generate()
    priv_raw = priv.private_bytes_raw()
    pub_raw = priv.public_key().public_bytes_raw()
    return key_id, priv_raw, pub_raw


def ensure_configured_key(
    session: Session, key_id: str, seed_b64: str
) -> ActiveKey | None:
    """Seed the active key from environment configuration (first boot).

    Returns the key if configuration was supplied, else None and the
    database-managed key flow applies.
    """
    if not seed_b64:
        return None
    if not key_id:
        raise ValueError("SIGNING_KEY_ID is required with SIGNING_PRIVATE_KEY")
    seed = decode_private_seed(seed_b64)
    priv = Ed25519PrivateKey.from_private_bytes(seed)
    pub_raw = priv.public_key().public_bytes_raw()
    existing = session.get(SigningKey, key_id)
    if existing is None:
        session.add(
            SigningKey(
                key_id=key_id,
                public_key=pub_raw,
                private_key=seed,
                active=True,
                created_at=str(_now_ms()),
            )
        )
        session.flush()
    elif existing.public_key != pub_raw:
        raise RuntimeError(
            f"signing key {key_id!r} already exists with a different public key"
        )
    return ActiveKey(
        key_id=key_id, public_key=pub_raw, private_key=priv
    )


def rotate_key(session: Session) -> ActiveKey:
    """Generate a new active key; mark the previous active key inactive."""
    session.query(SigningKey).filter(SigningKey.active.is_(True)).update(
        {SigningKey.active: False}
    )
    key_id, priv_raw, pub_raw = _generate_key_material()
    session.add(
        SigningKey(
            key_id=key_id,
            public_key=pub_raw,
            private_key=priv_raw,
            active=True,
            created_at=str(_now_ms()),
        )
    )
    session.flush()
    return ActiveKey(
        key_id=key_id,
        public_key=pub_raw,
        private_key=Ed25519PrivateKey.from_private_bytes(priv_raw),
    )


def sign_sth(
    key: ActiveKey, tree_size: int, root_hash: bytes, timestamp_ms: int
) -> bytes:
    return key.private_key.sign(
        sth_input_bytes(tree_size, root_hash, timestamp_ms)
    )
