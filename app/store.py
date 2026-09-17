"""Tenant-scoped append store with RFC 9162 materialised Merkle nodes."""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import crypto, merkle
from .models import Leaf, MerkleNode, SigningKey, Tenant, TreeHead


class IdempotencyConflict(Exception):
    """Same idempotency key reused with different leaf content (HTTP 409)."""


class NotFound(Exception):
    pass


@dataclass(frozen=True)
class AppendResult:
    leaf_index: int
    leaf_hash: bytes
    leaf_input: bytes
    tree_size: int
    root_hash: bytes
    key_id: str
    timestamp_ms: int
    signature: bytes
    duplicate: bool


def _now_ms() -> int:
    return time.time_ns() // 1_000_000


class Store:
    def __init__(self, session: Session):
        self.session = session

    # ------------------------------------------------------------------
    # Tenants
    # ------------------------------------------------------------------

    def lock_or_create_tenant(self, tenant_id: str) -> Tenant:
        """Serialise all appends for a tenant on its row (SELECT FOR UPDATE).

        Different tenants use different rows, so appends across tenants do
        not block each other.
        """
        tenant = self.session.get(Tenant, tenant_id, with_for_update=True)
        if tenant is None:
            # Insert; if a concurrent transaction won, lock its row instead.
            tenant = Tenant(tenant_id=tenant_id, tree_size=0)
            self.session.add(tenant)
            try:
                self.session.flush()
            except IntegrityError:
                self.session.rollback()
                tenant = self.session.get(
                    Tenant, tenant_id, with_for_update=True
                )
                if tenant is None:  # pragma: no cover
                    raise
        return tenant

    def get_or_create_tenant(self, tenant_id: str) -> Tenant:
        tenant = self.session.get(Tenant, tenant_id)
        if tenant is None:
            tenant = Tenant(tenant_id=tenant_id, tree_size=0)
            self.session.add(tenant)
            try:
                self.session.flush()
            except IntegrityError:
                self.session.rollback()
                tenant = self.session.get(Tenant, tenant_id)
                if tenant is None:  # pragma: no cover
                    raise
        return tenant

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        return self.session.get(Tenant, tenant_id)

    # ------------------------------------------------------------------
    # Appends
    # ------------------------------------------------------------------

    def append(
        self,
        tenant_id: str,
        leaf_input: bytes,
        idempotency_key: str,
    ) -> AppendResult:
        leaf_h = merkle.leaf_hash(leaf_input)
        tenant = self.lock_or_create_tenant(tenant_id)

        existing = self._find_idempotent(tenant_id, idempotency_key)
        if existing is not None:
            if existing.leaf_hash != leaf_h:
                raise IdempotencyConflict(idempotency_key)
            return self._append_result(existing, tenant, duplicate=True)

        index = tenant.tree_size
        self.session.add(
            Leaf(
                tenant_id=tenant_id,
                leaf_index=index,
                leaf_hash=leaf_h,
                leaf_input=leaf_input,
                idempotency_key=idempotency_key,
            )
        )
        self._materialise_on_append(tenant_id, index, leaf_h)
        tenant.tree_size = index + 1
        self.session.flush()

        leaf_row = self._get_leaf_or_raise(tenant_id, index)
        return self._append_result(leaf_row, tenant, duplicate=False)

    def _find_idempotent(self, tenant_id: str, key: str) -> Leaf | None:
        return (
            self.session.query(Leaf)
            .filter(Leaf.tenant_id == tenant_id, Leaf.idempotency_key == key)
            .one_or_none()
        )

    def _materialise_on_append(
        self, tenant_id: str, index: int, leaf_h: bytes
    ) -> None:
        """Write the new internal nodes created by appending ``index``.

        Following RFC §2.1.2: leaf index i merges its node-stack ``trailing
        1-bits of i`` times. The node created at each merge covers a perfect
        subtree of size 2^level whose left edge is (index+1 - 2^level).
        Level-0 rows live in the leaves table, so only levels >= 1 are
        stored here.
        """
        # RFC §2.1.2: leaf index i triggers popcount(trailing-1-bits of i)
        # merges. Merge t (0-based) creates a node of span 2^(t+1) whose
        # left edge is (index + 1 - 2^(t+1)); position depends on the
        # original leaf index, the loop condition only walks its bits.
        self.session.flush()  # make the new level-0 leaf queryable
        # Hashes produced during this append are kept locally so the merge
        # chain needs no extra database round-trips.
        fresh: dict[tuple[int, int], bytes] = {(index, 1): leaf_h}

        def lookup(pos: int, block: int) -> bytes:
            cached = fresh.get((pos, block))
            return cached if cached is not None else self._aligned_hash(
                tenant_id, pos, block
            )

        bits = index
        span = 2
        while bits & 1:
            left_index = index + 1 - span
            right_index = index + 1 - span // 2
            parent = merkle.node_hash(
                lookup(left_index, span // 2),
                lookup(right_index, span // 2),
            )
            self.session.add(
                MerkleNode(
                    tenant_id=tenant_id,
                    left_index=left_index,
                    level=span.bit_length() - 1,
                    node_hash=parent,
                )
            )
            fresh[(left_index, span)] = parent
            bits >>= 1
            span <<= 1

    # ------------------------------------------------------------------
    # Reads / proofs
    # ------------------------------------------------------------------

    def get_leaf(self, tenant_id: str, index: int) -> Leaf:
        tenant = self.get_tenant(tenant_id)
        if tenant is None or index < 0 or index >= tenant.tree_size:
            raise NotFound("leaf not found")
        return self._get_leaf_or_raise(tenant_id, index)

    def _get_leaf_or_raise(self, tenant_id: str, index: int) -> Leaf:
        row = (
            self.session.query(Leaf)
            .filter(Leaf.tenant_id == tenant_id, Leaf.leaf_index == index)
            .one_or_none()
        )
        if row is None:
            raise NotFound(f"leaf {index} not found")
        return row

    def root_at_size(self, tenant_id: str, tree_size: int) -> bytes:
        if tree_size == 0:
            return merkle.EMPTY_HASH
        tenant = self.get_tenant(tenant_id)
        if tenant is None or tree_size > tenant.tree_size:
            raise NotFound("tree size beyond current tree head")
        return merkle.range_root(
            lambda idx, block: self._aligned_hash(tenant_id, idx, block),
            0,
            tree_size,
        )

    def current_root(self, tenant: Tenant) -> bytes:
        return self.root_at_size(tenant.tenant_id, tenant.tree_size)

    def inclusion_proof(
        self, tenant_id: str, leaf_index: int, tree_size: int
    ) -> list[bytes]:
        tenant = self.get_tenant(tenant_id)
        if tenant is None:
            raise NotFound("tenant not found")
        if tree_size < 1 or tree_size > tenant.tree_size:
            raise NotFound("tree size unavailable")
        if leaf_index < 0 or leaf_index >= tree_size:
            raise NotFound("leaf not present at the requested tree size")

        def provider(index: int, size: int) -> bytes:
            return merkle.range_root(
                lambda idx, block: self._aligned_hash(tenant_id, idx, block),
                index,
                size,
            )

        return merkle.inclusion_proof(provider, leaf_index, tree_size)

    def consistency_proof(
        self, tenant_id: str, first: int, second: int
    ) -> list[bytes]:
        tenant = self.get_tenant(tenant_id)
        if tenant is None:
            raise NotFound("tenant not found")
        if first < 1 or second < first or second > tenant.tree_size:
            raise NotFound("requested tree sizes unavailable")
        if first == second:
            return []

        def provider(index: int, size: int) -> bytes:
            return merkle.range_root(
                lambda idx, block: self._aligned_hash(tenant_id, idx, block),
                index,
                size,
            )

        return merkle.consistency_proof(provider, first, second)

    def _aligned_hash(
        self, tenant_id: str, index: int, block: int) -> bytes:
        """Hash of the aligned perfect subtree at (index, block=2^level)."""
        if not merkle.is_power_of_two(block):
            raise ValueError("block must be a power of two")
        if block == 1:
            row = (
                self.session.query(Leaf.leaf_hash)
                .filter(
                    Leaf.tenant_id == tenant_id, Leaf.leaf_index == index
                )
                .one()
            )
            return row[0]
        level = block.bit_length() - 1
        row = (
            self.session.query(MerkleNode.node_hash)
            .filter(
                MerkleNode.tenant_id == tenant_id,
                MerkleNode.left_index == index,
                MerkleNode.level == level,
            )
            .one()
        )
        return row[0]

    # ------------------------------------------------------------------
    # Signed tree heads
    # ------------------------------------------------------------------

    def get_or_sign_sth(self, tenant_id: str, tree_size: int) -> TreeHead:
        tenant = self.get_tenant(tenant_id)
        if tenant is None or tree_size < 0 or tree_size > tenant.tree_size:
            raise NotFound("tree size unavailable")

        sth = (
            self.session.query(TreeHead)
            .filter(
                TreeHead.tenant_id == tenant_id, TreeHead.tree_size == tree_size
            )
            .one_or_none()
        )
        if sth is not None:
            return sth

        root_hash = self.root_at_size(tenant_id, tree_size)
        active = crypto.get_active_key(self.session)
        timestamp_ms = _now_ms()
        signature = crypto.sign_sth(active, tree_size, root_hash, timestamp_ms)
        sth = TreeHead(
            tenant_id=tenant_id,
            tree_size=tree_size,
            root_hash=root_hash,
            key_id=active.key_id,
            signature=signature,
            timestamp_ms=timestamp_ms,
        )
        self.session.add(sth)
        try:
            self.session.flush()
        except IntegrityError:
            # Another concurrent request signed this exact size first.
            self.session.rollback()
            sth = (
                self.session.query(TreeHead)
                .filter(
                    TreeHead.tenant_id == tenant_id,
                    TreeHead.tree_size == tree_size,
                )
                .one()
            )
        return sth

    def current_sth(self, tenant_id: str) -> TreeHead:
        tenant = self.get_tenant(tenant_id)
        if tenant is None:
            raise NotFound("tenant not found")
        return self.get_or_sign_sth(tenant_id, tenant.tree_size)

    def _append_result(
        self, leaf: Leaf, tenant: Tenant, duplicate: bool
    ) -> AppendResult:
        tree_size = leaf.leaf_index + 1
        sth = self.get_or_sign_sth(tenant.tenant_id, tree_size)
        return AppendResult(
            leaf_index=leaf.leaf_index,
            leaf_hash=leaf.leaf_hash,
            leaf_input=leaf.leaf_input,
            tree_size=tree_size,
            root_hash=sth.root_hash,
            key_id=sth.key_id,
            timestamp_ms=sth.timestamp_ms,
            signature=sth.signature,
            duplicate=duplicate,
        )

    # ------------------------------------------------------------------
    # Keys
    # ------------------------------------------------------------------

    def list_keys(self) -> list[SigningKey]:
        return list(self.session.query(SigningKey).order_by(SigningKey.created_at))

    def get_public_key(self, key_id: str) -> SigningKey:
        row = self.session.get(SigningKey, key_id)
        if row is None:
            raise NotFound("unknown key id")
        return row

    def rotate_key(self) -> SigningKey:
        active = crypto.rotate_key(self.session)
        self.session.flush()
        return self.session.get(SigningKey, active.key_id)


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")
