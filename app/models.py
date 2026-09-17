from sqlalchemy import (
    BigInteger,
    Boolean,
    ForeignKey,
    Index,
    LargeBinary,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"

    # Opaque tenant identifier supplied by the client (X-Tenant-ID header).
    tenant_id: Mapped[str] = mapped_column(String(256), primary_key=True)
    tree_size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    leaves: Mapped[list["Leaf"]] = relationship(back_populates="tenant")


class SigningKey(Base):
    """Ed25519 keys. Old keys are never deleted so historic STHs stay verifiable."""

    __tablename__ = "signing_keys"

    key_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    private_key: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[str] = mapped_column(String(40), nullable=False)


class Leaf(Base):
    __tablename__ = "leaves"
    __table_args__ = (
        UniqueConstraint("tenant_id", "leaf_index", name="uq_leaves_tenant_index"),
        Index("ix_leaves_tenant_idem", "tenant_id", "idempotency_key", unique=True),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id"), nullable=False
    )
    leaf_index: Mapped[int] = mapped_column(BigInteger, nullable=False)
    leaf_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    # JCS-canonical bytes of the signed leaf input (the leaf structure).
    leaf_input: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(512), nullable=False)

    tenant: Mapped[Tenant] = relationship(back_populates="leaves")


class MerkleNode(Base):
    """Materialised internal Merkle nodes, Trillian-style.

    A row stores the hash of the perfect subtree of length 2^level covering
    leaves [left_index, left_index + 2^level). level 0 rows are *not* stored
    here; leaves live in the leaves table.
    """

    __tablename__ = "merkle_nodes"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id", "left_index", "level", name="uq_nodes_tenant_left_level"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id"), nullable=False
    )
    left_index: Mapped[int] = mapped_column(BigInteger, nullable=False)
    level: Mapped[int] = mapped_column(BigInteger, nullable=False)
    node_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)


class TreeHead(Base):
    """Signed Tree Head (STH) per (tenant, tree_size). Immutable once written."""

    __tablename__ = "tree_heads"
    __table_args__ = (
        UniqueConstraint("tenant_id", "tree_size", name="uq_sth_tenant_size"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(
        ForeignKey("tenants.tenant_id"), nullable=False
    )
    tree_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    root_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    key_id: Mapped[str] = mapped_column(
        ForeignKey("signing_keys.key_id"), nullable=False
    )
    signature: Mapped[bytes] = mapped_column(LargeBinary(64), nullable=False)
    timestamp_ms: Mapped[int] = mapped_column(BigInteger, nullable=False)
