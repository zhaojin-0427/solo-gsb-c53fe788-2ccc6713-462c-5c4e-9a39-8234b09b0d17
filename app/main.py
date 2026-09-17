import base64
import json
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import canonical, crypto, merkle
from .canonical import CanonicalizationError
from .config import get_settings
from .db import SessionLocal, init_db
from .models import Tenant
from .schemas import (
    AppendEntryRequest,
    AppendEntryResponse,
    ConsistencyProofResponse,
    InclusionProofResponse,
    LeafResponse,
    PublicKeyResponse,
    RotateKeyResponse,
    TreeHeadResponse,
    VerificationResult,
    VerifyConsistencyRequest,
    VerifyInclusionRequest,
)
from .store import IdempotencyConflict, NotFound, Store, b64


def b64decode_required(encoded: str, what: str) -> bytes:
    try:
        return base64.b64decode(encoded.encode("ascii"), validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail=f"{what} is not valid base64")


def get_session() -> Session:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def require_tenant(x_tenant_id: str | None) -> str:
    if not x_tenant_id:
        raise HTTPException(
            status_code=400, detail="missing X-Tenant-ID header"
        )
    if len(x_tenant_id) > 256:
        raise HTTPException(status_code=400, detail="tenant id too long")
    return x_tenant_id


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    # Seed the optional env-configured signing key.
    settings = get_settings()
    if settings.signing_private_key:
        with SessionLocal() as session:
            crypto.ensure_configured_key(
                session,
                settings.signing_key_id,
                settings.signing_private_key,
            )
            session.commit()
    yield


app = FastAPI(
    title="Build Artifact Transparency Log API",
    version="1.0.0",
    lifespan=lifespan,
)


@app.exception_handler(NotFound)
async def not_found_handler(request: Request, exc: NotFound) -> JSONResponse:
    return JSONResponse(
        status_code=404, content={"error": "not_found", "detail": str(exc)}
    )


@app.exception_handler(CanonicalizationError)
async def jcs_error_handler(
    request: Request, exc: CanonicalizationError
) -> JSONResponse:
    return JSONResponse(
        status_code=400,
        content={"error": "invalid_claim", "detail": f"JCS canonicalisation failed: {exc}"},
    )


@app.exception_handler(IntegrityError)
async def integrity_error_handler(
    request: Request, exc: IntegrityError
) -> JSONResponse:
    return JSONResponse(
        status_code=409,
        content={"error": "conflict", "detail": "concurrent write conflict; retry"},
    )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------


@app.post("/v1/entries", response_model=AppendEntryResponse, status_code=201)
def append_entry(
    body: AppendEntryRequest,
    response: Response,
    x_tenant_id: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> AppendEntryResponse:
    tenant_id = require_tenant(x_tenant_id)

    if body.revokes_leaf_index is not None:
        tenant = session.get(Tenant, tenant_id)
        if tenant is None or not (0 <= body.revokes_leaf_index < tenant.tree_size):
            raise HTTPException(
                status_code=409,
                detail=(
                    "revokes_leaf_index must reference an existing leaf at the "
                    "time the revocation is appended"
                ),
            )

    try:
        leaf_input = canonical.build_leaf_input(
            body.claim, body.revokes_leaf_index
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    store = Store(session)
    try:
        result = store.append(tenant_id, leaf_input, body.idempotency_key)
    except IdempotencyConflict:
        raise HTTPException(
            status_code=409,
            detail=(
                "idempotency key was already used with different content; "
                "reusing a key requires identical claim and revocation target"
            ),
        )
    session.commit()

    if result.duplicate:
        response.status_code = status.HTTP_200_OK
    else:
        response.status_code = status.HTTP_201_CREATED
    return AppendEntryResponse(
        leaf_index=result.leaf_index,
        leaf_hash=b64(result.leaf_hash),
        leaf_input=b64(result.leaf_input),
        tree_size=result.tree_size,
        root_hash=b64(result.root_hash),
        timestamp_ms=result.timestamp_ms,
        key_id=result.key_id,
        signature=b64(result.signature),
        duplicate=result.duplicate,
    )


@app.get("/v1/leaves/{leaf_index}", response_model=LeafResponse)
def get_leaf(
    leaf_index: int,
    x_tenant_id: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> LeafResponse:
    tenant_id = require_tenant(x_tenant_id)
    if leaf_index < 0:
        raise NotFound("leaf not found")
    leaf = Store(session).get_leaf(tenant_id, leaf_index)
    return LeafResponse(
        leaf_index=leaf.leaf_index,
        leaf_hash=b64(leaf.leaf_hash),
        leaf_input=b64(leaf.leaf_input),
        idempotency_key=leaf.idempotency_key,
        envelope=json.loads(leaf.leaf_input.decode("utf-8")),
    )


# ---------------------------------------------------------------------------
# Tree heads and proofs
# ---------------------------------------------------------------------------


@app.get("/v1/tree-head", response_model=TreeHeadResponse)
def get_current_tree_head(
    tree_size: int | None = None,
    x_tenant_id: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> TreeHeadResponse:
    tenant_id = require_tenant(x_tenant_id)
    store = Store(session)
    # An empty tree also has a signed tree head, so auto-create the tenant.
    tenant = store.get_or_create_tenant(tenant_id)
    target = tenant.tree_size if tree_size is None else tree_size
    if target < 0:
        raise HTTPException(status_code=400, detail="tree_size must be >= 0")
    sth = store.get_or_sign_sth(tenant_id, target)
    session.commit()
    return _sth_response(sth)


def _sth_response(sth) -> TreeHeadResponse:
    return TreeHeadResponse(
        tree_size=sth.tree_size,
        root_hash=b64(sth.root_hash),
        timestamp_ms=sth.timestamp_ms,
        key_id=sth.key_id,
        signature=b64(sth.signature),
    )


@app.get("/v1/proofs/inclusion", response_model=InclusionProofResponse)
def get_inclusion_proof(
    leaf_index: int,
    tree_size: int,
    x_tenant_id: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> InclusionProofResponse:
    tenant_id = require_tenant(x_tenant_id)
    store = Store(session)
    path = store.inclusion_proof(tenant_id, leaf_index, tree_size)
    leaf = store.get_leaf(tenant_id, leaf_index)
    root = store.root_at_size(tenant_id, tree_size)
    return InclusionProofResponse(
        leaf_index=leaf_index,
        tree_size=tree_size,
        leaf_hash=b64(leaf.leaf_hash),
        root_hash=b64(root),
        inclusion_path=[b64(p) for p in path],
    )


@app.get("/v1/proofs/consistency", response_model=ConsistencyProofResponse)
def get_consistency_proof(
    first_tree_size: int,
    second_tree_size: int,
    x_tenant_id: str | None = Header(default=None),
    session: Session = Depends(get_session),
) -> ConsistencyProofResponse:
    tenant_id = require_tenant(x_tenant_id)
    if first_tree_size < 1:
        raise HTTPException(
            status_code=400,
            detail="consistency proofs require first_tree_size >= 1",
        )
    if second_tree_size < first_tree_size:
        raise HTTPException(
            status_code=400,
            detail="second_tree_size must be >= first_tree_size",
        )
    store = Store(session)
    path = store.consistency_proof(
        tenant_id, first_tree_size, second_tree_size
    )
    first_root = store.root_at_size(tenant_id, first_tree_size)
    second_root = store.root_at_size(tenant_id, second_tree_size)
    return ConsistencyProofResponse(
        first_tree_size=first_tree_size,
        second_tree_size=second_tree_size,
        first_root_hash=b64(first_root),
        second_root_hash=b64(second_root),
        consistency_path=[b64(p) for p in path],
    )


# ---------------------------------------------------------------------------
# Stateless verification (never touches the database)
# ---------------------------------------------------------------------------


@app.post("/v1/verify/inclusion", response_model=VerificationResult)
def verify_inclusion(body: VerifyInclusionRequest) -> VerificationResult:
    leaf_input = b64decode_required(body.leaf_input, "leaf_input")
    root = b64decode_required(body.root_hash, "root_hash")
    if len(root) != 32:
        return VerificationResult(valid=False, reason="root_hash must be 32 bytes")
    path = []
    for i, p in enumerate(body.inclusion_path):
        node = b64decode_required(p, f"inclusion_path[{i}]")
        if len(node) != 32:
            return VerificationResult(
                valid=False, reason=f"inclusion_path[{i}] must be 32 bytes"
            )
        path.append(node)
    leaf_h = merkle.leaf_hash(leaf_input)
    valid = merkle.verify_inclusion(
        leaf_h, body.leaf_index, body.tree_size, path, root
    )
    if not valid:
        return VerificationResult(
            valid=False, reason="inclusion proof does not verify against root"
        )
    return VerificationResult(valid=True)


@app.post("/v1/verify/consistency", response_model=VerificationResult)
def verify_consistency(body: VerifyConsistencyRequest) -> VerificationResult:
    first_root = b64decode_required(body.first_root_hash, "first_root_hash")
    second_root = b64decode_required(body.second_root_hash, "second_root_hash")
    if len(first_root) != 32 or len(second_root) != 32:
        return VerificationResult(valid=False, reason="root hashes must be 32 bytes")
    path = []
    for i, p in enumerate(body.consistency_path):
        node = b64decode_required(p, f"consistency_path[{i}]")
        if len(node) != 32:
            return VerificationResult(
                valid=False, reason=f"consistency_path[{i}] must be 32 bytes"
            )
        path.append(node)
    valid = merkle.verify_consistency(
        body.first_tree_size,
        body.second_tree_size,
        path,
        first_root,
        second_root,
    )
    if not valid:
        return VerificationResult(
            valid=False, reason="consistency proof does not verify"
        )
    return VerificationResult(valid=True)


@app.post("/v1/verify/tree-head", response_model=VerificationResult)
def verify_tree_head(
    tree_size: int,
    root_hash: str,
    timestamp_ms: int,
    signature: str,
    public_key: str,
) -> VerificationResult:
    """Verify an STH Ed25519 signature with the caller-supplied public key."""
    root = b64decode_required(root_hash, "root_hash")
    sig = b64decode_required(signature, "signature")
    pub = b64decode_required(public_key, "public_key")
    if len(root) != 32:
        return VerificationResult(valid=False, reason="root_hash must be 32 bytes")
    if len(sig) != 64:
        return VerificationResult(valid=False, reason="Ed25519 signature must be 64 bytes")
    if len(pub) != 32:
        return VerificationResult(valid=False, reason="Ed25519 public key must be 32 bytes")
    valid = crypto.verify_sth_signature(
        pub, tree_size, root, timestamp_ms, sig
    )
    return VerificationResult(
        valid=valid,
        reason=None if valid else "tree head signature does not verify",
    )


# ---------------------------------------------------------------------------
# Signing keys
# ---------------------------------------------------------------------------


@app.get("/v1/keys", response_model=list[PublicKeyResponse])
def list_keys(session: Session = Depends(get_session)) -> list[PublicKeyResponse]:
    return [
        PublicKeyResponse(
            key_id=k.key_id,
            public_key=b64(k.public_key),
            active=k.active,
            created_at=k.created_at,
        )
        for k in Store(session).list_keys()
    ]


@app.get("/v1/keys/{key_id}", response_model=PublicKeyResponse)
def get_key(key_id: str, session: Session = Depends(get_session)) -> PublicKeyResponse:
    k = Store(session).get_public_key(key_id)
    return PublicKeyResponse(
        key_id=k.key_id,
        public_key=b64(k.public_key),
        active=k.active,
        created_at=k.created_at,
    )


@app.post("/v1/keys/rotate", response_model=RotateKeyResponse, status_code=201)
def rotate_key(
    session: Session = Depends(get_session),
) -> RotateKeyResponse:
    store = Store(session)
    previous = next(
        (k for k in store.list_keys() if k.active), None
    )
    new_key = store.rotate_key()
    session.commit()
    return RotateKeyResponse(
        previous_active_key_id=previous.key_id if previous else None,
        key_id=new_key.key_id,
        public_key=b64(new_key.public_key),
        active=True,
    )
