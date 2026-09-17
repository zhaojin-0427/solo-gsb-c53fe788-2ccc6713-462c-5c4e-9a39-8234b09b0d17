from typing import Any, Literal, Optional

from pydantic import BaseModel, Field


class AppendEntryRequest(BaseModel):
    idempotency_key: str = Field(min_length=1, max_length=512)
    claim: dict[str, Any]
    revokes_leaf_index: Optional[int] = Field(default=None, ge=0)


class AppendEntryResponse(BaseModel):
    leaf_index: int
    leaf_hash: str  # base64
    leaf_input: str  # base64 JCS envelope bytes
    tree_size: int
    root_hash: str  # base64
    timestamp_ms: int
    key_id: str
    signature: str  # base64
    duplicate: bool


class LeafResponse(BaseModel):
    leaf_index: int
    leaf_hash: str
    leaf_input: str
    idempotency_key: str
    envelope: dict[str, Any]


class TreeHeadResponse(BaseModel):
    tree_size: int
    root_hash: str
    timestamp_ms: int
    key_id: str
    signature: str


class InclusionProofResponse(BaseModel):
    leaf_index: int
    tree_size: int
    leaf_hash: str
    root_hash: str
    inclusion_path: list[str]


class ConsistencyProofResponse(BaseModel):
    first_tree_size: int
    second_tree_size: int
    first_root_hash: str
    second_root_hash: str
    consistency_path: list[str]


class VerifyInclusionRequest(BaseModel):
    leaf_input: str  # base64 JCS envelope
    leaf_index: int
    tree_size: int
    inclusion_path: list[str]
    root_hash: str


class VerifyConsistencyRequest(BaseModel):
    first_tree_size: int
    second_tree_size: int
    consistency_path: list[str]
    first_root_hash: str
    second_root_hash: str


class VerificationResult(BaseModel):
    valid: bool
    reason: Optional[str] = None


class PublicKeyResponse(BaseModel):
    key_id: str
    public_key: str  # base64
    active: bool
    created_at: str


class RotateKeyResponse(BaseModel):
    previous_active_key_id: Optional[str]
    key_id: str
    public_key: str
    active: Literal[True] = True


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
