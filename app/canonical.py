"""JCS (RFC 8785) canonicalisation and Merkle leaf construction.

A claim submitted by a client is canonicalised with JCS; signatures and
hashes always operate on those canonical bytes, so whitespace and object
key ordering can never cause two serialisations of the same claim to differ.

Merkle leaf inputs are versioned envelopes canonicalised with JCS::

    {
      "version": 1,
      "type": "build-artifact-claim",
      "claim": <the client's JSON object>,
      "revokes_leaf_index": <int or absent>
    }

Leaf hash = SHA256(0x00 || JCS(envelope)).

Revocations never modify history: a revocation is simply a new envelope
whose ``revokes_leaf_index`` points at the leaf being revoked.
"""

from __future__ import annotations

from typing import Any

import jcs

LEAF_VERSION = 1
LEAF_TYPE = "build-artifact-claim"
REVOCATION_TYPE = "build-artifact-revocation"


class CanonicalizationError(ValueError):
    pass


def canonicalize(value: Any) -> bytes:
    """Return JCS (RFC 8785) canonical bytes for a JSON-compatible value."""
    try:
        return jcs.canonicalize(value)
    except Exception as exc:  # the C extension raises generic errors
        raise CanonicalizationError(str(exc)) from exc


def build_leaf_input(claim: dict[str, Any], revokes_leaf_index: int | None) -> bytes:
    if not isinstance(claim, dict):
        raise ValueError("claim must be a JSON object")
    envelope: dict[str, Any] = {
        "version": LEAF_VERSION,
        "type": LEAF_TYPE,
        "claim": claim,
    }
    if revokes_leaf_index is not None:
        if revokes_leaf_index < 0:
            raise ValueError("revokes_leaf_index must be non-negative")
        envelope["type"] = REVOCATION_TYPE
        envelope["revokes_leaf_index"] = revokes_leaf_index
    return canonicalize(envelope)
