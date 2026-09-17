import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import canonical
from app.canonical import CanonicalizationError


def test_canonical_sort_and_roundtrip():
    a = canonical.canonicalize({"b": 2, "a": [3, 1, 2], "c": {"z": 0, "y": 1}})
    assert a == b'{"a":[3,1,2],"b":2,"c":{"y":1,"z":0}}'


def test_leaf_envelope_shape():
    env = canonical.build_leaf_input({"x": 1}, None)
    assert env == b'{"claim":{"x":1},"type":"build-artifact-claim","version":1}'
    rev = canonical.build_leaf_input({"x": 1}, 7)
    assert rev == (
        b'{"claim":{"x":1},"revokes_leaf_index":7,'
        b'"type":"build-artifact-revocation","version":1}'
    )


def test_negative_revocation_index_rejected():
    with pytest.raises(ValueError):
        canonical.build_leaf_input({"x": 1}, -1)


def test_non_finite_numbers_raise_canonicalization_error():
    with pytest.raises(CanonicalizationError):
        canonical.canonicalize({"x": float("nan")})
    with pytest.raises(CanonicalizationError):
        canonical.canonicalize({"x": float("inf")})


def test_claim_must_be_object():
    with pytest.raises(ValueError):
        canonical.build_leaf_input([1, 2, 3], None)
