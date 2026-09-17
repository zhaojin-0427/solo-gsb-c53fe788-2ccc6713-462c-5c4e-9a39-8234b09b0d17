"""RFC 9162 (obsoletes RFC 6962) Merkle tree primitives.

All hashing uses SHA-256:
  leaf hash = HASH(0x00 || leaf_input)
  node hash = HASH(0x01 || left || right)
  empty     = HASH()

The pure generators/verifiers in this module only need a ``HashProvider``
callable ``subtree_hash(index, size)`` that returns the MTH of the (possibly
non-power-of-two) interval leaves[index : index+size]; they never touch a
database.
"""

from __future__ import annotations

import hashlib
from typing import Callable, List

EMPTY_HASH = hashlib.sha256(b"").digest()

HashProvider = Callable[[int, int], bytes]


def leaf_hash(leaf_input: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + leaf_input).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def is_power_of_two(x: int) -> bool:
    return x > 0 and (x & (x - 1)) == 0


def largest_power_of_two_less_than(n: int) -> int:
    """Largest power of two strictly smaller than n (n > 1)."""
    return 1 << ((n - 1).bit_length() - 1)


def mth(leaf_inputs: List[bytes]) -> bytes:
    """Reference MTH computation straight from the RFC recursion."""
    n = len(leaf_inputs)
    if n == 0:
        return EMPTY_HASH
    if n == 1:
        return leaf_hash(leaf_inputs[0])
    k = largest_power_of_two_less_than(n)
    return node_hash(mth(leaf_inputs[:k]), mth(leaf_inputs[k:]))


def root_from_hashes(leaf_hashes: List[bytes]) -> bytes:
    """MTH given already-computed leaf hashes (RFC 2.1.2 stack algorithm)."""
    stack: List[bytes] = []
    for i, lh in enumerate(leaf_hashes):
        stack.append(lh)
        merge_count = (i ^ (i + 1)).bit_length() - 1  # trailing 1 bits of i
        for _ in range(merge_count):
            right = stack.pop()
            left = stack.pop()
            stack.append(node_hash(left, right))
    while len(stack) > 1:
        right = stack.pop()
        left = stack.pop()
        stack.append(node_hash(left, right))
    return stack[0] if stack else EMPTY_HASH


def range_root(aligned: Callable[[int, int], bytes], start: int, size: int) -> bytes:
    """MTH of an arbitrary leaf interval [start, start+size).

    ``aligned(index, block)`` returns the hash of the aligned perfect subtree
    leaves[index : index+block] (block a power of two, index a multiple of
    block) -- exactly the rows materialised in the database.

    Decomposition follows the RFC MTH recursion (k = largest power of two
    strictly smaller than length) applied to an arbitrary contiguous
    sub-range of the global tree:

      rec(p, 1)            -> leaf-level lookup aligned(p, 1)
      rec(p, n) aligned    -> aligned(p, n)            (single lookup)
      rec(p, n) otherwise  -> node(rec(p, k), rec(p+k, n-k))

    Every leaf/base case lands on an aligned perfect subtree of the global
    tree: a subtree reached via right branches keeps length <= k while its
    position advances in multiples of k, shrinking until it becomes an
    aligned perfect block. The number of aligned lookups is bounded by
    O(log size).
    """

    def rec(p: int, length: int) -> bytes:
        if length == 0:
            return EMPTY_HASH
        if length == 1 or (
            is_power_of_two(length) and (p == 0 or p % length == 0)
        ):
            return aligned(p, length)
        k = largest_power_of_two_less_than(length)
        return node_hash(rec(p, k), rec(p + k, length - k))

    return rec(start, size)


# ---------------------------------------------------------------------------
# Inclusion proofs (RFC 9162 §2.1.3)
# ---------------------------------------------------------------------------


def inclusion_proof(provider: HashProvider, leaf_index: int, tree_size: int) -> List[bytes]:
    """PATH(leaf_index, D_tree_size) via the RFC recursion."""
    if not (0 <= leaf_index < tree_size):
        raise ValueError("leaf_index out of range")

    def gen(m: int, start: int, n: int) -> List[bytes]:
        if n == 1:
            return []
        k = largest_power_of_two_less_than(n)
        if m < k:
            return gen(m, start, k) + [provider(start + k, n - k)]
        return gen(m - k, start + k, n - k) + [provider(start, k)]

    return gen(leaf_index, 0, tree_size)


def verify_inclusion(
    leaf_h: bytes,
    leaf_index: int,
    tree_size: int,
    proof: List[bytes],
    root: bytes,
) -> bool:
    """Stateless inclusion proof verifier, RFC 9162 §2.1.3.2."""
    if tree_size <= 0 or leaf_index < 0 or leaf_index >= tree_size:
        return False

    fn = leaf_index
    sn = tree_size - 1
    r = leaf_h

    for p in proof:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            r = node_hash(p, r)
            if not (fn & 1):
                # §4.b.ii: shift until LSB(fn) is set or fn becomes 1.
                # Stopping at 1 (not 0) matters because §4.c shifts once more.
                while (fn & 1) == 0 and fn > 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1

    return sn == 0 and r == root

# ---------------------------------------------------------------------------
# Consistency proofs (RFC 9162 §2.1.4)
# ---------------------------------------------------------------------------


def consistency_proof(provider: HashProvider, first: int, second: int) -> List[bytes]:
    """PROOF(first, D_second) = SUBPROOF(first, D_second, true)."""
    if not (0 < first <= second):
        raise ValueError("require 0 < first <= second")
    if first == second:
        return []

    def sub(m: int, start: int, n: int, b: bool) -> List[bytes]:
        if m == n:
            return [] if b else [provider(start, n)]
        k = largest_power_of_two_less_than(n)
        if m <= k:
            return sub(m, start, k, b) + [provider(start + k, n - k)]
        return sub(m - k, start + k, n - k, False) + [provider(start, k)]

    return sub(first, 0, second, True)


def verify_consistency(
    first: int,
    second: int,
    proof: List[bytes],
    first_hash: bytes,
    second_hash: bytes,
) -> bool:
    """Stateless consistency proof verifier, RFC 9162 §2.1.4.2."""
    if first <= 0 or second < first:
        return False
    if first == second:
        # A tree is trivially consistent with itself; no nodes needed.
        return not proof and first_hash == second_hash
    if not proof:
        return False

    path = list(proof)
    if is_power_of_two(first):
        path = [first_hash] + path

    fn = first - 1
    sn = second - 1

    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not (fn & 1):
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1

    return sn == 0 and fr == first_hash and sr == second_hash
