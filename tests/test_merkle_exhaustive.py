"""Exhaustive property checks for merkle.py against the RFC reference MTH."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import merkle

MAX_N = 300


def main() -> None:
    data = [os.urandom(40) for _ in range(MAX_N)]
    hashes = [merkle.leaf_hash(d) for d in data]

    # Precompute MTH for every prefix.
    prefix_root = [b""] * (MAX_N + 1)
    for n in range(MAX_N + 1):
        prefix_root[n] = merkle.mth(data[:n])
        assert merkle.root_from_hashes(hashes[:n]) == prefix_root[n], n

    # In-memory interval-MTH provider (generator asks for arbitrary
    # intervals; range_root decomposes them into aligned lookups).
    def make_provider(n):
        aligned = make_aligned(n)

        def provider(index, size):
            assert size > 0 and index + size <= n
            return merkle.range_root(aligned, index, size)

        return provider

    # Aligned-subtree provider for range_root.
    def make_aligned(n):
        def aligned(index, block):
            assert merkle.is_power_of_two(block) and index % block == 0
            assert index + block <= n
            return merkle.root_from_hashes(hashes[index : index + block])

        return aligned

    # Inclusion proofs for every leaf of every prefix tree.
    for n in range(1, MAX_N + 1):
        provider = make_provider(n)
        for m in range(n):
            path = merkle.inclusion_proof(provider, m, n)
            assert len(path) <= n.bit_length(), (n, m, len(path))
            assert merkle.verify_inclusion(
                hashes[m], m, n, path, prefix_root[n]
            ), (n, m)
            # Wrong leaf must fail.
            wrong = os.urandom(32)
            assert not merkle.verify_inclusion(wrong, m, n, path, prefix_root[n])
            # Wrong index must fail (unless proof coincidentally works).
            if m + 1 < n:
                assert not merkle.verify_inclusion(
                    hashes[m], m + 1, n, path, prefix_root[n]
                )
            # Corrupt a proof element.
            if path:
                bad = list(path)
                bad[0] = os.urandom(32)
                assert not merkle.verify_inclusion(
                    hashes[m], m, n, bad, prefix_root[n]
                )

    # Consistency proofs for every 0 < m < n pair.
    for second in range(2, MAX_N + 1):
        provider = make_provider(second)
        for first in range(1, second):
            path = merkle.consistency_proof(provider, first, second)
            assert path, (first, second)
            assert merkle.verify_consistency(
                first, second, path, prefix_root[first], prefix_root[second]
            ), (first, second)
            # Old root tampered -> fail.
            assert not merkle.verify_consistency(
                first, second, path, os.urandom(32), prefix_root[second]
            )
        # first == second: trivial, empty proof, equal roots.
        assert merkle.verify_consistency(
            second, second, [], prefix_root[second], prefix_root[second]
        )
        assert not merkle.verify_consistency(
            second, second, [], prefix_root[second], os.urandom(32)
        )

    # range_root must reproduce the MTH for every interval of every small n.
    for n in range(1, 130):
        aligned = make_aligned(n)
        for start in range(n):
            for size in range(1, n - start + 1):
                got = merkle.range_root(aligned, start, size)
                want = merkle.root_from_hashes(hashes[start : start + size])
                assert got == want, (start, size)

    print(f"OK: all Merkle checks passed for n up to {MAX_N}")


if __name__ == "__main__":
    main()
