"""Generate an Ed25519 key pair for SIGNING_KEY_ID / SIGNING_PRIVATE_KEY.

Usage:  python scripts/generate_signing_key.py [key_id]
"""

import base64
import secrets
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def main() -> None:
    key_id = sys.argv[1] if len(sys.argv) > 1 else "key_" + secrets.token_hex(8)
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw()
    pub = priv.public_key().public_bytes_raw()
    print(f"SIGNING_KEY_ID={key_id}")
    print(f"SIGNING_PRIVATE_KEY={base64.b64encode(seed).decode()}")
    print(f"# public key (base64): {base64.b64encode(pub).decode()}")


if __name__ == "__main__":
    main()
