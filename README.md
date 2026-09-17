# Build Artifact Transparency Log

A transparent, append-only log of build-artifact claims for release
pipelines. Clients submit artifact digests, build metadata and an
idempotency key; the service writes them into a per-tenant **Merkle tree**
following **RFC 9162** (which obsoletes RFC 6962) — leaf hashes
`SHA256(0x00 ‖ data)`, node hashes `SHA256(0x01 ‖ left ‖ right)`, empty tree
`SHA256("")`. Claims are canonicalised with **JCS (RFC 8785)** before
hashing, and every tree head is signed with **Ed25519**.

Built with Python 3.11, FastAPI and PostgreSQL; started with Docker Compose.

## Guarantees

- **Dense, gap-free sequence.** Concurrent appends for a tenant are
  serialised on the tenant row (`SELECT … FOR UPDATE`); leaf indices are
  `0,1,2,…` with no overwrites or lost writes. Different tenants use
  different rows and do not block each other.
- **Idempotency.** Replaying the same `idempotency_key` with identical
  content returns the original result (`200` + `duplicate: true`). The same
  key with different content is rejected with **409**; nothing is appended.
- **JCS canonical claims.** Key ordering and whitespace in the submitted
  JSON never affect the leaf hash.
- **Inclusion proofs** for any leaf at any (published) tree size and
  **consistency proofs** between any old and new tree head, both exactly as
  defined in RFC 9162 §2.1.3–2.1.4.
- **Stateless verification.** `POST /v1/verify/inclusion` and
  `POST /v1/verify/consistency` recompute hashes purely from the supplied
  proof and never read the database, so they can be run offline against any
  cached tree head.
- **Clear errors** for unknown tenants/leaves, out-of-range indices, and
  leaves that were not yet part of the chosen tree size (`404`/`400`).
- **Revocation appends a new claim** (`type: build-artifact-revocation`,
  `revokes_leaf_index: n`). Existing leaves and previously signed tree
  heads are never modified.
- **Signed tree heads with key rotation.** Each STH is signed by the active
  Ed25519 key. Rotation (`POST /v1/keys/rotate`) creates a new active key but
  keeps every old key, so historic signatures remain verifiable forever.

## Quick start with Docker Compose

```bash
cp .env.example .env          # optional: edit credentials / ports
docker compose up --build
```

- API: http://localhost:8080
- Interactive API docs (Swagger UI): http://localhost:8080/docs
- OpenAPI schema: http://localhost:8080/openapi.json
- PostgreSQL is exposed on host port 5432 by default (set `POSTGRES_PORT` to
  change, or remove the port mapping).

All requests for log data carry a tenant identifier in the
`X-Tenant-ID` header. Tenants are independent Merkle trees and are created
lazily on first use.

### Configuration (environment variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | (compose sets it) | `postgresql+psycopg2://user:pass@db:5432/dbname` |
| `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` | `artifactlog` | Database credentials |
| `API_PORT` | `8080` | Host port for the API |
| `POSTGRES_PORT` | `5432` | Host port for PostgreSQL |
| `SIGNING_KEY_ID` | _(empty)_ | Fix the initial Ed25519 key id |
| `SIGNING_PRIVATE_KEY` | _(empty)_ | Base64 of the 32-byte Ed25519 seed |

If no signing key is configured, the service generates one on first boot and
persists it in the database; fetch it from `GET /v1/keys`. To run a known
key across deployments, generate a pair and put both variables in `.env`:

```bash
python scripts/generate_signing_key.py key-prod-2026
# SIGNING_KEY_ID=key-prod-2026
# SIGNING_PRIVATE_KEY=<base64 32-byte seed>
```

## Data model

### Leaf envelope

The Merkle leaf input is the JCS canonical form of:

```json
{
  "version": 1,
  "type": "build-artifact-claim",
  "claim": { ...arbitrary client JSON object... }
}
```

A revocation uses:

```json
{
  "version": 1,
  "type": "build-artifact-revocation",
  "claim": { ...arbitrary client JSON object... },
  "revokes_leaf_index": 17
}
```

`leaf_hash = SHA256(0x00 ‖ JCS(envelope))`. It is recommended that `claim`
contain at least `artifact_digest` (e.g. `sha256:…`) and `build_metadata`
(job id, run id, committer, provenance links…), but any JSON object is
accepted.

### Signed tree head payload

The Ed25519 signature is over the unambiguous binary string:

```
"ARTIFACTLOG-STH-v1" ‖ uint64_be(tree_size) ‖ root_hash(32 bytes)
                     ‖ uint64_be(timestamp_ms)
```

`tree_size = 0` signs the empty-tree root `SHA256("")`.

## API

All hashes, proofs and keys are base64-encoded (`+`/`/`, standard padding).
Errors are JSON: `{"error": "...", "detail": "..."}`.

### Append a claim

```bash
curl -sS -X POST http://localhost:8080/v1/entries \
  -H 'X-Tenant-ID: team-payments' \
  -H 'Content-Type: application/json' \
  -d '{
        "idempotency_key": "build-4821",
        "claim": {
          "artifact_digest": "sha256:9f1b…",
          "build_metadata": {"job": "release", "run_id": 4821}
        }
      }'
```

Response `201 Created` (or `200 OK` for an idempotent replay):

```json
{
  "leaf_index": 0,
  "leaf_hash": "…",
  "leaf_input": "…",
  "tree_size": 1,
  "root_hash": "…",
  "timestamp_ms": 1789000000000,
  "key_id": "key_990ec2f486963d0e",
  "signature": "…",
  "duplicate": false
}
```

Replaying the exact body with the same `idempotency_key` returns
`duplicate: true` with the same `leaf_index`/`tree_size`. A different body
with the same key returns **409**.

Revocation: add `"revokes_leaf_index": <n>` (must reference an already
existing leaf; otherwise `409`). It is appended as a new leaf; the old leaf
and all earlier tree heads remain untouched.

### Fetch a leaf

`GET /v1/leaves/{leaf_index}` → `leaf_index`, `leaf_hash`, `leaf_input`,
`idempotency_key`, parsed `envelope`. `404` if it does not exist.

### Tree head

```bash
curl -sS http://localhost:8080/v1/tree-head \
  -H 'X-Tenant-ID: team-payments'                 # current size
curl -sS 'http://localhost:8080/v1/tree-head?tree_size=5' \
  -H 'X-Tenant-ID: team-payments'                 # a historical size
```

Returns `tree_size`, `root_hash`, `timestamp_ms`, `key_id`, `signature`.
A tree size beyond the current tree returns `404`. STHs are immutable: a
given size is signed once and the stored (root, timestamp, key, signature)
is returned forever.

### Inclusion proof

```bash
curl -sS 'http://localhost:8080/v1/proofs/inclusion?leaf_index=3&tree_size=10' \
  -H 'X-Tenant-ID: team-payments'
```

```json
{
  "leaf_index": 3,
  "tree_size": 10,
  "leaf_hash": "…",
  "root_hash": "…",
  "inclusion_path": ["…", "…", "…"]
}
```

`404` when the leaf does not exist, the tree size is not available, or the
leaf was appended after the requested tree size.

### Consistency proof

```bash
curl -sS 'http://localhost:8080/v1/proofs/consistency?first_tree_size=10&second_tree_size=25' \
  -H 'X-Tenant-ID: team-payments'
```

Returns both root hashes and `consistency_path`. `first_tree_size` must be
≥ 1 (`400` otherwise); equal sizes yield an empty path; sizes beyond the
current tree return `404`.

### Verification (no database access)

```bash
# Inclusion: feed back the leaf bytes, index, tree size, path and root.
curl -sS -X POST http://localhost:8080/v1/verify/inclusion \
  -H 'Content-Type: application/json' \
  -d '{"leaf_input":"…","leaf_index":3,"tree_size":10,
       "inclusion_path":["…"],"root_hash":"…"}'
# {"valid": true, "reason": null}

# Consistency between two cached tree heads.
curl -sS -X POST http://localhost:8080/v1/verify/consistency \
  -H 'Content-Type: application/json' \
  -d '{"first_tree_size":10,"second_tree_size":25,
       "consistency_path":["…"],
       "first_root_hash":"…","second_root_hash":"…"}'
# {"valid": true, "reason": null}

# Tree-head signature (public key supplied by the caller).
curl -sS -X POST \
  'http://localhost:8080/v1/verify/tree-head?tree_size=10&root_hash=…&timestamp_ms=…&signature=…&public_key=…'
```

These endpoints are pure: they read no tenant data and can be run against
cached proofs without trusting the serving log.

### Signing keys

- `GET /v1/keys` — list all keys (`key_id`, base64 `public_key`, `active`,
  `created_at`); retired keys are retained indefinitely.
- `GET /v1/keys/{key_id}` — one public key (`404` if unknown).
- `POST /v1/keys/rotate` — generate a new active key; the previous one is
  marked inactive. New STHs use the new key; old STHs stay verifiable with
  the old public key.

### Health

`GET /health` → `{"status":"ok"}`

## Storage layout

- `tenants(tenant_id PK, tree_size)` — one row per tenant; appends take a
  row lock to serialize.
- `leaves(tenant_id, leaf_index, leaf_hash, leaf_input, idempotency_key)`
  with a unique constraint on `(tenant_id, idempotency_key)`.
- `merkle_nodes(tenant_id, left_index, level, node_hash)` — Trillian-style
  materialised internal nodes for O(log n) root and proof assembly.
- `tree_heads(tenant_id, tree_size, root_hash, timestamp_ms, key_id,
  signature)` — one immutable signed tree head per size.
- `signing_keys(key_id, public_key, private_key, active, created_at)`.

Tables are created automatically on startup (`Base.metadata.create_all`).

## Local development (without Docker)

```bash
python3 -m venv --without-pip .venv   # if ensurepip is unavailable
python3 get-pip path / .venv pip      # bootstrap pip as needed
pip install -r requirements.txt
export DATABASE_URL='postgresql+psycopg2://artifactlog:artifactlog@localhost:5432/artifactlog'
uvicorn app.main:app --reload --port 8080
```

### Tests

```bash
pip install pytest pgserver
python tests/test_merkle_exhaustive.py   # RFC-vector cross-checks (n up to 300)
pytest tests/test_api.py -q              # API end-to-end on ephemeral Postgres
python tests/test_concurrency.py         # 400 parallel appends stress test
```

The Merkle module is tested exhaustively: for every tree size up to 300 and
every leaf index, the generated inclusion proof verifies with the RFC 9162
verifier against an independently recomputed MTH, and every
`(first, second)` tree-size pair produces a valid consistency proof.
Tampered leaves, roots or proof elements are rejected.

## Security notes

- The reference deployment has no authentication/authorization in front of
  the API. Put it behind your release-network gateway or an authenticating
  proxy and restrict who can call `/v1/keys/rotate`.
- TLS termination (Ingress/load balancer) is expected to be provided by the
  deployment environment.
- Private signing keys are stored in PostgreSQL; protect database access and
  backups, or inject a KMS-managed seed through `SIGNING_PRIVATE_KEY`.
