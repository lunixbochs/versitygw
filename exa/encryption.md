# Exa Transparent Encryption (draft)

This document describes the exa access key format, bucket key APIs, and the
object encryption behavior implemented by versitygw (posix backend).

## AccessKeyID container format

AccessKeyID values can be a bech32-encoded CBOR payload. These keys are
recognizable by the `exa1` prefix (HRP `exa`).

CBOR map fields:
- `v` (uint): version. Current value is `1`.
- `a` (string): base access key (IAM lookup/root checks use this).
- `s` (bytes, optional): mlkem768x25519 private key bytes.

Notes:
- The SigV4 `AccessKeyID` is the full `exa1...` string.
- The server authenticates using the base access key `a` and the IAM secret.
- Encryption-aware clients can omit `s` to request auth-only behavior.

## Wrapped bucket key format

Wrapped bucket keys are CBOR-encoded blobs stored in bucket metadata and
returned by the `exa-keys` API. The CBOR map fields are:
- `v` (uint): version. Current value is `1`.
- `e` (bytes): HPKE encapsulation.
- `c` (bytes): encrypted bucket key.

Wrapping uses HPKE MLKEM768X25519 with HKDF-SHA256 and ChaCha20-Poly1305,
with info string `age-encryption.org/mlkem768x25519`. The bucket key is 16
bytes. JSON transport uses standard base64 encoding for the wrapped bytes.

## Bucket key distribution API

All endpoints are bucket-level S3 query params (not admin APIs). They require
SigV4 authentication. Presigned URLs are allowed. `X-Amz-Security-Token` is
not supported.

### GET /{bucket}?exa-keys
Returns wrapped bucket keys **only for the calling access key**.

Access control:
- Allowed if bucket ACL grants Read or Write to the caller.
- Bucket policies are ignored for this endpoint.
- Root and admin bypass ACL checks.

Response (JSON; `wrapped` is base64):
```json
{"current":3,"keys":[{"version":1,"wrapped":"BASE64..."},{"version":3,"wrapped":"BASE64..."}]}
```

### PUT /{bucket}?exa-keys
Stores wrapped keys for a given rekey version and sets the current version.

Access control:
- Bucket owner only (or root). Admin role alone is not sufficient.
- Read-only gateway mode returns AccessDenied.

Request (JSON; `wrapped` is base64):
```json
{"version":3,"keys":[{"access":"AKIA...BASE","wrapped":"BASE64..."}]}
```

Behavior:
- Stores `exa.kv.<version>.wrap.<access>` for each entry.
- Updates `exa.kv.current` to the provided `version`.

### POST /{bucket}?exa-pubkeys
Fetches user public keys by access ID (used by clients for rekeying).

Access control:
- Bucket owner only (or root). Admin role alone is not sufficient.

Request:
```json
{"access":["AKIA...BASE","AKIA...BASE2"]}
```

Response:
```json
{"keys":{"AKIA...BASE":"PUBKEY1","AKIA...BASE2":"PUBKEY2"}}
```

## Object encryption

Object layout on disk:
- `nonce` (16 bytes) prefix
- encrypted payload (age stream format, chunk size 64 KiB)

Key derivation:
- File key: HKDF-SHA256(bucketKey, salt=nonce, info="exa-data") -> 16 bytes
- Stream key: HKDF-SHA256(fileKey, salt=nonce, info="payload") -> 32 bytes

Payload size:
- `encryptedPayloadSize = plaintextSize + chunks * 16`, where
  `chunks = ceil(plaintextSize / 65536)` and empty plaintext uses 1 chunk.
- Total stored size = `16 + encryptedPayloadSize`.

### Upload behavior

If AccessKeyID includes `s` (secret present):
- The server unwraps the bucket key, generates a random nonce, encrypts
  the stream on write, and stores `exa.kv` metadata.

If AccessKeyID omits `s` (auth-only):
- The client encrypts locally and MUST send:
  - `x-exa-key-version`: decimal bucket key version
- The object body MUST start with the 16-byte nonce prefix, followed by the
  encrypted payload.

### Download behavior

If AccessKeyID includes `s`:
- The server decrypts on the fly and uses plaintext sizes for range requests,
  `Content-Length`, and listing sizes.

If AccessKeyID omits `s`:
- The server returns ciphertext with raw sizes (nonce + encrypted payload).
- Responses include `x-exa-key-version` header.

Directory listings always report plaintext sizes for encrypted objects.

### Headers

- `x-exa-key-version`: decimal string

## CopyObject and multipart

CopyObject:
- Cross-bucket copy is rejected if the source object is encrypted.
- Same-bucket copy preserves ciphertext and exa metadata (no re-encryption).

Multipart:
- Multipart encryption is supported only with full exa access keys (with `s`).
- Auth-only exa keys return `NotImplemented` for multipart operations.
- Each part is encrypted independently with a per-part nonce stored only in
  metadata (no nonce prefix in the part payload).
- Part key derivation:
  - File key: HKDF-SHA256(bucketKey, salt=nonce, info="exa-data-part") -> 16 bytes
  - Stream key: HKDF-SHA256(fileKey, salt=nonce, info="payload-part") -> 32 bytes
- CompleteMultipartUpload decrypts each part and re-encrypts the final object
  with a new nonce and the current bucket key (same behavior as PutObject).
- UploadPartCopy is not supported for exa-encrypted uploads.
- Mixed plaintext and encrypted parts are rejected.

## Metadata layout (posix backend)

Bucket metadata attributes:
- `exa.kv.current`: ASCII decimal key-version string.
- `exa.kv.<version>.wrap.<access>`: wrapped bucket key bytes.

Object metadata attributes:
- `exa.kv`: key-version used to derive the file key.

Multipart part metadata attributes:
- `exa.nonce`: 16-byte part nonce (parts never include a nonce prefix).
- `exa.kv`: key-version used to derive the part key.

## IAM public keys

IAM accounts carry a `PublicKey` field. Internal IAM supports storing it via
admin CLI:
- `versitygw admin create-user --public-key ...`
- `versitygw admin update-user --public-key ...`

LDAP/Vault/IPA backends do not map public keys yet.

## Example curl (placeholder for SigV4)

```text
# GET exa keys (replace with a SigV4-capable client)
GET /mybucket?exa-keys

# PUT exa keys
PUT /mybucket?exa-keys
{"version":3,"keys":[{"access":"AKIA...BASE","wrapped":"BASE64..."}]}

# POST exa pubkeys
POST /mybucket?exa-pubkeys
{"access":["AKIA...BASE"]}
```
