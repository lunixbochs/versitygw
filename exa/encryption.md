# Exa Transparent Encryption API (draft)

This document describes the current exa API surface added to versitygw for
transparent encryption key distribution and access key encoding. Object
encryption/decryption is not covered here and will be documented separately
once the age integration lands.

## AccessKeyID container format

The AccessKeyID can be a bech32m-encoded CBOR payload. These keys are
recognizable by the `exa1` prefix (HRP `exa`).

CBOR map fields:
- `v` (uint): version. Current value is `1`.
- `a` (string): base access key (IAM lookup/root checks use this).
- `s` (bytes, optional): mlkem768x25519 private key bytes.

Notes:
- Encryption-aware clients use the full `exa1...` AccessKeyID for SigV4, but
  can omit `s` when they only want auth behavior.
- The server validates the bech32m checksum, decodes CBOR, and rejects unknown
  versions or missing `a`.

## Endpoints

All endpoints are bucket-level S3 query params (not admin APIs). They require
SigV4 authentication. Presigned URLs are allowed, but `X-Amz-Security-Token`
(temporary credentials) is not supported.
For signed (non-presigned) requests, `X-Amz-Content-Sha256` is required.

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

## Error behavior

All endpoints return standard S3 error responses. Common errors:
- `AccessDenied`: ACL check failed, read-only, or non-owner for owner-only APIs.
- `InvalidRequest`: malformed JSON, missing required fields, or missing pubkey.
- `InvalidBucketName`, `NoSuchBucket`: bucket validation.
- `NotImplemented`: backend does not implement exa key storage.
- `InvalidAccessKeyID`: pubkey request for unknown user.

## Metadata layout (POSIX backend)

Bucket metadata attributes:
- `exa.kv.current`: ASCII decimal key-version string.
- `exa.kv.<version>.wrap.<access>`: wrapped bucket key bytes.

Object metadata attributes (reserved for encryption work):
- `exa.nonce`: 16-byte file nonce.
- `exa.kv`: key-version used to derive the file key.

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
