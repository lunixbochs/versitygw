# Exa API Client Specification

Status: implementation specification for the current `encryption` branch.

This document defines client-facing behavior for Exa-specific functionality in:
- S3-compatible APIs (bucket query APIs plus Exa-aware object behavior)
- Admin APIs used for Exa public key management

The behavior described here is based on the current gateway implementation.

## 1. Scope

This spec covers:
- Exa AccessKeyID format (`exa1...`)
- Bucket key distribution APIs:
  - `GET /{bucket}?exa-keys`
  - `PUT /{bucket}?exa-keys`
  - `POST /{bucket}?exa-pubkeys`
- Exa-specific behavior of standard object APIs:
  - `PUT Object`
  - `GET Object`
  - `HEAD Object`
  - `CopyObject`
  - Multipart operations
- Admin APIs for setting and updating IAM user public keys

This spec does not redefine non-Exa S3 behavior.

## 2. Authentication and Signing

### 2.1 S3 Exa APIs

- Must be authenticated with SigV4.
- Standard header-auth and presigned URLs are supported.
- For presigned requests, `X-Amz-Security-Token` is not supported.

### 2.2 Admin APIs

- Must be authenticated with SigV4 header auth.
- Presigned admin requests are not supported by current routing.
- Caller must resolve to role `admin` (root is treated as admin).

## 3. Exa AccessKeyID Format

AccessKeyID may be a bech32-encoded CBOR payload with HRP `exa`, typically:

- `exa1...`

CBOR fields:
- `v` (uint): access format version. Current value: `1`
- `a` (string): base IAM access key used for account lookup and secret verification
- `s` (bytes, optional): MLKEM768X25519 private key bytes

Rules:
- If AccessKeyID is not `exa1...`, it is treated as a normal access key.
- If AccessKeyID is `exa1...`, `v` must be `1` and `a` must be non-empty.
- The SigV4 secret is still the IAM secret for base access key `a`.

Practical modes:
- Full Exa key: includes `s`
- Auth-only Exa key: omits `s`

## 4. Encodings and Headers

### 4.1 JSON byte fields

All JSON `[]byte` fields use standard base64 encoding (Go JSON behavior).

### 4.2 Exa object headers

- `x-exa-key-version`: decimal unsigned integer string

## 5. S3 Bucket Exa APIs

All Exa bucket APIs are bucket-level query APIs:
- Path: `/{bucket}`
- Query selector: `exa-keys` or `exa-pubkeys`

These endpoints return JSON, not XML.

### 5.1 GET `/{bucket}?exa-keys`

Returns wrapped bucket keys for the current caller access key only.

Authorization:
- Allowed for root
- Allowed for admin role
- Allowed for users with bucket ACL `READ` or `WRITE`
- Bucket policy is not consulted for this endpoint

Response:

```json
{
  "current": 3,
  "keys": [
    {"version": 1, "wrapped": "BASE64..."},
    {"version": 3, "wrapped": "BASE64..."}
  ]
}
```

Notes:
- `keys` are filtered to keys written for the caller's base access key.
- `keys` are sorted by `version` ascending.
- `current` may be `0` if no current version is set.

### 5.2 PUT `/{bucket}?exa-keys`

Stores wrapped keys for one version and sets that version as current.

Authorization:
- Allowed for root
- Allowed for bucket owner only
- Admin role alone is not sufficient
- In read-only mode returns `AccessDenied`

Request:

```json
{
  "version": 3,
  "keys": [
    {"access": "AKIA_BASE_1", "wrapped": "BASE64..."},
    {"access": "AKIA_BASE_2", "wrapped": "BASE64..."}
  ]
}
```

Validation:
- `version` must be > 0
- `keys` must be non-empty
- each key entry must have non-empty `access` and non-empty `wrapped`

Storage behavior:
- For each key entry:
  - `exa.kv.<version>.wrap.<access>` = wrapped bytes
- Current version:
  - `exa.kv.current` = decimal version string

### 5.3 POST `/{bucket}?exa-pubkeys`

Returns IAM public keys for requested access IDs.

Authorization:
- Allowed for root
- Allowed for bucket owner only
- Admin role alone is not sufficient

Request:

```json
{
  "access": ["AKIA_BASE_1", "AKIA_BASE_2"]
}
```

Response:

```json
{
  "keys": {
    "AKIA_BASE_1": "PUBKEY1",
    "AKIA_BASE_2": "PUBKEY2"
  }
}
```

Validation/Errors:
- `access` array must be non-empty
- each access entry must be non-empty
- unknown access returns `InvalidAccessKeyId`
- known user without `PublicKey` returns `InvalidRequest`

## 6. Exa Object Data Behavior

### 6.1 Cryptographic parameters

- Bucket key size: 16 bytes
- File nonce size: 16 bytes
- Payload chunk size: 64 KiB
- Per-chunk overhead: 16 bytes (ChaCha20-Poly1305)

Wrapped bucket key format (CBOR):
- `v` version (must be `1`)
- `e` HPKE encapsulation
- `c` wrapped ciphertext

HPKE suite:
- KEM: MLKEM768X25519
- KDF: HKDF-SHA256
- AEAD: ChaCha20-Poly1305
- Label/info: `age-encryption.org/mlkem768x25519`

Derivation:
- Object file key: HKDF-SHA256(bucketKey, salt=nonce, info=`exa-data`) -> 16 bytes
- Object stream key: HKDF-SHA256(fileKey, salt=nonce, info=`payload`) -> 32 bytes
- Multipart part key info strings:
  - `exa-data-part`
  - `payload-part`

### 6.2 Upload (`PUT Object`)

### Mode A: Full Exa access key (has `s`)

- Server unwraps current bucket key for caller access.
- Server generates random nonce.
- Server encrypts plaintext stream before writing object.
- Stored object bytes: `nonce(16)` + encrypted payload.
- Server stores object metadata:
  - `exa.kv` (key version used)

### Mode B: Auth-only Exa access key (no `s`)

Client sends already-encrypted object.

Required headers:
- `x-exa-key-version`

Object body contract:
- body must be `nonce(16)` + encrypted payload

Validation:
- key version must parse as uint > 0
- headers require Exa access key format (`exa1...`)

### 6.3 Download (`GET Object`, `HEAD Object`)

If object has Exa metadata:

- With full Exa access key (`s` present):
  - server decrypts on read
  - `Content-Length` and ranges are plaintext-based
  - no Exa headers are added

- With auth-only Exa key or non-Exa key:
  - server returns raw stored bytes (ciphertext with nonce prefix)
  - `Content-Length` is ciphertext length
  - response includes:
    - `x-exa-key-version`

### 6.4 Listing size semantics

For encrypted objects, listing paths compute and expose plaintext size.

### 6.5 CopyObject behavior

- Cross-bucket copy of encrypted source object is rejected with `InvalidObjectState`.
- Same-bucket copy preserves ciphertext and Exa metadata (no re-encryption).
- Copying encrypted source requires using an Exa-style access key (`exa1...`).

### 6.6 Multipart behavior

Support matrix:

- Full Exa access key:
  - `CreateMultipartUpload`: supported
  - `UploadPart`: supported (parts encrypted independently)
  - `ListParts`: supported
  - `CompleteMultipartUpload`: supported (parts decrypted then final object
    re-encrypted with new nonce and current bucket key)
  - `AbortMultipartUpload`: supported
  - `ListMultipartUploads`: supported

- Auth-only Exa key:
  - All multipart operations above return `NotImplemented`

- `UploadPartCopy`:
  - If request uses Exa access key, returns `NotImplemented`

Part encryption details:
- Multipart parts do not include nonce prefix in part payload.
- Part metadata stores per-part nonce and key version.

## 7. Admin API: Exa-Relevant Endpoints

These endpoints are not Exa-namespaced, but are required for Exa pubkey
distribution flow.

Base path examples assume admin server root.

### 7.1 PATCH `/create-user`

Purpose:
- Create IAM user including optional public key.

Request body: XML `auth.Account`

```xml
<Account>
  <Access>AKIA_BASE_1</Access>
  <Secret>SECRET</Secret>
  <PublicKey>PUBKEY1</PublicKey>
  <Role>user</Role>
  <UserID>0</UserID>
  <GroupID>0</GroupID>
  <ProjectID>0</ProjectID>
</Account>
```

Notes:
- `Role` must be one of: `user`, `admin`, `userplus`
- `PublicKey` may be omitted
- success status: `201 Created`

### 7.2 PATCH `/update-user?access=<base_access>`

Purpose:
- Update mutable user properties including `PublicKey`.

Request body: XML `auth.MutableProps`

```xml
<MutableProps>
  <PublicKey>PUBKEY1_UPDATED</PublicKey>
</MutableProps>
```

Notes:
- To update key, include `<PublicKey>...`
- To clear key, send empty `PublicKey` element
- success status: `200 OK`

### 7.3 PATCH `/list-users`

Purpose:
- Return all IAM users and includes `PublicKey` when set.

Response body: XML `auth.ListUserAccountsResult`.

Example snippet:

```xml
<ListUserAccountsResult>
  <Accounts>
    <Access>AKIA_BASE_1</Access>
    <Secret>***</Secret>
    <PublicKey>PUBKEY1</PublicKey>
    <Role>user</Role>
    <UserID>0</UserID>
    <GroupID>0</GroupID>
    <ProjectID>0</ProjectID>
  </Accounts>
</ListUserAccountsResult>
```

## 8. Error Model (Client Expectations)

Errors are S3-style XML:
- `<Error><Code>...</Code><Message>...</Message>...</Error>`

Common codes for Exa flows:
- `AccessDenied` (403)
- `InvalidAccessKeyId` (403)
- `InvalidRequest` (400)
- `NotImplemented` (501)
- `InvalidObjectState` (403)

Admin-specific codes:
- `XAdminAccessDenied` (403)
- `XAdminUserNotFound` (404)
- `XAdminUserExists` (409)
- `XAdminInvalidArgument` (400 or 404, depending on case)

## 9. Recommended Client Flow

1. Provision IAM users with public keys via admin API (`create-user`/`update-user`).
2. Bucket owner fetches required pubkeys with `POST ?exa-pubkeys`.
3. Client rekey logic wraps bucket key per user access and pushes with `PUT ?exa-keys`.
4. Readers fetch their own wrapped keys via `GET ?exa-keys`.
5. Data operations:
   - full Exa key for server-side transparent decrypt/encrypt
   - auth-only Exa key for client-side encryption mode

## 10. Compatibility Notes

- Exa bucket APIs are currently implemented by the posix backend path.
- For non-supporting backends, `?exa-keys` operations return `NotImplemented`.
- Access and wrapped key formats are versioned; current version is `1`.
