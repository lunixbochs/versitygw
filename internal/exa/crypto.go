// Copyright 2025 Versity Software
// This file is licensed under the Apache License, Version 2.0
// (the "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package exa

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"filippo.io/hpke"
	"github.com/fxamacker/cbor/v2"
	"github.com/versity/versitygw/internal/exa/stream"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	NonceSize        = 16
	BucketKeySize    = 16
	FileKeySize      = 16
	WrappedKeyV1     = 1
	fileKeyInfo      = "exa-data"
	streamKeyInfo    = "payload"
	pqLabel          = "age-encryption.org/mlkem768x25519"
	wrappedKeyEncTag = "missing wrapped key encapsulation"
)

type wrappedKey struct {
	Version uint64 `cbor:"v"`
	Enc     []byte `cbor:"e"`
	Cipher  []byte `cbor:"c"`
}

func DecodeWrappedKey(data []byte) (enc, cipher []byte, err error) {
	if len(data) == 0 {
		return nil, nil, errors.New("wrapped key is empty")
	}

	var wk wrappedKey
	if err := cbor.Unmarshal(data, &wk); err != nil {
		return nil, nil, err
	}
	if wk.Version != WrappedKeyV1 {
		return nil, nil, fmt.Errorf("unsupported wrapped key version: %d", wk.Version)
	}
	if len(wk.Enc) == 0 {
		return nil, nil, errors.New(wrappedKeyEncTag)
	}
	if len(wk.Cipher) == 0 {
		return nil, nil, errors.New("missing wrapped key ciphertext")
	}

	return wk.Enc, wk.Cipher, nil
}

func UnwrapBucketKey(secret, wrapped []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, errors.New("missing secret key")
	}

	enc, ct, err := DecodeWrappedKey(wrapped)
	if err != nil {
		return nil, err
	}
	if len(ct) != BucketKeySize+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("unexpected wrapped key size: %d", len(ct))
	}

	k, err := hpke.MLKEM768X25519().NewPrivateKey(secret)
	if err != nil {
		return nil, errors.New("invalid MLKEM768-X25519 secret key")
	}

	r, err := hpke.NewRecipient(enc, k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(pqLabel))
	if err != nil {
		return nil, fmt.Errorf("setup hpke recipient: %w", err)
	}
	bucketKey, err := r.Open(nil, ct)
	if err != nil {
		return nil, errors.New("failed to unwrap bucket key")
	}
	if len(bucketKey) != BucketKeySize {
		return nil, fmt.Errorf("unexpected bucket key size: %d", len(bucketKey))
	}

	return bucketKey, nil
}

func DeriveFileKey(bucketKey, nonce []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("invalid nonce size: %d", len(nonce))
	}
	if len(bucketKey) != BucketKeySize {
		return nil, fmt.Errorf("invalid bucket key size: %d", len(bucketKey))
	}

	h := hkdf.New(sha256.New, bucketKey, nonce, []byte(fileKeyInfo))
	fileKey := make([]byte, FileKeySize)
	if _, err := io.ReadFull(h, fileKey); err != nil {
		return nil, err
	}
	return fileKey, nil
}

func DeriveStreamKey(fileKey, nonce []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("invalid nonce size: %d", len(nonce))
	}
	if len(fileKey) != FileKeySize {
		return nil, fmt.Errorf("invalid file key size: %d", len(fileKey))
	}

	h := hkdf.New(sha256.New, fileKey, nonce, []byte(streamKeyInfo))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, key); err != nil {
		return nil, err
	}
	return key, nil
}

func EncryptedPayloadSize(plaintextSize int64) int64 {
	var chunks int64
	if plaintextSize == 0 {
		chunks = 1
	} else {
		chunks = (plaintextSize + stream.ChunkSize - 1) / stream.ChunkSize
	}
	return plaintextSize + chunks*chacha20poly1305.Overhead
}

func PlaintextSizeFromPayload(payloadSize int64) (int64, error) {
	return stream.PlaintextSize(payloadSize)
}
