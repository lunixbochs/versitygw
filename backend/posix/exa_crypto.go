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

package posix

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/internal/exa"
	"github.com/versity/versitygw/s3err"
)

type exaObjectMeta struct {
	nonce   []byte
	version uint64
}

type exaMultipartMode string

const (
	exaMultipartModeNone   exaMultipartMode = "none"
	exaMultipartModeServer exaMultipartMode = "server"
	exaMultipartModeClient exaMultipartMode = "client"
)

type exaMultipartState struct {
	mode    exaMultipartMode
	version uint64
}

func exaAccessFromContext(ctx context.Context) *exa.ExaAccess {
	exaAccess, _ := backend.ExaAccessFromContext(ctx)
	return exaAccess
}

func exaRandomNonce() ([]byte, error) {
	nonce := make([]byte, exa.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	return nonce, nil
}

func exaMultipartStateForRequest(exaAccess *exa.ExaAccess, version *uint64) (exaMultipartState, error) {
	switch {
	case version != nil:
		if exaAccess == nil || len(exaAccess.Secret) > 0 || *version == 0 {
			return exaMultipartState{}, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		return exaMultipartState{mode: exaMultipartModeClient, version: *version}, nil
	case exaAccess == nil:
		return exaMultipartState{mode: exaMultipartModeNone}, nil
	case len(exaAccess.Secret) > 0:
		return exaMultipartState{mode: exaMultipartModeServer}, nil
	default:
		return exaMultipartState{}, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
}

func (state exaMultipartState) isEncrypted() bool {
	return state.mode == exaMultipartModeServer || state.mode == exaMultipartModeClient
}

func (p *Posix) exaMultipartState(bucket, object string) (exaMultipartState, error) {
	modeBytes, err := p.meta.RetrieveAttribute(nil, bucket, object, backend.ExaMultipartModeKey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return exaMultipartState{mode: exaMultipartModeNone}, nil
	}
	if err != nil {
		return exaMultipartState{}, fmt.Errorf("get exa multipart mode: %w", err)
	}

	state := exaMultipartState{mode: exaMultipartMode(modeBytes)}
	switch state.mode {
	case exaMultipartModeNone, exaMultipartModeServer:
		return state, nil
	case exaMultipartModeClient:
		versionBytes, err := p.meta.RetrieveAttribute(nil, bucket, object, backend.ExaMultipartKVKey)
		if err != nil {
			if errors.Is(err, meta.ErrNoSuchKey) {
				return exaMultipartState{}, s3err.GetAPIError(s3err.ErrInvalidObjectState)
			}
			return exaMultipartState{}, fmt.Errorf("get exa multipart key version: %w", err)
		}
		version, err := strconv.ParseUint(string(versionBytes), 10, 64)
		if err != nil || version == 0 {
			return exaMultipartState{}, s3err.GetAPIError(s3err.ErrInvalidObjectState)
		}
		state.version = version
		return state, nil
	default:
		return exaMultipartState{}, s3err.GetAPIError(s3err.ErrInvalidObjectState)
	}
}

func (p *Posix) storeExaMultipartState(f *os.File, bucket, object string, state exaMultipartState) error {
	if state.mode == "" {
		state.mode = exaMultipartModeNone
	}
	if err := p.meta.StoreAttribute(f, bucket, object, backend.ExaMultipartModeKey, []byte(state.mode)); err != nil {
		return fmt.Errorf("set exa multipart mode: %w", err)
	}
	if state.mode != exaMultipartModeClient {
		return nil
	}
	if state.version == 0 {
		return s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	if err := p.meta.StoreAttribute(f, bucket, object, backend.ExaMultipartKVKey, []byte(strconv.FormatUint(state.version, 10))); err != nil {
		return fmt.Errorf("set exa multipart key version: %w", err)
	}
	return nil
}

func validateExaMultipartAccess(exaAccess *exa.ExaAccess, state exaMultipartState) error {
	switch state.mode {
	case exaMultipartModeNone:
		if exaAccess != nil && len(exaAccess.Secret) == 0 {
			return s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
	case exaMultipartModeClient:
		if exaAccess == nil || len(exaAccess.Secret) > 0 {
			return s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
	case exaMultipartModeServer:
		if exaAccess == nil || len(exaAccess.Secret) == 0 {
			return s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
	default:
		return s3err.GetAPIError(s3err.ErrInvalidObjectState)
	}
	return nil
}

func (p *Posix) exaPartMetadata(bucket, object string) (*exaObjectMeta, bool, error) {
	nonce, err := p.meta.RetrieveAttribute(nil, bucket, object, backend.ExaObjectNonceKey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("get exa nonce: %w", err)
	}
	if len(nonce) != exa.NonceSize {
		return nil, false, nil
	}

	versionBytes, err := p.meta.RetrieveAttribute(nil, bucket, object, backend.ExaObjectKVKey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("get exa key version: %w", err)
	}
	version, err := strconv.ParseUint(string(versionBytes), 10, 64)
	if err != nil || version == 0 {
		return nil, false, nil
	}

	return &exaObjectMeta{nonce: nonce, version: version}, true, nil
}

func (p *Posix) exaObjectVersion(bucket, object string) (uint64, bool, error) {
	versionBytes, err := p.meta.RetrieveAttribute(nil, bucket, object, backend.ExaObjectKVKey)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("get exa key version: %w", err)
	}
	version, err := strconv.ParseUint(string(versionBytes), 10, 64)
	if err != nil || version == 0 {
		return 0, false, nil
	}

	return version, true, nil
}

func (p *Posix) exaPlaintextSize(bucket, object string, encSize int64) int64 {
	_, ok, err := p.exaObjectVersion(bucket, object)
	if err != nil || !ok {
		return encSize
	}
	if encSize < exa.NonceSize {
		return encSize
	}
	payloadSize := encSize - exa.NonceSize
	plainSize, err := exa.PlaintextSizeFromPayload(payloadSize)
	if err != nil {
		return encSize
	}
	return plainSize
}

func exaReadNonce(src io.ReaderAt) ([]byte, error) {
	nonce := make([]byte, exa.NonceSize)
	n, err := src.ReadAt(nonce, 0)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n != exa.NonceSize {
		return nil, io.ErrUnexpectedEOF
	}
	return nonce, nil
}

func (p *Posix) exaWrappedKey(bucket, access string, version uint64) ([]byte, error) {
	attr := backend.ExaBucketKeyWrapAttr(version, access)
	wrapped, err := p.meta.RetrieveAttribute(nil, bucket, "", attr)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
	}
	if err != nil {
		return nil, fmt.Errorf("get exa wrapped key: %w", err)
	}
	if len(wrapped) == 0 {
		return nil, s3err.GetAPIError(s3err.ErrAccessDenied)
	}
	return wrapped, nil
}

func (p *Posix) exaCurrentWrappedKey(bucket, access string) (uint64, []byte, error) {
	version, err := p.getExaCurrentVersion(bucket)
	if err != nil {
		return 0, nil, err
	}
	if version == 0 {
		return 0, nil, s3err.GetAPIError(s3err.ErrAccessDenied)
	}
	wrapped, err := p.exaWrappedKey(bucket, access, version)
	if err != nil {
		return 0, nil, err
	}
	return version, wrapped, nil
}

func (p *Posix) storeExaPartMeta(f *os.File, bucket, object string, nonce []byte, version uint64) error {
	if len(nonce) != exa.NonceSize || version == 0 {
		return s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	if err := p.meta.StoreAttribute(f, bucket, object, backend.ExaObjectNonceKey, nonce); err != nil {
		return fmt.Errorf("set exa nonce: %w", err)
	}
	if err := p.meta.StoreAttribute(f, bucket, object, backend.ExaObjectKVKey, []byte(strconv.FormatUint(version, 10))); err != nil {
		return fmt.Errorf("set exa key version: %w", err)
	}
	return nil
}

func (p *Posix) storeExaObjectVersion(f *os.File, bucket, object string, version uint64) error {
	if version == 0 {
		return s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	if err := p.meta.StoreAttribute(f, bucket, object, backend.ExaObjectKVKey, []byte(strconv.FormatUint(version, 10))); err != nil {
		return fmt.Errorf("set exa key version: %w", err)
	}
	return nil
}
