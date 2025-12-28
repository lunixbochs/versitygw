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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"

	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/s3err"
)

func (p *Posix) GetBucketExaKeys(_ context.Context, bucket, access string) (uint64, map[uint64][]byte, error) {
	if !p.isBucketValid(bucket) {
		return 0, nil, s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, nil, s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return 0, nil, fmt.Errorf("stat bucket: %w", err)
	}

	current, err := p.getExaCurrentVersion(bucket)
	if err != nil {
		return 0, nil, err
	}

	attrs, err := p.meta.ListAttributes(bucket, "")
	if err != nil {
		return 0, nil, fmt.Errorf("list exa keys: %w", err)
	}

	keys := make(map[uint64][]byte)
	for _, attr := range attrs {
		version, attrAccess, ok := backend.ParseExaBucketKeyAttr(attr)
		if !ok || attrAccess != access {
			continue
		}

		value, err := p.meta.RetrieveAttribute(nil, bucket, "", attr)
		if errors.Is(err, meta.ErrNoSuchKey) {
			continue
		}
		if err != nil {
			return 0, nil, fmt.Errorf("get exa key %q: %w", attr, err)
		}
		keys[version] = value
	}

	return current, keys, nil
}

func (p *Posix) PutBucketExaKeys(_ context.Context, bucket string, version uint64, keys map[string][]byte) error {
	if !p.isBucketValid(bucket) {
		return s3err.GetAPIError(s3err.ErrInvalidBucketName)
	}
	_, err := os.Stat(bucket)
	if errors.Is(err, fs.ErrNotExist) {
		return s3err.GetAPIError(s3err.ErrNoSuchBucket)
	}
	if err != nil {
		return fmt.Errorf("stat bucket: %w", err)
	}
	if version == 0 || len(keys) == 0 {
		return s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	for access, wrapped := range keys {
		if access == "" || len(wrapped) == 0 {
			return s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		attr := backend.ExaBucketKeyWrapAttr(version, access)
		if err := p.meta.StoreAttribute(nil, bucket, "", attr, wrapped); err != nil {
			return fmt.Errorf("set exa key %q: %w", attr, err)
		}
	}

	err = p.meta.StoreAttribute(nil, bucket, "", backend.ExaBucketKeyCurrent, []byte(strconv.FormatUint(version, 10)))
	if err != nil {
		return fmt.Errorf("set exa current version: %w", err)
	}

	return nil
}

func (p *Posix) getExaCurrentVersion(bucket string) (uint64, error) {
	b, err := p.meta.RetrieveAttribute(nil, bucket, "", backend.ExaBucketKeyCurrent)
	if errors.Is(err, meta.ErrNoSuchKey) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("get exa current version: %w", err)
	}
	if len(b) == 0 {
		return 0, nil
	}
	version, err := strconv.ParseUint(string(b), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse exa current version: %w", err)
	}
	return version, nil
}
