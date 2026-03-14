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

package backend

import (
	"context"
	"strconv"
	"strings"

	"github.com/versity/versitygw/internal/exa"
)

const (
	ExaBucketKeyCurrent = "exa.kv.current"
	exaBucketKeyPrefix  = "exa.kv."
	exaBucketKeyWrapSep = ".wrap."
	ExaObjectNonceKey   = "exa.nonce"
	ExaObjectKVKey      = "exa.kv"
	ExaMultipartModeKey = "exa.mpu.mode"
	ExaMultipartKVKey   = "exa.mpu.kv"

	ExaContextAccessKey     = "exa-access"
	ExaContextKeyVersionKey = "exa-key-version"
)

type ExaKeyStore interface {
	GetBucketExaKeys(ctx context.Context, bucket, access string) (uint64, map[uint64][]byte, error)
	PutBucketExaKeys(ctx context.Context, bucket string, version uint64, keys map[string][]byte) error
}

func ExaBucketKeyWrapAttr(version uint64, access string) string {
	return exaBucketKeyPrefix + strconv.FormatUint(version, 10) + exaBucketKeyWrapSep + access
}

func ParseExaBucketKeyAttr(attr string) (uint64, string, bool) {
	if !strings.HasPrefix(attr, exaBucketKeyPrefix) {
		return 0, "", false
	}
	rest := strings.TrimPrefix(attr, exaBucketKeyPrefix)
	parts := strings.SplitN(rest, exaBucketKeyWrapSep, 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return 0, "", false
	}
	version, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, "", false
	}
	return version, parts[1], true
}

func ExaAccessFromContext(ctx context.Context) (*exa.ExaAccess, bool) {
	val := ctx.Value(ExaContextAccessKey)
	if val == nil {
		return nil, false
	}
	exaAccess, ok := val.(*exa.ExaAccess)
	return exaAccess, ok
}

func SetExaResponseInfo(ctx context.Context, version uint64) {
	setter, ok := ctx.(interface{ SetUserValue(key any, value any) })
	if !ok {
		return
	}
	setter.SetUserValue(ExaContextKeyVersionKey, strconv.FormatUint(version, 10))
}
