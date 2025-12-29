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

package utils

import (
	"errors"
	"fmt"
	"strings"

	"github.com/fxamacker/cbor/v2"
	"github.com/versity/versitygw/internal/exa"
	exabech32 "github.com/versity/versitygw/internal/exa/bech32"
)

const (
	exaBech32Hrp     = "exa"
	exaAccessVersion = 1
)

// ParseExaAccess returns the base access key and decoded exa payload, if present.
// Non-exa access keys return the input access as-is with nil payload.
func ParseExaAccess(access string) (string, *exa.ExaAccess, error) {
	if !looksLikeExaAccess(access) {
		return access, nil, nil
	}

	hrp, data, err := exabech32.Decode(access)
	if err != nil {
		return "", nil, err
	}
	if hrp != exaBech32Hrp {
		return "", nil, fmt.Errorf("unexpected hrp: %s", hrp)
	}

	var exaAccess exa.ExaAccess
	if err := cbor.Unmarshal(data, &exaAccess); err != nil {
		return "", nil, err
	}
	if exaAccess.Version != exaAccessVersion {
		return "", nil, fmt.Errorf("unsupported exa access version: %d", exaAccess.Version)
	}
	if exaAccess.Access == "" {
		return "", nil, errors.New("missing exa access")
	}

	return exaAccess.Access, &exaAccess, nil
}

func looksLikeExaAccess(access string) bool {
	if len(access) < len(exaBech32Hrp)+2 {
		return false
	}
	lower := strings.ToLower(access)
	return strings.HasPrefix(lower, exaBech32Hrp+"1")
}
