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
)

const (
	exaBech32Hrp     = "exa"
	exaBech32mConst  = 0x2bc830a3
	exaAccessVersion = 1
)

// ParseExaAccess returns the base access key and decoded exa payload, if present.
// Non-exa access keys return the input access as-is with nil payload.
func ParseExaAccess(access string) (string, *exa.ExaAccess, error) {
	if !looksLikeExaAccess(access) {
		return access, nil, nil
	}

	hrp, data, err := bech32mDecode(access)
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

var bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var bech32CharsetRev = func() [128]int {
	var rev [128]int
	for i := range rev {
		rev[i] = -1
	}
	for i, ch := range bech32Charset {
		rev[ch] = i
	}
	return rev
}()

func bech32mDecode(input string) (string, []byte, error) {
	if len(input) < 8 {
		return "", nil, errors.New("bech32m string too short")
	}
	if strings.ToLower(input) != input && strings.ToUpper(input) != input {
		return "", nil, errors.New("bech32m mixed case")
	}

	input = strings.ToLower(input)
	sep := strings.LastIndexByte(input, '1')
	if sep < 1 || sep+7 > len(input) {
		return "", nil, errors.New("bech32m missing separator or checksum")
	}
	hrp := input[:sep]
	dataPart := input[sep+1:]
	data := make([]byte, len(dataPart))
	for i := 0; i < len(dataPart); i++ {
		ch := dataPart[i]
		if ch >= 128 || bech32CharsetRev[ch] == -1 {
			return "", nil, errors.New("bech32m invalid character")
		}
		data[i] = byte(bech32CharsetRev[ch])
	}

	if !bech32mVerifyChecksum(hrp, data) {
		return "", nil, errors.New("bech32m invalid checksum")
	}

	payload := data[:len(data)-6]
	decoded, err := bech32ConvertBits(payload, 5, 8, false)
	if err != nil {
		return "", nil, err
	}

	return hrp, decoded, nil
}

func bech32mVerifyChecksum(hrp string, data []byte) bool {
	values := append(bech32HrpExpand(hrp), data...)
	return bech32Polymod(values) == exaBech32mConst
}

func bech32HrpExpand(hrp string) []byte {
	expanded := make([]byte, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		expanded = append(expanded, hrp[i]>>5)
	}
	expanded = append(expanded, 0)
	for i := 0; i < len(hrp); i++ {
		expanded = append(expanded, hrp[i]&31)
	}
	return expanded
}

func bech32Polymod(values []byte) uint32 {
	var chk uint32 = 1
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		if (b & 1) != 0 {
			chk ^= 0x3b6a57b2
		}
		if (b & 2) != 0 {
			chk ^= 0x26508e6d
		}
		if (b & 4) != 0 {
			chk ^= 0x1ea119fa
		}
		if (b & 8) != 0 {
			chk ^= 0x3d4233dd
		}
		if (b & 16) != 0 {
			chk ^= 0x2a1462b3
		}
	}
	return chk
}

func bech32ConvertBits(data []byte, fromBits, toBits uint, pad bool) ([]byte, error) {
	var acc uint
	var bits uint
	maxv := uint((1 << toBits) - 1)
	ret := make([]byte, 0, len(data)*int(fromBits)/int(toBits))
	for _, value := range data {
		if value>>fromBits != 0 {
			return nil, errors.New("bech32m invalid data range")
		}
		acc = (acc << fromBits) | uint(value)
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			ret = append(ret, byte((acc>>bits)&maxv))
		}
	}
	if pad {
		if bits > 0 {
			ret = append(ret, byte((acc<<(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || ((acc<<(toBits-bits))&maxv) != 0 {
		return nil, errors.New("bech32m invalid padding")
	}
	return ret, nil
}
