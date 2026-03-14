// Copyright 2026 Versity Software
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

import "strings"

const (
	ExaNonceHeader      = "x-exa-nonce"
	ExaKeyVersionHeader = "x-exa-key-version"
)

func DefaultExposeHeaders() []string {
	return []string{"ETag", ExaNonceHeader, ExaKeyVersionHeader}
}

func AppendUniqueHeaderValues(existing string, values ...string) string {
	existing = strings.TrimSpace(existing)

	lowerExisting := map[string]struct{}{}
	if existing != "" {
		for _, part := range strings.Split(existing, ",") {
			p := strings.TrimSpace(part)
			if p == "" {
				continue
			}
			lowerExisting[strings.ToLower(p)] = struct{}{}
		}
	}

	toAdd := make([]string, 0, len(values))
	for _, value := range values {
		v := strings.TrimSpace(value)
		if v == "" {
			continue
		}
		lowerValue := strings.ToLower(v)
		if _, ok := lowerExisting[lowerValue]; ok {
			continue
		}
		toAdd = append(toAdd, v)
		lowerExisting[lowerValue] = struct{}{}
	}

	if len(toAdd) == 0 {
		return existing
	}
	if existing == "" {
		return strings.Join(toAdd, ", ")
	}

	return existing + ", " + strings.Join(toAdd, ", ")
}
