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

package controllers

import (
	"encoding/json"
	"sort"

	"github.com/gofiber/fiber/v2"
	"github.com/versity/versitygw/auth"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/s3api/utils"
	"github.com/versity/versitygw/s3err"
)

type exaKeyEntry struct {
	Version uint64 `json:"version"`
	Wrapped []byte `json:"wrapped"`
}

type exaKeysResponse struct {
	Current uint64        `json:"current"`
	Keys    []exaKeyEntry `json:"keys"`
}

type exaPutKeysRequest struct {
	Version uint64          `json:"version"`
	Keys    []exaWrappedKey `json:"keys"`
}

type exaWrappedKey struct {
	Access  string `json:"access"`
	Wrapped []byte `json:"wrapped"`
}

type exaPubKeysRequest struct {
	Access []string `json:"access"`
}

type exaPubKeysResponse struct {
	Keys map[string]string `json:"keys"`
}

func (c S3ApiController) GetBucketExaKeys(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	exaStore, ok := c.be.(backend.ExaKeyStore)
	if !ok {
		return &Response{
			MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
		}, s3err.GetAPIError(s3err.ErrNotImplemented)
	}

	if err := authorizeExaKeysRead(acct, isRoot, parsedAcl); err != nil {
		return &Response{
			MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
		}, err
	}

	current, keys, err := exaStore.GetBucketExaKeys(ctx.Context(), bucket, acct.Access)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
		}, err
	}

	resp := exaKeysResponse{
		Current: current,
		Keys:    make([]exaKeyEntry, 0, len(keys)),
	}
	versions := make([]uint64, 0, len(keys))
	for version := range keys {
		versions = append(versions, version)
	}
	sort.Slice(versions, func(i, j int) bool {
		return versions[i] < versions[j]
	})
	for _, version := range versions {
		resp.Keys = append(resp.Keys, exaKeyEntry{
			Version: version,
			Wrapped: keys[version],
		})
	}

	body, err := json.Marshal(resp)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
		}, s3err.GetAPIError(s3err.ErrInternalError)
	}

	return &Response{
		Data: body,
		Headers: map[string]*string{
			"Content-Type": utils.GetStringPtr(fiber.MIMEApplicationJSON),
		},
		MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
	}, nil
}

func (c S3ApiController) PutBucketExaKeys(ctx *fiber.Ctx) (*Response, error) {
	bucket := ctx.Params("bucket")
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	if c.readonly {
		return &Response{
			MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
		}, s3err.GetAPIError(s3err.ErrAccessDenied)
	}
	if err := authorizeExaOwner(acct, isRoot, parsedAcl); err != nil {
		return &Response{
			MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
		}, err
	}

	exaStore, ok := c.be.(backend.ExaKeyStore)
	if !ok {
		return &Response{
			MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
		}, s3err.GetAPIError(s3err.ErrNotImplemented)
	}

	var req exaPutKeysRequest
	if err := json.Unmarshal(ctx.Body(), &req); err != nil {
		return &Response{
			MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
		}, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	if req.Version == 0 || len(req.Keys) == 0 {
		return &Response{
			MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
		}, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	keys := make(map[string][]byte, len(req.Keys))
	for _, key := range req.Keys {
		if key.Access == "" || len(key.Wrapped) == 0 {
			return &Response{
				MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
			}, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		keys[key.Access] = key.Wrapped
	}

	if err := exaStore.PutBucketExaKeys(ctx.Context(), bucket, req.Version, keys); err != nil {
		return &Response{
			MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
		}, err
	}

	return &Response{
		MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
	}, nil
}

func (c S3ApiController) PostBucketExaPubKeys(ctx *fiber.Ctx) (*Response, error) {
	acct := utils.ContextKeyAccount.Get(ctx).(auth.Account)
	isRoot := utils.ContextKeyIsRoot.Get(ctx).(bool)
	parsedAcl := utils.ContextKeyParsedAcl.Get(ctx).(auth.ACL)

	if err := authorizeExaOwner(acct, isRoot, parsedAcl); err != nil {
		return &Response{
			MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
		}, err
	}

	var req exaPubKeysRequest
	if err := json.Unmarshal(ctx.Body(), &req); err != nil {
		return &Response{
			MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
		}, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}
	if len(req.Access) == 0 {
		return &Response{
			MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
		}, s3err.GetAPIError(s3err.ErrInvalidRequest)
	}

	resp := exaPubKeysResponse{
		Keys: make(map[string]string, len(req.Access)),
	}
	for _, access := range req.Access {
		if access == "" {
			return &Response{
				MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
			}, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		user, err := c.iam.GetUserAccount(access)
		if err != nil {
			if err == auth.ErrNoSuchUser {
				return &Response{
					MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
				}, s3err.GetAPIError(s3err.ErrInvalidAccessKeyID)
			}
			return &Response{
				MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
			}, err
		}
		if user.PublicKey == "" {
			return &Response{
				MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
			}, s3err.GetAPIError(s3err.ErrInvalidRequest)
		}
		resp.Keys[access] = user.PublicKey
	}

	body, err := json.Marshal(resp)
	if err != nil {
		return &Response{
			MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
		}, s3err.GetAPIError(s3err.ErrInternalError)
	}

	return &Response{
		Data: body,
		Headers: map[string]*string{
			"Content-Type": utils.GetStringPtr(fiber.MIMEApplicationJSON),
		},
		MetaOpts: &MetaOptions{BucketOwner: parsedAcl.Owner},
	}, nil
}

func authorizeExaKeysRead(acct auth.Account, isRoot bool, acl auth.ACL) error {
	if isRoot || acct.Role == auth.RoleAdmin {
		return nil
	}
	if err := auth.VerifyACL(acl, acct.Access, auth.PermissionRead); err == nil {
		return nil
	}
	if err := auth.VerifyACL(acl, acct.Access, auth.PermissionWrite); err == nil {
		return nil
	}
	return s3err.GetAPIError(s3err.ErrAccessDenied)
}

func authorizeExaOwner(acct auth.Account, isRoot bool, acl auth.ACL) error {
	if isRoot {
		return nil
	}
	if acct.Access == acl.Owner {
		return nil
	}
	return s3err.GetAPIError(s3err.ErrAccessDenied)
}
