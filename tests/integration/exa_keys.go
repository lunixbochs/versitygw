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

package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
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

type exaWrappedKey struct {
	Access  string `json:"access"`
	Wrapped []byte `json:"wrapped"`
}

type exaPutKeysRequest struct {
	Version uint64          `json:"version"`
	Keys    []exaWrappedKey `json:"keys"`
}

type exaPubKeysRequest struct {
	Access []string `json:"access"`
}

type exaPubKeysResponse struct {
	Keys map[string]string `json:"keys"`
}

func ExaKeys_Put_owner_only(s *S3Conf) error {
	testName := "ExaKeys_Put_owner_only"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		testuser := getUser("user")
		if err := createUsers(s, []user{testuser}); err != nil {
			return err
		}

		body, err := json.Marshal(exaPutKeysRequest{
			Version: 1,
			Keys: []exaWrappedKey{
				{Access: testuser.access, Wrapped: []byte("wrapped")},
			},
		})
		if err != nil {
			return err
		}

		req, err := createSignedReq(
			http.MethodPut,
			s.endpoint,
			fmt.Sprintf("%s?exa-keys", bucket),
			testuser.access,
			testuser.secret,
			"s3",
			s.awsRegion,
			"",
			body,
			time.Now(),
			map[string]string{"Content-Type": "application/json"},
		)
		if err != nil {
			return err
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return err
		}
		if err := checkHTTPResponseApiErr(resp, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func ExaKeys_Get_read_permission(s *S3Conf) error {
	testName := "ExaKeys_Get_read_permission"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		reader := getUser("user")
		other := getUser("user")
		if err := createUsers(s, []user{reader, other}); err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.PutBucketAcl(ctx, &s3.PutBucketAclInput{
			Bucket:    &bucket,
			GrantRead: &reader.access,
		})
		cancel()
		if err != nil {
			return err
		}

		version := uint64(2)
		wrappedReader := []byte("reader-wrap")
		wrappedOther := []byte("other-wrap")
		putBody, err := json.Marshal(exaPutKeysRequest{
			Version: version,
			Keys: []exaWrappedKey{
				{Access: reader.access, Wrapped: wrappedReader},
				{Access: other.access, Wrapped: wrappedOther},
			},
		})
		if err != nil {
			return err
		}

		putReq, err := createSignedReq(
			http.MethodPut,
			s.endpoint,
			fmt.Sprintf("%s?exa-keys", bucket),
			s.awsID,
			s.awsSecret,
			"s3",
			s.awsRegion,
			"",
			putBody,
			time.Now(),
			map[string]string{"Content-Type": "application/json"},
		)
		if err != nil {
			return err
		}

		putResp, err := s.httpClient.Do(putReq)
		if err != nil {
			return err
		}
		if putResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(putResp.Body)
			putResp.Body.Close()
			return fmt.Errorf("unexpected put exa-keys status %d: %s", putResp.StatusCode, string(body))
		}
		putResp.Body.Close()

		getReq, err := createSignedReq(
			http.MethodGet,
			s.endpoint,
			fmt.Sprintf("%s?exa-keys", bucket),
			reader.access,
			reader.secret,
			"s3",
			s.awsRegion,
			"",
			nil,
			time.Now(),
			nil,
		)
		if err != nil {
			return err
		}

		getResp, err := s.httpClient.Do(getReq)
		if err != nil {
			return err
		}
		if getResp.StatusCode != http.StatusOK {
			if err := checkHTTPResponseApiErr(getResp, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
				return err
			}
			return fmt.Errorf("expected get exa-keys to succeed")
		}

		body, err := io.ReadAll(getResp.Body)
		getResp.Body.Close()
		if err != nil {
			return err
		}

		var resp exaKeysResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			return err
		}
		if resp.Current != version {
			return fmt.Errorf("expected current version %d, got %d", version, resp.Current)
		}
		if len(resp.Keys) != 1 {
			return fmt.Errorf("expected 1 key, got %d", len(resp.Keys))
		}
		if resp.Keys[0].Version != version {
			return fmt.Errorf("expected key version %d, got %d", version, resp.Keys[0].Version)
		}
		if string(resp.Keys[0].Wrapped) != string(wrappedReader) {
			return fmt.Errorf("unexpected wrapped key data")
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func ExaPubkeys_owner_only(s *S3Conf) error {
	testName := "ExaPubkeys_owner_only"
	return actionHandler(s, testName, func(s3client *s3.Client, bucket string) error {
		userWithKey := getUser("user")
		if err := createUsers(s, []user{userWithKey}); err != nil {
			return err
		}

		pubkey := "test-exa-pubkey"
		if err := updateUserPublicKey(s, userWithKey, pubkey); err != nil {
			return err
		}

		body, err := json.Marshal(exaPubKeysRequest{Access: []string{userWithKey.access}})
		if err != nil {
			return err
		}

		userReq, err := createSignedReq(
			http.MethodPost,
			s.endpoint,
			fmt.Sprintf("%s?exa-pubkeys", bucket),
			userWithKey.access,
			userWithKey.secret,
			"s3",
			s.awsRegion,
			"",
			body,
			time.Now(),
			map[string]string{"Content-Type": "application/json"},
		)
		if err != nil {
			return err
		}

		userResp, err := s.httpClient.Do(userReq)
		if err != nil {
			return err
		}
		if err := checkHTTPResponseApiErr(userResp, s3err.GetAPIError(s3err.ErrAccessDenied)); err != nil {
			return err
		}

		ownerReq, err := createSignedReq(
			http.MethodPost,
			s.endpoint,
			fmt.Sprintf("%s?exa-pubkeys", bucket),
			s.awsID,
			s.awsSecret,
			"s3",
			s.awsRegion,
			"",
			body,
			time.Now(),
			map[string]string{"Content-Type": "application/json"},
		)
		if err != nil {
			return err
		}

		ownerResp, err := s.httpClient.Do(ownerReq)
		if err != nil {
			return err
		}
		if ownerResp.StatusCode != http.StatusOK {
			respBody, _ := io.ReadAll(ownerResp.Body)
			ownerResp.Body.Close()
			return fmt.Errorf("unexpected exa-pubkeys status %d: %s", ownerResp.StatusCode, string(respBody))
		}

		respBody, err := io.ReadAll(ownerResp.Body)
		ownerResp.Body.Close()
		if err != nil {
			return err
		}

		var resp exaPubKeysResponse
		if err := json.Unmarshal(respBody, &resp); err != nil {
			return err
		}
		if resp.Keys[userWithKey.access] != pubkey {
			return fmt.Errorf("expected pubkey %q, got %q", pubkey, resp.Keys[userWithKey.access])
		}

		return nil
	}, withOwnership(types.ObjectOwnershipBucketOwnerPreferred))
}

func updateUserPublicKey(s *S3Conf, usr user, pubkey string) error {
	out, err := execCommand(s.getAdminCommand(
		"-a", s.awsID,
		"-s", s.awsSecret,
		"-er", s.endpoint,
		"update-user",
		"-a", usr.access,
		"--public-key", pubkey,
	)...)
	if err != nil {
		return err
	}
	if strings.Contains(string(out), adminErrorPrefix) {
		return fmt.Errorf("failed to update user public key: %s", out)
	}
	return nil
}
