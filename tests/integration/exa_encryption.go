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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"filippo.io/hpke"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/fxamacker/cbor/v2"
	"github.com/versity/versitygw/internal/exa"
	exabech32 "github.com/versity/versitygw/internal/exa/bech32"
	exastream "github.com/versity/versitygw/internal/exa/stream"
	"github.com/versity/versitygw/s3err"
)

const (
	exaBech32Hrp     = "exa"
	exaAccessVersion = 1
	exaHpkeLabel     = "age-encryption.org/mlkem768x25519"
)

type exaWrappedKeyV1 struct {
	Version uint64 `cbor:"v"`
	Enc     []byte `cbor:"e"`
	Cipher  []byte `cbor:"c"`
}

func ExaEncryption_roundtrip(s *S3Conf) error {
	testName := "ExaEncryption_roundtrip"
	if s.azureTests {
		return nil
	}

	return actionHandler(s, testName, func(_ *s3.Client, bucket string) error {
		fullAccess, authOnlyAccess, bucketKey, version, err := setupExaKeys(s, bucket)
		if err != nil {
			return err
		}

		obj := "exa-obj"
		plaintext := []byte("exa roundtrip payload")
		if err := putSignedObject(s, bucket, obj, fullAccess, plaintext, nil); err != nil {
			return err
		}

		fullBody, fullHeaders, err := getSignedObject(s, bucket, obj, fullAccess, nil)
		if err != nil {
			return err
		}
		if !bytes.Equal(fullBody, plaintext) {
			return fmt.Errorf("expected plaintext with full key, got %q", string(fullBody))
		}
		if got := fullHeaders.Get("Content-Length"); got != strconv.Itoa(len(plaintext)) {
			return fmt.Errorf("expected plaintext content-length %d, got %q", len(plaintext), got)
		}

		authBody, authHeaders, err := getSignedObject(s, bucket, obj, authOnlyAccess, nil)
		if err != nil {
			return err
		}

		nonceHeader := authHeaders.Get("x-exa-nonce")
		if nonceHeader == "" {
			return fmt.Errorf("missing x-exa-nonce header")
		}
		versionHeader := authHeaders.Get("x-exa-key-version")
		if versionHeader == "" {
			return fmt.Errorf("missing x-exa-key-version header")
		}
		if versionHeader != strconv.FormatUint(version, 10) {
			return fmt.Errorf("expected key version %d, got %q", version, versionHeader)
		}
		nonce, err := base64.RawURLEncoding.DecodeString(nonceHeader)
		if err != nil {
			return fmt.Errorf("decode x-exa-nonce: %w", err)
		}
		if len(nonce) != exa.NonceSize {
			return fmt.Errorf("unexpected nonce length %d", len(nonce))
		}
		if len(authBody) < exa.NonceSize {
			return fmt.Errorf("ciphertext shorter than nonce prefix")
		}
		if !bytes.Equal(authBody[:exa.NonceSize], nonce) {
			return fmt.Errorf("nonce header does not match payload prefix")
		}

		expectedPayloadSize := exa.EncryptedPayloadSize(int64(len(plaintext)))
		expectedTotal := int64(exa.NonceSize) + expectedPayloadSize
		if int64(len(authBody)) != expectedTotal {
			return fmt.Errorf("expected ciphertext length %d, got %d", expectedTotal, len(authBody))
		}
		if got := authHeaders.Get("Content-Length"); got != strconv.FormatInt(expectedTotal, 10) {
			return fmt.Errorf("expected ciphertext content-length %d, got %q", expectedTotal, got)
		}

		payload := authBody[exa.NonceSize:]
		fileKey, err := exa.DeriveFileKey(bucketKey, nonce)
		if err != nil {
			return err
		}
		streamKey, err := exa.DeriveStreamKey(fileKey, nonce)
		if err != nil {
			return err
		}
		decReader, err := exastream.NewDecryptReader(streamKey, bytes.NewReader(payload))
		if err != nil {
			return err
		}
		decrypted, err := io.ReadAll(decReader)
		if err != nil {
			return err
		}
		if !bytes.Equal(decrypted, plaintext) {
			return fmt.Errorf("decrypted payload mismatch")
		}

		obj2 := "exa-obj-auth"
		plaintext2 := []byte("exa auth-only upload")
		nonce2 := make([]byte, exa.NonceSize)
		if _, err := rand.Read(nonce2); err != nil {
			return err
		}
		fileKey2, err := exa.DeriveFileKey(bucketKey, nonce2)
		if err != nil {
			return err
		}
		streamKey2, err := exa.DeriveStreamKey(fileKey2, nonce2)
		if err != nil {
			return err
		}
		encReader, err := exastream.NewEncryptReader(streamKey2, bytes.NewReader(plaintext2))
		if err != nil {
			return err
		}
		cipherPayload, err := io.ReadAll(encReader)
		if err != nil {
			return err
		}
		cipherBody := append(append([]byte(nil), nonce2...), cipherPayload...)
		headers := map[string]string{
			"x-exa-nonce":       base64.RawURLEncoding.EncodeToString(nonce2),
			"x-exa-key-version": strconv.FormatUint(version, 10),
		}
		if err := putSignedObject(s, bucket, obj2, authOnlyAccess, cipherBody, headers); err != nil {
			return err
		}

		fullBody2, _, err := getSignedObject(s, bucket, obj2, fullAccess, nil)
		if err != nil {
			return err
		}
		if !bytes.Equal(fullBody2, plaintext2) {
			return fmt.Errorf("expected plaintext after auth-only upload, got %q", string(fullBody2))
		}

		authConf := *s
		authConf.awsID = authOnlyAccess
		listClient := authConf.GetClient()
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		listRes, err := listClient.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
		cancel()
		if err != nil {
			return err
		}
		if len(listRes.Contents) != 2 {
			return fmt.Errorf("expected 2 objects, got %d", len(listRes.Contents))
		}
		sizes := map[string]int64{
			obj:  int64(len(plaintext)),
			obj2: int64(len(plaintext2)),
		}
		for _, entry := range listRes.Contents {
			key := getString(entry.Key)
			expectedSize, ok := sizes[key]
			if !ok {
				return fmt.Errorf("unexpected object in list: %q", key)
			}
			if entry.Size == nil || *entry.Size != expectedSize {
				return fmt.Errorf("expected size %d for %q, got %v", expectedSize, key, entry.Size)
			}
		}

		return nil
	})
}

func ExaEncryption_canary_put(s *S3Conf) error {
	testName := "ExaEncryption_canary_put"
	if s.azureTests {
		return nil
	}

	return actionHandler(s, testName, func(_ *s3.Client, bucket string) error {
		fullAccess, authOnlyAccess, _, _, err := setupExaKeys(s, bucket)
		if err != nil {
			return err
		}

		random := make([]byte, 24)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		canary := []byte("exa-canary-" + hex.EncodeToString(random))
		payload := append([]byte("payload:"), canary...)

		obj := "exa-canary"
		if err := putSignedObject(s, bucket, obj, fullAccess, payload, nil); err != nil {
			return err
		}

		fullBody, _, err := getSignedObject(s, bucket, obj, fullAccess, nil)
		if err != nil {
			return err
		}
		if !bytes.Equal(fullBody, payload) {
			return fmt.Errorf("expected plaintext canary, got %q", string(fullBody))
		}

		authBody, _, err := getSignedObject(s, bucket, obj, authOnlyAccess, nil)
		if err != nil {
			return err
		}
		if bytes.Contains(authBody, canary) {
			return fmt.Errorf("auth-only read leaked canary")
		}

		return nil
	})
}

func ExaEncryption_canary_multipart(s *S3Conf) error {
	testName := "ExaEncryption_canary_multipart"
	if s.azureTests {
		return nil
	}

	return actionHandler(s, testName, func(_ *s3.Client, bucket string) error {
		fullAccess, authOnlyAccess, _, _, err := setupExaKeys(s, bucket)
		if err != nil {
			return err
		}

		exaConf := *s
		exaConf.awsID = fullAccess
		exaClient := exaConf.GetClient()

		obj := "exa-canary-mp"
		mp, err := createMp(exaClient, bucket, obj)
		if err != nil {
			return err
		}

		random := make([]byte, 24)
		if _, err := rand.Read(random); err != nil {
			return err
		}
		canary := []byte("exa-canary-" + hex.EncodeToString(random))

		const partSize = 5 * 1024 * 1024
		part1 := make([]byte, partSize)
		if _, err := rand.Read(part1); err != nil {
			return err
		}
		copy(part1, canary)
		part2 := make([]byte, partSize)
		if _, err := rand.Read(part2); err != nil {
			return err
		}

		plaintext := make([]byte, 0, len(part1)+len(part2))
		plaintext = append(plaintext, part1...)
		plaintext = append(plaintext, part2...)

		partsData := [][]byte{part1, part2}
		completedParts := make([]types.CompletedPart, 0, len(partsData))
		for i, data := range partsData {
			pn := int32(i + 1)
			ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
			out, err := exaClient.UploadPart(ctx, &s3.UploadPartInput{
				Bucket:     &bucket,
				Key:        &obj,
				UploadId:   mp.UploadId,
				PartNumber: &pn,
				Body:       bytes.NewReader(data),
			})
			cancel()
			if err != nil {
				return err
			}
			completedParts = append(completedParts, types.CompletedPart{
				ETag:       out.ETag,
				PartNumber: &pn,
			})
		}

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = exaClient.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: completedParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		fullBody, _, err := getSignedObject(s, bucket, obj, fullAccess, nil)
		if err != nil {
			return err
		}
		if !bytes.Equal(fullBody, plaintext) {
			return fmt.Errorf("expected plaintext multipart canary, got %d bytes", len(fullBody))
		}
		if !bytes.Contains(fullBody, canary) {
			return fmt.Errorf("expected canary in multipart plaintext")
		}

		authBody, _, err := getSignedObject(s, bucket, obj, authOnlyAccess, nil)
		if err != nil {
			return err
		}
		if bytes.Contains(authBody, canary) {
			return fmt.Errorf("auth-only read leaked multipart canary")
		}

		return nil
	})
}

func ExaEncryption_copy_cross_bucket_reject(s *S3Conf) error {
	testName := "ExaEncryption_copy_cross_bucket_reject"
	if s.azureTests {
		return nil
	}

	return actionHandler(s, testName, func(_ *s3.Client, bucket string) error {
		dstBucket := getBucketName()
		if err := setup(s, dstBucket); err != nil {
			return err
		}
		defer teardown(s, dstBucket)

		fullAccess, _, _, _, err := setupExaKeys(s, bucket)
		if err != nil {
			return err
		}

		obj := "exa-src"
		payload := []byte("copy source")
		if err := putSignedObject(s, bucket, obj, fullAccess, payload, nil); err != nil {
			return err
		}

		exaConf := *s
		exaConf.awsID = fullAccess
		exaClient := exaConf.GetClient()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = exaClient.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     &dstBucket,
			Key:        getPtr("exa-dst"),
			CopySource: getPtr(fmt.Sprintf("%s/%s", bucket, obj)),
		})
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrInvalidObjectState)); err != nil {
			return err
		}
		return nil
	})
}

func ExaEncryption_multipart_roundtrip(s *S3Conf) error {
	testName := "ExaEncryption_multipart_roundtrip"
	if s.azureTests {
		return nil
	}

	return actionHandler(s, testName, func(_ *s3.Client, bucket string) error {
		fullAccess, authOnlyAccess, _, _, err := setupExaKeys(s, bucket)
		if err != nil {
			return err
		}

		authConf := *s
		authConf.awsID = authOnlyAccess
		authClient := authConf.GetClient()

		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err = createMp(authClient, bucket, "exa-mp-auth-only")
		cancel()
		if err := checkApiErr(err, s3err.GetAPIError(s3err.ErrNotImplemented)); err != nil {
			return err
		}

		exaConf := *s
		exaConf.awsID = fullAccess
		exaClient := exaConf.GetClient()

		obj := "exa-mp"
		mp, err := createMp(exaClient, bucket, obj)
		if err != nil {
			return err
		}

		totalSize := int64(10 * 1024 * 1024)
		partCount := int64(2)
		parts, csum, err := uploadParts(exaClient, totalSize, partCount, bucket, obj, *mp.UploadId)
		if err != nil {
			return err
		}

		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		listRes, err := exaClient.ListParts(ctx, &s3.ListPartsInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
		})
		cancel()
		if err != nil {
			return err
		}
		if len(listRes.Parts) != int(partCount) {
			return fmt.Errorf("expected %d parts, got %d", partCount, len(listRes.Parts))
		}
		partSize := totalSize / partCount
		lastSize := totalSize - partSize*(partCount-1)
		for i, part := range listRes.Parts {
			if part.Size == nil {
				return fmt.Errorf("missing size for part %d", i+1)
			}
			expectedSize := partSize
			if int64(i) == partCount-1 {
				expectedSize = lastSize
			}
			if *part.Size != expectedSize {
				return fmt.Errorf("expected part size %d, got %d", expectedSize, *part.Size)
			}
		}

		completeParts := make([]types.CompletedPart, 0, len(parts))
		for _, part := range parts {
			completeParts = append(completeParts, types.CompletedPart{
				ETag:       part.ETag,
				PartNumber: part.PartNumber,
			})
		}
		ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
		_, err = exaClient.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
			Bucket:   &bucket,
			Key:      &obj,
			UploadId: mp.UploadId,
			MultipartUpload: &types.CompletedMultipartUpload{
				Parts: completeParts,
			},
		})
		cancel()
		if err != nil {
			return err
		}

		fullBody, _, err := getSignedObject(s, bucket, obj, fullAccess, nil)
		if err != nil {
			return err
		}
		fullSum := sha256.Sum256(fullBody)
		if hex.EncodeToString(fullSum[:]) != csum {
			return fmt.Errorf("multipart plaintext checksum mismatch")
		}

		authBody, authHeaders, err := getSignedObject(s, bucket, obj, authOnlyAccess, nil)
		if err != nil {
			return err
		}
		nonceHeader := authHeaders.Get("x-exa-nonce")
		if nonceHeader == "" {
			return fmt.Errorf("missing x-exa-nonce header")
		}
		nonce, err := base64.RawURLEncoding.DecodeString(nonceHeader)
		if err != nil {
			return fmt.Errorf("decode x-exa-nonce: %w", err)
		}
		if len(nonce) != exa.NonceSize {
			return fmt.Errorf("unexpected nonce length %d", len(nonce))
		}
		if len(authBody) < exa.NonceSize {
			return fmt.Errorf("ciphertext shorter than nonce prefix")
		}
		if !bytes.Equal(authBody[:exa.NonceSize], nonce) {
			return fmt.Errorf("nonce header does not match payload prefix")
		}

		expectedPayloadSize := exa.EncryptedPayloadSize(totalSize)
		expectedTotal := int64(exa.NonceSize) + expectedPayloadSize
		if int64(len(authBody)) != expectedTotal {
			return fmt.Errorf("expected ciphertext length %d, got %d", expectedTotal, len(authBody))
		}
		if got := authHeaders.Get("Content-Length"); got != strconv.FormatInt(expectedTotal, 10) {
			return fmt.Errorf("expected ciphertext content-length %d, got %q", expectedTotal, got)
		}

		return nil
	})
}

func setupExaKeys(s *S3Conf, bucket string) (string, string, []byte, uint64, error) {
	kem := hpke.MLKEM768X25519()
	priv, err := kem.GenerateKey()
	if err != nil {
		return "", "", nil, 0, err
	}
	secret, err := priv.Bytes()
	if err != nil {
		return "", "", nil, 0, err
	}

	bucketKey := make([]byte, exa.BucketKeySize)
	if _, err := rand.Read(bucketKey); err != nil {
		return "", "", nil, 0, err
	}

	wrapped, err := wrapBucketKey(priv.PublicKey(), bucketKey)
	if err != nil {
		return "", "", nil, 0, err
	}

	version := uint64(1)
	if err := putExaKeys(s, bucket, s.awsID, wrapped, version); err != nil {
		return "", "", nil, 0, err
	}

	fullAccess, err := makeExaAccessKey(s.awsID, secret)
	if err != nil {
		return "", "", nil, 0, err
	}
	authOnlyAccess, err := makeExaAccessKey(s.awsID, nil)
	if err != nil {
		return "", "", nil, 0, err
	}

	return fullAccess, authOnlyAccess, bucketKey, version, nil
}

func putExaKeys(s *S3Conf, bucket, access string, wrapped []byte, version uint64) error {
	body, err := json.Marshal(exaPutKeysRequest{
		Version: version,
		Keys: []exaWrappedKey{{
			Access:  access,
			Wrapped: wrapped,
		}},
	})
	if err != nil {
		return err
	}

	req, err := createSignedReq(
		http.MethodPut,
		s.endpoint,
		fmt.Sprintf("%s?exa-keys", bucket),
		s.awsID,
		s.awsSecret,
		"s3",
		s.awsRegion,
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
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return fmt.Errorf("unexpected exa-keys status %d: %s", resp.StatusCode, string(respBody))
	}
	resp.Body.Close()
	return nil
}

func wrapBucketKey(pub hpke.PublicKey, bucketKey []byte) ([]byte, error) {
	if len(bucketKey) != exa.BucketKeySize {
		return nil, fmt.Errorf("unexpected bucket key size %d", len(bucketKey))
	}
	enc, sender, err := hpke.NewSender(pub, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(exaHpkeLabel))
	if err != nil {
		return nil, err
	}
	ct, err := sender.Seal(nil, bucketKey)
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(exaWrappedKeyV1{Version: 1, Enc: enc, Cipher: ct})
}

func makeExaAccessKey(access string, secret []byte) (string, error) {
	payload := exa.ExaAccess{Version: exaAccessVersion, Access: access}
	if len(secret) > 0 {
		payload.Secret = secret
	}
	cborBytes, err := cbor.Marshal(payload)
	if err != nil {
		return "", err
	}
	return exabech32.Encode(exaBech32Hrp, cborBytes)
}

func putSignedObject(s *S3Conf, bucket, key, access string, body []byte, headers map[string]string) error {
	req, err := createSignedReq(
		http.MethodPut,
		s.endpoint,
		fmt.Sprintf("%s/%s", bucket, key),
		access,
		s.awsSecret,
		"s3",
		s.awsRegion,
		body,
		time.Now(),
		headers,
	)
	if err != nil {
		return err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return fmt.Errorf("unexpected put status %d: %s", resp.StatusCode, string(respBody))
	}
	resp.Body.Close()
	return nil
}

func getSignedObject(s *S3Conf, bucket, key, access string, headers map[string]string) ([]byte, http.Header, error) {
	req, err := createSignedReq(
		http.MethodGet,
		s.endpoint,
		fmt.Sprintf("%s/%s", bucket, key),
		access,
		s.awsSecret,
		"s3",
		s.awsRegion,
		nil,
		time.Now(),
		headers,
	)
	if err != nil {
		return nil, nil, err
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return nil, nil, fmt.Errorf("unexpected get status %d: %s", resp.StatusCode, string(respBody))
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, nil, err
	}
	return body, resp.Header, nil
}
