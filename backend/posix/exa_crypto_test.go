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

package posix

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"filippo.io/hpke"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/fxamacker/cbor/v2"
	exastream "github.com/lunixbochs/sage/stream"
	"github.com/stretchr/testify/require"
	"github.com/versity/versitygw/backend"
	"github.com/versity/versitygw/backend/meta"
	"github.com/versity/versitygw/internal/exa"
	"github.com/versity/versitygw/s3response"
)

func TestCompleteMultipartUploadExaState(t *testing.T) {
	privateKey, err := hpke.MLKEM768X25519().GenerateKey()
	require.NoError(t, err)
	secret, err := privateKey.Bytes()
	require.NoError(t, err)
	fullAccess := &exa.ExaAccess{Version: 1, Access: "test-access", Secret: secret}
	authOnlyAccess := &exa.ExaAccess{Version: 1, Access: fullAccess.Access}

	bucketKey := []byte("0123456789abcdef")
	enc, sender, err := hpke.NewSender(privateKey.PublicKey(), hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte("age-encryption.org/mlkem768x25519"))
	require.NoError(t, err)
	sealedKey, err := sender.Seal(nil, bucketKey)
	require.NoError(t, err)
	wrappedKey, err := cbor.Marshal(map[string]any{"v": uint64(1), "e": enc, "c": sealedKey})
	require.NoError(t, err)

	plaintext := []byte("multipart completion must preserve the upload's encryption mode")
	nonce, err := exaRandomNonce()
	require.NoError(t, err)
	fileKey, err := exa.DeriveFileKey(bucketKey, nonce)
	require.NoError(t, err)
	streamKey, err := exa.DeriveStreamKey(fileKey, nonce)
	require.NoError(t, err)
	encryptReader, err := exastream.NewEncryptReader(streamKey, bytes.NewReader(plaintext))
	require.NoError(t, err)
	payload, err := io.ReadAll(encryptReader)
	require.NoError(t, err)
	ciphertext := append(nonce, payload...)
	version := uint64(7)

	for _, metadataType := range []string{"xattr", "sidecar"} {
		t.Run(metadataType, func(t *testing.T) {
			for _, tc := range []struct {
				name          string
				access        *exa.ExaAccess
				keyVersion    *uint64
				body          []byte
				wantEncrypted bool
			}{
				{name: "plaintext", body: plaintext},
				{name: "server", access: fullAccess, body: plaintext, wantEncrypted: true},
				{name: "client", access: authOnlyAccess, keyVersion: &version, body: ciphertext, wantEncrypted: true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					root := t.TempDir()
					t.Chdir(root)
					var metadata meta.MetadataStorer = meta.XattrMeta{}
					if metadataType == "sidecar" {
						sidecar, err := meta.NewSideCar(t.TempDir())
						require.NoError(t, err)
						metadata = sidecar
					} else if err := (meta.XattrMeta{}).Test(root); err != nil {
						t.Skipf("xattrs unavailable: %v", err)
					}
					p, err := New(root, metadata, PosixOpts{NewDirPerm: 0755})
					require.NoError(t, err)
					t.Cleanup(p.Shutdown)

					bucket, object := "test-bucket", "test-object"
					require.NoError(t, os.Mkdir(bucket, 0755))
					require.NoError(t, p.PutBucketExaKeys(t.Context(), bucket, version, map[string][]byte{fullAccess.Access: wrappedKey}))
					ctx := t.Context()
					if tc.access != nil {
						ctx = context.WithValue(ctx, backend.ExaContextAccessKey, tc.access)
					}

					upload, err := p.CreateMultipartUpload(ctx, s3response.CreateMultipartUploadInput{
						Bucket: &bucket, Key: &object, ExaKeyVersion: tc.keyVersion,
					})
					require.NoError(t, err)
					part, err := p.UploadPart(ctx, &s3.UploadPartInput{
						Bucket: &bucket, Key: &object, UploadId: &upload.UploadId,
						PartNumber: aws.Int32(1), ContentLength: aws.Int64(int64(len(tc.body))),
						Body: bytes.NewReader(tc.body),
					})
					require.NoError(t, err)

					// Completion renames the upload directory before reading its Exa state.
					_, _, err = p.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
						Bucket: &bucket, Key: &object, UploadId: &upload.UploadId,
						MultipartUpload: &types.CompletedMultipartUpload{
							Parts: []types.CompletedPart{{PartNumber: aws.Int32(1), ETag: part.ETag}},
						},
					})
					require.NoError(t, err)

					stored, err := os.ReadFile(filepath.Join(bucket, object))
					require.NoError(t, err)
					storedVersion, err := metadata.RetrieveAttribute(nil, bucket, object, backend.ExaObjectKVKey)
					if tc.wantEncrypted {
						require.NoError(t, err)
						require.Equal(t, "7", string(storedVersion))
						require.NotEqual(t, plaintext, stored)
					} else {
						require.ErrorIs(t, err, meta.ErrNoSuchKey)
						require.Equal(t, plaintext, stored)
					}
					if tc.keyVersion != nil {
						require.Equal(t, ciphertext, stored, "client ciphertext must be preserved")
					}

					readCtx := context.WithValue(t.Context(), backend.ExaContextAccessKey, fullAccess)
					result, err := p.GetObject(readCtx, &s3.GetObjectInput{Bucket: &bucket, Key: &object})
					require.NoError(t, err)
					defer result.Body.Close()
					got, err := io.ReadAll(result.Body)
					require.NoError(t, err)
					require.Equal(t, plaintext, got)
				})
			}
		})
	}
}
