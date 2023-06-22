package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

var (
	shortTimeout = 10 * time.Second
)

func setup(s *S3Conf, bucket string) error {
	s3client := s3.NewFromConfig(s.Config())

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := s3client.CreateBucket(ctx, &s3.CreateBucketInput{
		Bucket: &bucket,
	})
	cancel()
	return err
}

func teardown(s *S3Conf, bucket string) error {
	s3client := s3.NewFromConfig(s.Config())

	deleteObject := func(bucket, key, versionId *string) error {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		_, err := s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    bucket,
			Key:       key,
			VersionId: versionId,
		})
		cancel()
		if err != nil {
			return fmt.Errorf("failed to delete object %v: %v", *key, err)
		}
		return nil
	}

	in := &s3.ListObjectsV2Input{Bucket: &bucket}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
		out, err := s3client.ListObjectsV2(ctx, in)
		cancel()
		if err != nil {
			return fmt.Errorf("failed to list objects: %v", err)
		}

		for _, item := range out.Contents {
			err = deleteObject(&bucket, item.Key, nil)
			if err != nil {
				return err
			}
		}

		if out.IsTruncated {
			in.ContinuationToken = out.ContinuationToken
		} else {
			break
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err := s3client.DeleteBucket(ctx, &s3.DeleteBucketInput{
		Bucket: &bucket,
	})
	cancel()
	return err
}

func TestMakeBucket(s *S3Conf) {
	testname := "test make bucket"
	runF(testname)

	bucket := "testbucket"

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	passF(testname)

	testname = "test delete empty bucket"
	runF(testname)

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	passF(testname)
}

func TestPutGetObject(s *S3Conf) {
	testname := "test put/get object"
	runF(testname)

	bucket := "testbucket1"

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	// use funny size to prevent accidental alignments
	datalen := 1234567
	data := make([]byte, datalen)
	rand.Read(data)
	csum := sha256.Sum256(data)
	r := bytes.NewReader(data)

	name := "myobject"
	s3client := s3.NewFromConfig(s.Config())

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &name,
		Body:   r,
	})
	cancel()
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &name,
	})
	defer cancel()
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	defer out.Body.Close()

	if out.ContentLength != int64(datalen) {
		failF("%v: content length got %v expected %v", testname, out.ContentLength, datalen)
		return
	}

	b, err := io.ReadAll(out.Body)
	if err != nil {
		failF("%v: read body %v", testname, err)
		return
	}

	newsum := sha256.Sum256(b)
	if csum != newsum {
		failF("%v: checksum got %x expected %x", testname, newsum, csum)
		return
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	passF(testname)
}

func TestPutGetMPObject(s *S3Conf) {
	testname := "test put/get multipart object"
	runF(testname)

	bucket := "testbucket2"

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	name := "mympuobject"
	s3client := s3.NewFromConfig(s.Config())

	datalen := 10*1024*1024 + 15
	dr := NewDataReader(datalen, 5*1024*1024)
	WithPartSize(5 * 1024 * 1024)
	s.PartSize = 5 * 1024 * 1024
	err = uploadData(s, dr, bucket, name)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &name,
	})
	defer cancel()
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	defer out.Body.Close()

	if out.ContentLength != int64(datalen) {
		failF("%v: content length got %v expected %v", testname, out.ContentLength, datalen)
		return
	}

	b := make([]byte, 1048576)
	h := sha256.New()
	for {
		n, err := out.Body.Read(b)
		if err == io.EOF {
			h.Write(b[:n])
			break
		}
		if err != nil {
			failF("%v: read %v", err)
			return
		}
		h.Write(b[:n])
	}

	if !isEqual(dr.Sum(), h.Sum(nil)) {
		failF("%v: checksum got %x expected %x", testname, h.Sum(nil), dr.Sum())
		return
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	passF(testname)
}

func isEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	for i, d := range a {
		if d != b[i] {
			return false
		}
	}

	return true
}

func uploadData(s *S3Conf, r io.Reader, bucket, object string) error {
	uploader := manager.NewUploader(s3.NewFromConfig(s.Config()))
	uploader.PartSize = s.PartSize
	uploader.Concurrency = s.Concurrency

	upinfo := &s3.PutObjectInput{
		Body:   r,
		Bucket: &bucket,
		Key:    &object,
	}

	_, err := uploader.Upload(context.Background(), upinfo)
	return err
}

func TestPutDirObject(s *S3Conf) {
	testname := "test put directory object"
	runF(testname)

	bucket := "testbucket3"

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	name := "myobjectdir/"
	s3client := s3.NewFromConfig(s.Config())

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &name,
	})
	cancel()
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
	cancel()
	if err != nil {
		failF("failed to list objects: %v", err)
		return
	}

	if !contains(name, out.Contents) {
		failF("directory object not found")
		return
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	passF(testname)
}

func TestListObject(s *S3Conf) {
	testname := "list objects"
	runF(testname)

	bucket := "testbucket4"

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	s3client := s3.NewFromConfig(s.Config())

	dir1 := "myobjectdir/"
	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &dir1,
	})
	cancel()
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	obj1 := "myobjectdir/myobject"
	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &obj1,
	})
	cancel()
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	obj2 := "myobjectdir1/myobject"
	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &obj2,
	})
	cancel()
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	// put:
	// "myobjectdir/"
	// "myobjectdir/myobject"
	// "myobjectdir1/myobject"
	// should return:
	// "myobjectdir/myobject"
	// "myobjectdir1/myobject"

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	out, err := s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
	cancel()
	if err != nil {
		failF("failed to list objects: %v", err)
		return
	}

	if !contains(obj1, out.Contents) {
		failF("object %v not found", obj1)
		return
	}
	if !contains(obj2, out.Contents) {
		failF("object %v not found", obj2)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &obj1,
	})
	cancel()
	if err != nil {
		failF("failed to delete %v: %v", obj1, err)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: &bucket,
		Key:    &obj2,
	})
	cancel()
	if err != nil {
		failF("failed to delete %v: %v", obj2, err)
		return
	}

	// put:
	// "myobjectdir/"
	// "myobjectdir/myobject"
	// "myobjectdir1/myobject"
	// delete:
	// "myobjectdir/myobject"
	// "myobjectdir1/myobject"
	// should return:
	// "myobjectdir/"

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	out, err = s3client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{Bucket: &bucket})
	cancel()
	if err != nil {
		failF("failed to list objects: %v", err)
		return
	}

	if !contains(dir1, out.Contents) {
		failF("dir %v not found", dir1)
		return
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	passF(testname)
}

func contains(name string, list []types.Object) bool {
	for _, item := range list {
		fmt.Println(*item.Key)
		if strings.EqualFold(name, *item.Key) {
			return true
		}
	}
	return false
}

func TestListAbortMultiPartObject(s *S3Conf) {
	testname := "list/abort multipart objects"
	runF(testname)

	bucket := "testbucket6"

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	s3client := s3.NewFromConfig(s.Config())

	obj := "mympuobject"

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	mpu, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: &bucket,
		Key:    &obj,
	})
	cancel()
	if err != nil {
		failF("%v: create multipart upload: %v", testname, err)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	lmpu, err := s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket: &bucket,
	})
	cancel()
	if err != nil {
		failF("%v: list multipart upload: %v", testname, err)
		return
	}

	//for _, item := range lmpu.Uploads {
	//	fmt.Println(" -- ", *item.Key, *item.UploadId)
	//}

	if !containsUID(obj, *mpu.UploadId, lmpu.Uploads) {
		failF("%v: upload %v/%v not found", testname, obj, *mpu.UploadId)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.AbortMultipartUpload(ctx, &s3.AbortMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &obj,
		UploadId: mpu.UploadId,
	})
	cancel()
	if err != nil {
		failF("%v: abort multipart upload: %v", testname, err)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	lmpu, err = s3client.ListMultipartUploads(ctx, &s3.ListMultipartUploadsInput{
		Bucket: &bucket,
	})
	cancel()
	if err != nil {
		failF("%v: list multipart upload: %v", testname, err)
		return
	}

	if len(lmpu.Uploads) != 0 {
		for _, item := range lmpu.Uploads {
			fmt.Println(" D- ", *item.Key, *item.UploadId)
		}
		failF("%v: unexpected multipart uploads found", testname)
		return
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	passF(testname)
}

func containsUID(name, id string, list []types.MultipartUpload) bool {
	for _, item := range list {
		if strings.EqualFold(name, *item.Key) && strings.EqualFold(id, *item.UploadId) {
			return true
		}
	}
	return false
}

func TestListMultiParts(s *S3Conf) {
	testname := "list multipart parts"
	runF(testname)

	bucket := "testbucket7"

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	s3client := s3.NewFromConfig(s.Config())

	obj := "mympuobject"

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	mpu, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: &bucket,
		Key:    &obj,
	})
	cancel()
	if err != nil {
		failF("%v: create multipart upload: %v", testname, err)
		return
	}

	// check list parts of no parts is good
	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	lp, err := s3client.ListParts(ctx, &s3.ListPartsInput{
		Bucket:   &bucket,
		Key:      &obj,
		UploadId: mpu.UploadId,
	})
	cancel()
	if err != nil {
		failF("%v: list parts: %v", testname, err)
		return
	}

	if len(lp.Parts) != 0 {
		failF("%v: list parts: expected no parts, got %v",
			testname, len(lp.Parts))
		return
	}

	// upload 1 part and check list parts
	size5MB := 5 * 1024 * 1024
	dr := NewDataReader(size5MB, size5MB)

	datafile := "rand.data"
	w, err := os.Create(datafile)
	if err != nil {
		failF("%v: create %v: %v", testname, datafile, err)
		return
	}
	defer w.Close()

	_, err = io.Copy(w, dr)
	if err != nil {
		failF("%v: write %v: %v", testname, datafile, err)
		return
	}

	_, err = w.Seek(0, io.SeekStart)
	if err != nil {
		failF("%v: seek %v: %v", testname, datafile, err)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        &bucket,
		Key:           &obj,
		PartNumber:    42,
		UploadId:      mpu.UploadId,
		Body:          w,
		ContentLength: int64(size5MB),
	})
	cancel()
	if err != nil {
		failF("%v: multipart put part: %v", testname, err)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	lp, err = s3client.ListParts(ctx, &s3.ListPartsInput{
		Bucket:   &bucket,
		Key:      &obj,
		UploadId: mpu.UploadId,
	})
	cancel()
	if err != nil {
		failF("%v: list parts: %v", testname, err)
		return
	}

	//for _, part := range lp.Parts {
	//	fmt.Println(" -- ", part.PartNumber, part.ETag)
	//}

	if len(lp.Parts) != 1 || lp.Parts[0].PartNumber != 42 {
		fmt.Printf("%+v, %v, %v\n", lp.Parts, *lp.Key, *lp.UploadId)
		failF("%v: list parts: unexpected parts listing", testname)
		return
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	passF(testname)
}

func TestIncorrectMultiParts(s *S3Conf) {
	testname := "incorrect multipart parts"
	runF(testname)

	bucket := "testbucket8"

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	s3client := s3.NewFromConfig(s.Config())

	obj := "mympuobject"

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	mpu, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: &bucket,
		Key:    &obj,
	})
	cancel()
	if err != nil {
		failF("%v: create multipart upload: %v", testname, err)
		return
	}

	// upload 2 parts
	size5MB := 5 * 1024 * 1024
	dr := NewDataReader(size5MB, size5MB)

	datafile := "rand.data"
	w, err := os.Create(datafile)
	if err != nil {
		failF("%v: create %v: %v", testname, datafile, err)
		return
	}
	defer w.Close()

	_, err = io.Copy(w, dr)
	if err != nil {
		failF("%v: write %v: %v", testname, datafile, err)
		return
	}

	_, err = w.Seek(0, io.SeekStart)
	if err != nil {
		failF("%v: seek %v: %v", testname, datafile, err)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	mp1, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        &bucket,
		Key:           &obj,
		PartNumber:    42,
		UploadId:      mpu.UploadId,
		Body:          w,
		ContentLength: int64(size5MB),
	})
	cancel()
	if err != nil {
		failF("%v: multipart put part 1: %v", testname, err)
		return
	}

	_, err = w.Seek(0, io.SeekStart)
	if err != nil {
		failF("%v: seek %v: %v", testname, datafile, err)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	mp2, err := s3client.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        &bucket,
		Key:           &obj,
		PartNumber:    96,
		UploadId:      mpu.UploadId,
		Body:          w,
		ContentLength: int64(size5MB),
	})
	cancel()
	if err != nil {
		failF("%v: multipart put part 2: %v", testname, err)
		return
	}

	badEtag := "bogusEtagValue"

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &obj,
		UploadId: mpu.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{
				{
					ETag:       mp2.ETag,
					PartNumber: 96,
				},
				{
					ETag:       &badEtag,
					PartNumber: 99,
				},
			},
		},
	})
	cancel()
	if err == nil {
		failF("%v: complete multipart expected err", testname)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.CompleteMultipartUpload(ctx, &s3.CompleteMultipartUploadInput{
		Bucket:   &bucket,
		Key:      &obj,
		UploadId: mpu.UploadId,
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: []types.CompletedPart{
				{
					ETag:       mp1.ETag,
					PartNumber: 42,
				},
				{
					ETag:       mp2.ETag,
					PartNumber: 96,
				},
			},
		},
	})
	cancel()
	if err != nil {
		failF("%v: complete multipart: %v", testname, err)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	oi, err := s3client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &obj,
	})
	cancel()
	if err != nil {
		failF("%v: head object %v: %v", testname, obj, err)
		return
	}

	if oi.ContentLength != (int64(size5MB) * 2) {
		failF("%v: object len expected %v, got %v",
			testname, int64(size5MB)*2, oi.ContentLength)
		return
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	passF(testname)
}

func TestIncompleteMultiParts(s *S3Conf) {
	testname := "incomplete multipart parts"
	runF(testname)

	bucket := "testbucket9"

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	s3client := s3.NewFromConfig(s.Config())

	obj := "mympuobject"

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	mpu, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: &bucket,
		Key:    &obj,
	})
	cancel()
	if err != nil {
		failF("%v: create multipart upload: %v", testname, err)
		return
	}

	// upload 2 parts
	size5MB := 5 * 1024 * 1024
	size1MB := 1024 * 1024
	dr := NewDataReader(size1MB, size1MB)

	datafile := "rand.data"
	w, err := os.Create(datafile)
	if err != nil {
		failF("%v: create %v: %v", testname, datafile, err)
		return
	}
	defer w.Close()

	_, err = io.Copy(w, dr)
	if err != nil {
		failF("%v: write %v: %v", testname, datafile, err)
		return
	}

	_, err = w.Seek(0, io.SeekStart)
	if err != nil {
		failF("%v: seek %v: %v", testname, datafile, err)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        &bucket,
		Key:           &obj,
		PartNumber:    42,
		UploadId:      mpu.UploadId,
		Body:          w,
		ContentLength: int64(size5MB),
	})
	cancel()
	if err == nil {
		failF("%v: multipart put short part expected error", testname)
		return
	}

	// check list parts does not have incomplete part
	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	lp, err := s3client.ListParts(ctx, &s3.ListPartsInput{
		Bucket:   &bucket,
		Key:      &obj,
		UploadId: mpu.UploadId,
	})
	cancel()
	if err != nil {
		failF("%v: list parts: %v", testname, err)
		return
	}

	if containsPart(42, lp.Parts) {
		failF("%v: list parts: found incomplete part", testname)
		return
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	passF(testname)
}

func containsPart(part int32, list []types.Part) bool {
	for _, item := range list {
		if item.PartNumber == part {
			return true
		}
	}
	return false
}

func TestIncompletePutObject(s *S3Conf) {
	testname := "test incomplete put object"
	runF(testname)

	bucket := "testbucket10"

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	// use funny size to prevent accidental alignments
	datalen := 1234567
	shortdatalen := 12345
	data := make([]byte, shortdatalen)
	rand.Read(data)
	r := bytes.NewReader(data)

	name := "myobject"
	s3client := s3.NewFromConfig(s.Config())

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        &bucket,
		Key:           &name,
		Body:          r,
		ContentLength: int64(datalen),
	})
	cancel()
	if err == nil {
		failF("%v: expected error for short data put", testname)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &name,
	})
	defer cancel()
	if err == nil {
		failF("%v: expected object not exist", testname)
		return
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	passF(testname)
}

func TestRangeGet(s *S3Conf) {
	testname := "test range get"
	runF(testname)

	bucket := "testbucket11"

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	datalen := 10 * 1024
	data := make([]byte, datalen)
	rand.Read(data)
	r := bytes.NewReader(data)

	name := "myobject"
	s3client := s3.NewFromConfig(s.Config())

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: &bucket,
		Key:    &name,
		Body:   r,
	})
	cancel()
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	rangeString := "bytes=100-200"

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	out, err := s3client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &name,
		Range:  &rangeString,
	})
	defer cancel()
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	defer out.Body.Close()

	b, err := io.ReadAll(out.Body)
	if err != nil {
		failF("%v: read body %v", testname, err)
		return
	}

	// bytes range is inclusive, go range for second value is not
	if !isSame(b, data[100:201]) {
		failF("%v: data mismatch of range", testname)
		return
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	passF(testname)
}

func isSame(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, x := range a {
		if x != b[i] {
			return false
		}
	}
	return true
}

func TestInvalidMultiParts(s *S3Conf) {
	testname := "invalid multipart parts"
	runF(testname)

	bucket := "bucket12"

	err := setup(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}

	s3client := s3.NewFromConfig(s.Config())

	obj := "mympuobject"

	ctx, cancel := context.WithTimeout(context.Background(), shortTimeout)
	mpu, err := s3client.CreateMultipartUpload(ctx, &s3.CreateMultipartUploadInput{
		Bucket: &bucket,
		Key:    &obj,
	})
	cancel()
	if err != nil {
		failF("%v: create multipart upload: %v", testname, err)
		return
	}

	// upload 2 parts
	size5MB := 5 * 1024 * 1024
	dr := NewDataReader(size5MB, size5MB)

	datafile := "rand.data"
	w, err := os.Create(datafile)
	if err != nil {
		failF("%v: create %v: %v", testname, datafile, err)
		return
	}
	defer w.Close()

	_, err = io.Copy(w, dr)
	if err != nil {
		failF("%v: write %v: %v", testname, datafile, err)
		return
	}

	_, err = w.Seek(0, io.SeekStart)
	if err != nil {
		failF("%v: seek %v: %v", testname, datafile, err)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.UploadPart(ctx, &s3.UploadPartInput{
		Bucket:        &bucket,
		Key:           &obj,
		PartNumber:    -1,
		UploadId:      mpu.UploadId,
		Body:          w,
		ContentLength: int64(size5MB),
	})
	cancel()
	if err == nil {
		failF("%v: multipart put part 1 expected error", testname)
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), shortTimeout)
	_, err = s3client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: &bucket,
		Key:    &obj,
	})
	cancel()
	if err == nil {
		failF("%v: head object %v expected error", testname, obj)
		return
	}

	err = teardown(s, bucket)
	if err != nil {
		failF("%v: %v", testname, err)
		return
	}
	passF(testname)
}

// Full flow test
func TestFullFlow(s *S3Conf) {
	// TODO: add more test cases to get 100% coverage
	TestMakeBucket(s)
	TestPutGetObject(s)
	TestPutGetMPObject(s)
	TestPutDirObject(s)
	TestListObject(s)
	TestIncompletePutObject(s)
	TestListMultiParts(s)
	TestIncompleteMultiParts(s)
	TestIncorrectMultiParts(s)
	TestListAbortMultiPartObject(s)
	TestListAbortMultiPartObject(s)
	TestInvalidMultiParts(s)
}