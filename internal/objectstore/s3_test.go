package objectstore_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"

	"github.com/xilasec/xila-api/internal/objectstore"
	"github.com/xilasec/xila-api/internal/secretref"
)

// fakeS3 starts an in-process S3-compatible server with bucket created.
func fakeS3(t *testing.T, bucket string) string {
	t.Helper()
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())
	t.Cleanup(ts.Close)

	if err := backend.CreateBucket(bucket); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	return ts.URL
}

func client(t *testing.T, endpoint, bucket, prefix string) *objectstore.Client {
	t.Helper()
	c, err := objectstore.New(context.Background(), objectstore.Config{
		Endpoint:        endpoint,
		Region:          "us-east-1",
		Bucket:          bucket,
		Prefix:          prefix,
		AccessKeyID:     secretref.Static("test"),
		SecretAccessKey: secretref.Static("test"),
		ForcePathStyle:  true,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return c
}

func TestPutGetDeleteRoundTrip(t *testing.T) {
	endpoint := fakeS3(t, "xila-payloads")
	c := client(t, endpoint, "xila-payloads", "ingest")
	ctx := context.Background()

	key := "scan-jobs/scan-1"
	want := []byte(`{"findings":[]}`)
	if err := c.Put(ctx, key, want); err != nil {
		t.Fatalf("put: %v", err)
	}
	got, err := c.Get(ctx, key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("get = %q, want %q", got, want)
	}
	if err := c.Delete(ctx, key); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := c.Get(ctx, key); !errors.Is(err, objectstore.ErrNotFound) {
		t.Errorf("get after delete = %v, want ErrNotFound", err)
	}
	// Deleting an already-gone key is not an error (racing delete, or
	// retention cleaning up after the worker already did).
	if err := c.Delete(ctx, key); err != nil {
		t.Errorf("delete of a missing key: %v", err)
	}
}

// The prefix is applied under the hood; keys written with one prefix are not
// visible to a client configured with a different one (or no prefix), the
// same way they would not be if S3_PREFIX changed between deployments.
func TestPrefixIsolatesKeys(t *testing.T) {
	endpoint := fakeS3(t, "b")
	withPrefix := client(t, endpoint, "b", "ingest")
	noPrefix := client(t, endpoint, "b", "")
	ctx := context.Background()

	if err := withPrefix.Put(ctx, "scan-jobs/1", []byte("x")); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := noPrefix.Get(ctx, "scan-jobs/1"); !errors.Is(err, objectstore.ErrNotFound) {
		t.Errorf("unprefixed client should not see the prefixed object: %v", err)
	}
	if _, err := withPrefix.Get(ctx, "scan-jobs/1"); err != nil {
		t.Errorf("prefixed client should see its own object: %v", err)
	}
}

func TestGetMissingObjectFails(t *testing.T) {
	endpoint := fakeS3(t, "b")
	c := client(t, endpoint, "b", "")
	if _, err := c.Get(context.Background(), "scan-jobs/never-existed"); !errors.Is(err, objectstore.ErrNotFound) {
		t.Errorf("get of a never-written key = %v, want ErrNotFound", err)
	}
}

func TestNewFailsOnMissingBucket(t *testing.T) {
	endpoint := fakeS3(t, "exists")
	if _, err := objectstore.New(context.Background(), objectstore.Config{
		Endpoint: endpoint, Region: "us-east-1", Bucket: "does-not-exist",
		AccessKeyID: secretref.Static("test"), SecretAccessKey: secretref.Static("test"), ForcePathStyle: true,
	}); err == nil {
		t.Error("New with a nonexistent bucket should fail fast (HeadBucket)")
	}
}
