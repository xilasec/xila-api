// Package objectstore stores large ingest payloads outside Postgres
// (INGEST_PAYLOAD_STORE=s3, M11 11.8): a million 1 MB scan reports is a
// terabyte of scan_jobs.payload traffic, which the durable queue (SELECT …
// FOR UPDATE SKIP LOCKED) was never meant to carry. Client talks to any
// S3-compatible service — AWS S3, MinIO, Ceph, Cloudflare R2, GCS's S3
// interop — through aws-sdk-go-v2, with every request going through
// internal/netguard because the endpoint comes from configuration.
package objectstore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/xilasec/xila-api/internal/netguard"
)

// ErrNotFound is returned by Get when the key has no object: a payload
// deleted out from under a stuck job, or a reference that never resolved.
var ErrNotFound = errors.New("object not found")

// Config is the S3 (or S3-compatible) connection setting (internal/config.S3).
type Config struct {
	// Endpoint overrides the default AWS regional endpoint — set it for
	// MinIO, Ceph, R2, GCS interop, or any other S3-compatible service. Empty
	// means AWS.
	Endpoint string
	Region   string
	Bucket   string
	// Prefix is joined under every key ("" = bucket root).
	Prefix string
	// AccessKeyID / SecretAccessKey are static credentials. Both empty uses
	// the standard AWS credential chain instead (env vars, shared config,
	// EC2/ECS instance credentials, EKS IRSA via AssumeRoleWithWebIdentity).
	AccessKeyID     string
	SecretAccessKey string
	// ForcePathStyle addresses buckets as /bucket/key instead of
	// bucket.host/key — required by most non-AWS S3-compatible services.
	ForcePathStyle bool
}

// Client stores scan-ingest payloads in one bucket/prefix.
type Client struct {
	s3     *s3.Client
	bucket string
	prefix string
}

// New builds a Client and verifies the bucket is reachable (HeadBucket), so a
// wrong bucket name or missing credentials fails at startup, not on the first
// upload.
func New(ctx context.Context, cfg Config) (*Client, error) {
	loadOpts := []func(*awsconfig.LoadOptions) error{
		awsconfig.WithRegion(cfg.Region),
		awsconfig.WithHTTPClient(netguard.NewClient(60 * time.Second)),
	}
	if cfg.AccessKeyID != "" || cfg.SecretAccessKey != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, "")))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}
	cli := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.ForcePathStyle
	})
	c := &Client{s3: cli, bucket: cfg.Bucket, prefix: strings.Trim(cfg.Prefix, "/")}
	if _, err := cli.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(cfg.Bucket)}); err != nil {
		return nil, fmt.Errorf("S3 bucket %q not reachable: %w", cfg.Bucket, err)
	}
	return c, nil
}

// objectKey joins key (store-relative, e.g. "scan-jobs/<scan id>") under the
// configured prefix. The caller-facing key (what scan_jobs.payload_ref holds)
// never includes the prefix, so changing S3_PREFIX doesn't orphan it mid-flight
// more than necessary — only the bucket/region identify where an object lives.
func (c *Client) objectKey(key string) string {
	if c.prefix == "" {
		return key
	}
	return path.Join(c.prefix, key)
}

// Put uploads payload under key.
func (c *Client) Put(ctx context.Context, key string, payload []byte) error {
	_, err := c.s3.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(c.objectKey(key)),
		Body:   bytes.NewReader(payload),
	})
	if err != nil {
		return fmt.Errorf("put %s: %w", key, err)
	}
	return nil
}

// Get downloads the object at key. ErrNotFound distinguishes a missing object
// from a transport or permission failure, so a worker can fail the job with a
// clear message instead of a generic one.
func (c *Client) Get(ctx context.Context, key string) ([]byte, error) {
	out, err := c.s3.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(c.objectKey(key)),
	})
	if err != nil {
		var nsk *types.NoSuchKey
		if errors.As(err, &nsk) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, key)
		}
		return nil, fmt.Errorf("get %s: %w", key, err)
	}
	defer out.Body.Close()
	data, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", key, err)
	}
	return data, nil
}

// Delete removes the object at key. S3's DeleteObject does not error on a
// missing key, so a repeated or racing delete (a job completed twice, or
// retention cleaning up after a worker already did) is not an error here.
func (c *Client) Delete(ctx context.Context, key string) error {
	if _, err := c.s3.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(c.bucket),
		Key:    aws.String(c.objectKey(key)),
	}); err != nil {
		return fmt.Errorf("delete %s: %w", key, err)
	}
	return nil
}
