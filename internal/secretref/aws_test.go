package secretref

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// fakeSecretsManager is a minimal AWS JSON-1.1 Secrets Manager fake: it reads
// the request body's SecretId and answers with a canned SecretString, so
// tests can check the request reaching it (SigV4 Authorization header,
// X-Amz-Target) without a real AWS account.
func fakeSecretsManager(t *testing.T, secretString string) (*httptest.Server, *http.Request, *string) {
	t.Helper()
	var lastReq *http.Request
	var lastSecretID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastReq = r.Clone(r.Context())
		var body struct {
			SecretID     string `json:"SecretId"`
			VersionStage string `json:"VersionStage"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		lastSecretID = body.SecretID
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ARN":          "arn:aws:secretsmanager:us-east-1:123456789012:secret:" + body.SecretID,
			"Name":         body.SecretID,
			"SecretString": secretString,
		})
	}))
	t.Cleanup(srv.Close)
	return srv, lastReq, &lastSecretID
}

func setAWSTestEnv(t *testing.T, endpoint string) {
	t.Helper()
	t.Setenv("AWS_ENDPOINT_URL_SECRETS_MANAGER", endpoint)
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAFAKE00000000EXAM")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "fakeSecretAccessKeyNotReal")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
}

func TestAWSSecretsManagerLiteral(t *testing.T) {
	srv, _, secretID := fakeSecretsManager(t, "a-plain-secret-value")
	setAWSTestEnv(t, srv.URL)

	r := NewResolver()
	v, err := r.Resolve(context.Background(), "aws-sm://my-secret")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "a-plain-secret-value" {
		t.Errorf("value = %q", v)
	}
	if *secretID != "my-secret" {
		t.Errorf("SecretId sent = %q, want my-secret", *secretID)
	}
}

// The AWS SDK must sign the request (SigV4) with the static credentials from
// the environment, and address the GetSecretValue operation.
func TestAWSSecretsManagerSigV4AndTarget(t *testing.T) {
	var gotAuth, gotTarget string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotTarget = r.Header.Get("X-Amz-Target")
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_ = json.NewEncoder(w).Encode(map[string]any{"SecretString": "v"})
	}))
	defer srv.Close()
	setAWSTestEnv(t, srv.URL)

	r := NewResolver()
	if _, err := r.Resolve(context.Background(), "aws-sm://my-secret"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !strings.HasPrefix(gotAuth, "AWS4-HMAC-SHA256 ") {
		t.Errorf("Authorization = %q, want a SigV4 header", gotAuth)
	}
	if !strings.Contains(gotAuth, "Credential=AKIAFAKE00000000EXAM/") {
		t.Errorf("Authorization = %q, want our static access key id", gotAuth)
	}
	if gotTarget != "secretsmanager.GetSecretValue" {
		t.Errorf("X-Amz-Target = %q", gotTarget)
	}
}

func TestAWSSecretsManagerJSONKey(t *testing.T) {
	srv, _, _ := fakeSecretsManager(t, `{"jwt":"s3cr3t-jwt","other":"unused"}`)
	setAWSTestEnv(t, srv.URL)

	r := NewResolver()
	v, err := r.Resolve(context.Background(), "aws-sm://my-secret#jwt")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if v != "s3cr3t-jwt" {
		t.Errorf("value = %q, want s3cr3t-jwt", v)
	}
}

func TestAWSSecretsManagerMissingKey(t *testing.T) {
	srv, _, _ := fakeSecretsManager(t, `{"jwt":"s3cr3t-jwt"}`)
	setAWSTestEnv(t, srv.URL)

	r := NewResolver()
	_, err := r.Resolve(context.Background(), "aws-sm://my-secret#does-not-exist")
	if err == nil {
		t.Fatal("expected an error for a missing JSON key")
	}
	if strings.Contains(err.Error(), "s3cr3t-jwt") {
		t.Errorf("error leaked the secret value: %v", err)
	}
}

func TestAWSSecretsManagerNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		w.Header().Set("X-Amzn-ErrorType", "ResourceNotFoundException")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"__type": "ResourceNotFoundException", "message": "Secrets Manager can't find the specified secret."})
	}))
	defer srv.Close()
	setAWSTestEnv(t, srv.URL)

	r := NewResolver()
	if _, err := r.Resolve(context.Background(), "aws-sm://missing"); err == nil {
		t.Fatal("expected an error for a secret the backend doesn't have")
	}
}

// region in an ARN selects that region's regional endpoint resolution via a
// per-call option override; this proves it doesn't panic and still reaches
// the fake (which the AWS_ENDPOINT_URL_SECRETS_MANAGER override serves for
// every region).
func TestAWSSecretsManagerARNRegion(t *testing.T) {
	srv, _, secretID := fakeSecretsManager(t, "v")
	setAWSTestEnv(t, srv.URL)

	arn := "arn:aws:secretsmanager:eu-west-1:123456789012:secret:xila/jwt-aBc123"
	r := NewResolver()
	if _, err := r.Resolve(context.Background(), "aws-sm://"+arn); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if *secretID != arn {
		t.Errorf("SecretId sent = %q, want the ARN", *secretID)
	}
}
