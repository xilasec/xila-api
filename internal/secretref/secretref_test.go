package secretref

import (
	"context"
	"net"
	"strings"
	"testing"
)

func TestIsRef(t *testing.T) {
	cases := map[string]bool{
		"aws-sm://my-secret":                true,
		"aws-sm://my-secret#jwt":            true,
		"gcp-sm://projects/p/secrets/s":     true,
		"vault://kv/data/xila#jwt":          true,
		"azure-kv://myvault/my-secret":      true,
		"plain-literal-value":               false,
		"":                                  false,
		"postgres://user:pass@host/db":      false,
		"https://example.com/not-a-backend": false,
	}
	for in, want := range cases {
		if got := IsRef(in); got != want {
			t.Errorf("IsRef(%q) = %v, want %v", in, got, want)
		}
	}
}

// An ARN contains colons that net/url's authority parser would otherwise
// choke on ("invalid port"); the reference parser must not use url.Parse for
// the authority.
func TestParseARN(t *testing.T) {
	arn := "arn:aws:secretsmanager:us-east-1:123456789012:secret:xila/jwt-aBc123"
	r, ok := parse("aws-sm://" + arn + "#jwt")
	if !ok {
		t.Fatal("not recognized as a reference")
	}
	if r.path != arn {
		t.Errorf("path = %q, want %q", r.path, arn)
	}
	if r.key != "jwt" {
		t.Errorf("key = %q, want jwt", r.key)
	}
}

func TestParseAWSQuery(t *testing.T) {
	r, ok := parse("aws-sm://my-secret?version_stage=AWSPREVIOUS&region=eu-west-1#jwt")
	if !ok {
		t.Fatal("not recognized")
	}
	if r.path != "my-secret" || r.key != "jwt" {
		t.Fatalf("path=%q key=%q", r.path, r.key)
	}
	if got := r.query.Get("version_stage"); got != "AWSPREVIOUS" {
		t.Errorf("version_stage = %q", got)
	}
	if got := r.query.Get("region"); got != "eu-west-1" {
		t.Errorf("region = %q", got)
	}
}

// An unknown scheme is not a reference: the value is used literally.
func TestResolveRejectsNonReference(t *testing.T) {
	r := NewResolver()
	if _, err := r.Resolve(context.Background(), "a-literal-password"); err == nil {
		t.Error("resolving a non-reference should fail (callers must check IsRef first)")
	}
}

// A backend that cannot be reached fails without ever producing a value, and
// the error names the reference, not any secret content.
func TestResolveUnreachableBackend(t *testing.T) {
	// A closed listener: connections are refused immediately.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	t.Setenv("VAULT_ADDR", "http://"+addr)
	t.Setenv("VAULT_TOKEN", "root")

	r := NewResolver()
	_, err = r.Resolve(context.Background(), "vault://kv/data/xila#jwt")
	if err == nil {
		t.Fatal("expected an error talking to an unreachable Vault")
	}
	if !strings.HasPrefix(err.Error(), "vault://kv/data/xila: ") {
		t.Errorf("error = %q, want it to name the scheme and path", err.Error())
	}
}
