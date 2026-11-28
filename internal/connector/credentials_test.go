package connector

import "testing"

// Credential parsing is the first gate on a connector's stored token: a
// malformed or incomplete token must be rejected with ErrInvalid before any
// network call is attempted.

func TestParseAWSCredentials(t *testing.T) {
	tests := []struct {
		name  string
		token string
		ok    bool
	}{
		{"full", `{"access_key_id":"AKIA","secret_access_key":"s3cr3t","session_token":"tok"}`, true},
		{"no session token (optional)", `{"access_key_id":"AKIA","secret_access_key":"s3cr3t"}`, true},
		{"missing secret", `{"access_key_id":"AKIA"}`, false},
		{"missing access key", `{"secret_access_key":"s3cr3t"}`, false},
		{"empty object", `{}`, false},
		{"not json", `AKIA:s3cr3t`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parseAWSCredentials(tc.token)
			if tc.ok {
				if err != nil {
					t.Fatalf("parseAWSCredentials(%q) = %v; want ok", tc.token, err)
				}
				if c.AccessKeyID == "" || c.SecretAccessKey == "" {
					t.Fatalf("parsed empty required field: %+v", c)
				}
			} else if err == nil {
				t.Fatalf("parseAWSCredentials(%q) = nil; want error", tc.token)
			}
		})
	}
}

func TestParseQualysCredentials(t *testing.T) {
	tests := []struct {
		name  string
		token string
		ok    bool
	}{
		{"full", `{"username":"u","password":"p"}`, true},
		{"missing password", `{"username":"u"}`, false},
		{"missing username", `{"password":"p"}`, false},
		{"empty object", `{}`, false},
		{"not json", `u/p`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseQualysCredentials(tc.token)
			if tc.ok && err != nil {
				t.Fatalf("parseQualysCredentials(%q) = %v; want ok", tc.token, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("parseQualysCredentials(%q) = nil; want error", tc.token)
			}
		})
	}
}

func TestParseTrivyCredentials(t *testing.T) {
	tests := []struct {
		name  string
		token string
		ok    bool
	}{
		{"full", `{"bearer_token":"tok","ca_pem":"-----BEGIN CERTIFICATE-----"}`, true},
		{"no ca_pem (optional)", `{"bearer_token":"tok"}`, true},
		{"missing bearer token", `{"ca_pem":"x"}`, false},
		{"empty object", `{}`, false},
		{"not json", `tok`, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, err := parseTrivyCredentials(tc.token)
			if tc.ok {
				if err != nil {
					t.Fatalf("parseTrivyCredentials(%q) = %v; want ok", tc.token, err)
				}
				if c.BearerToken == "" {
					t.Fatalf("parsed empty bearer token: %+v", c)
				}
			} else if err == nil {
				t.Fatalf("parseTrivyCredentials(%q) = nil; want error", tc.token)
			}
		})
	}
}
