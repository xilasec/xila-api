package audit

import (
	"encoding/json"
	"strings"
)

// Redacted replaces every value the audit log must never hold.
const Redacted = "[REDACTED]"

// maxBodyBytes caps the request body an entry keeps. Larger bodies (scanner
// reports, SBOMs) are summarized by size: the scan/SBOM record is their audit
// trail, and copying them into the log would only duplicate data.
const maxBodyBytes = 16 << 10

// The redaction policy, in one place. A JSON key is compared lower-cased with
// '-' folded to '_'. It is redacted when it is in redactKeys, contains one of
// redactSubstrings or ends in "_key", unless it is in keepKeys (metadata about a secret, never the
// secret itself). Values that sit encrypted in secretbox — tracker / connector
// tokens and API keys, SSO client secrets and SP keys, MFA secrets, LDAP bind
// passwords — and webhook URLs (which embed their credential) are all covered.
var (
	redactKeys = map[string]bool{
		"key":          true, // connector / tracker API keys, SP keys
		"code":         true, // TOTP / recovery codes
		"otp":          true,
		"url":          true, // notification channels: webhook URLs carry their credential
		"webhook":      true,
		"sp_cert":      true,
		"idp_metadata": true, // may embed signing material; the URL form is kept
		"cookie":       true,
		"signature":    true,
	}
	redactSubstrings = []string{
		"password", "passwd", "passphrase", "secret", "token", "api_key", "apikey",
		"private_key", "privatekey", "credential", "authorization", "webhook", "recovery_code",
	}
	keepKeys = map[string]bool{
		"has_token":           true,
		"has_client_secret":   true,
		"has_password":        true,
		"has_sp_key":          true,
		"password_changed_at": true,
		"token_endpoint":      true,
		"is_secret":           true,
		"correlation_key":     true, // identifiers that merely end in _key
		"license_key":         true,
		"spdx_license_key":    true,
		"search_key":          true,
		"sort_key":            true,
	}
)

// sensitive reports whether a JSON key's value must be redacted.
func sensitive(key string) bool {
	k := strings.ReplaceAll(strings.ToLower(key), "-", "_")
	if keepKeys[k] {
		return false
	}
	if redactKeys[k] || strings.HasSuffix(k, "_key") {
		return true
	}
	for _, s := range redactSubstrings {
		if strings.Contains(k, s) {
			return true
		}
	}
	return false
}

// RedactValue returns v with every sensitive key's value replaced, at any depth.
func RedactValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if sensitive(k) {
				out[k] = Redacted
				continue
			}
			out[k] = RedactValue(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = RedactValue(val)
		}
		return out
	default:
		return v
	}
}

// RedactBody turns a request body into what an entry may store: a JSON body,
// redacted; anything else (multipart, raw reports, form posts) or anything over
// maxBodyBytes, only its type and size — never the bytes.
func RedactBody(body []byte, contentType string) any {
	if len(body) == 0 {
		return nil
	}
	summary := map[string]any{"content_type": contentType, "bytes": len(body)}
	if len(body) > maxBodyBytes {
		return summary
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return summary
	}
	return RedactValue(v)
}

// redactAny round-trips an arbitrary Go value (a handler's before / after
// state) through JSON so the same key policy applies to its field names.
func redactAny(v any) any {
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return RedactValue(out)
}
