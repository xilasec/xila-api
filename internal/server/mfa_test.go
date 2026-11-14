package server

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// totp is an authenticator app: the RFC 6238 code for secret at step offset d
// from now.
func totp(t *testing.T, secret string, d int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(time.Now().Unix()/30+d))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[off:off+4])&0x7fffffff)%1_000_000)
}

// Two-factor sign-in end to end: enrollment proves a code before it counts,
// sign-in then needs a code (once), recovery codes work once, wrong codes are
// capped, a reset link can't skip it, and an admin can reset a lost device.
func TestTwoFactorSignIn(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "owner@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")
	bobID := userIDOf(t, app, admin, "bob@xila.io")
	login := func() map[string]any {
		t.Helper()
		_, body := req(t, app, http.MethodPost, "/api/v1/auth/login", "", `{"email":"bob@xila.io","password":"supersecret"}`)
		return body
	}
	verify := func(challenge, code string) (int, map[string]any) {
		t.Helper()
		resp, body := req(t, app, http.MethodPost, "/api/v1/auth/mfa", "", `{"mfa_token":"`+challenge+`","code":"`+code+`"}`)
		return resp.StatusCode, body
	}

	// Enrollment: a secret, then a wrong code changes nothing, a right one enables.
	_, setup := req(t, app, http.MethodPost, "/api/v1/me/mfa/setup", bob, "")
	secret, _ := setup["secret"].(string)
	if secret == "" || !strings.HasPrefix(fmt.Sprint(setup["otpauth_url"]), "otpauth://totp/Xila:bob@xila.io?") {
		t.Fatalf("setup = %v", setup)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/me/mfa/enable", bob, `{"code":"000000"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("enable with a wrong code = %d", resp.StatusCode)
	}
	if body := login(); body["token"] == nil {
		t.Fatalf("a pending (unconfirmed) secret must not change sign-in: %v", body)
	}
	resp, en := req(t, app, http.MethodPost, "/api/v1/me/mfa/enable", bob, `{"code":"`+totp(t, secret, 0)+`"}`)
	codes, _ := en["recovery_codes"].([]any)
	if resp.StatusCode != http.StatusOK || len(codes) != 10 {
		t.Fatalf("enable = %d %v", resp.StatusCode, en)
	}

	// Sign-in: the password alone yields a challenge, not a session.
	first := login()
	challenge, _ := first["mfa_token"].(string)
	if first["mfa_required"] != true || first["token"] != nil || challenge == "" {
		t.Fatalf("password step with MFA = %v", first)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", challenge, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("the challenge token used as a session = %d, want 401", resp.StatusCode)
	}
	if code, _ := verify(challenge, "123456"); code != http.StatusUnauthorized {
		t.Errorf("wrong code = %d", code)
	}
	// The enrollment code's step is spent; the next step's code works once.
	next := totp(t, secret, 1)
	code, out := verify(challenge, next)
	if code != http.StatusOK || out["token"] == nil {
		t.Fatalf("right code = %d %v", code, out)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", out["token"].(string), ""); resp.StatusCode != http.StatusOK {
		t.Errorf("session after MFA = %d", resp.StatusCode)
	}
	if code, _ := verify(login()["mfa_token"].(string), next); code != http.StatusUnauthorized {
		t.Errorf("replaying a used code = %d, want 401", code)
	}

	// A recovery code works once, typed any way.
	rc := strings.ToUpper(codes[0].(string))
	if code, _ := verify(login()["mfa_token"].(string), " "+rc+" "); code != http.StatusOK {
		t.Errorf("recovery code = %d", code)
	}
	if code, _ := verify(login()["mfa_token"].(string), rc); code != http.StatusUnauthorized {
		t.Errorf("reused recovery code = %d", code)
	}
	if _, st := req(t, app, http.MethodGet, "/api/v1/me/mfa", out["token"].(string), ""); st["enabled"] != true || st["recovery_codes_left"] != float64(9) {
		t.Errorf("status = %v", st)
	}

	// A password reset link doesn't skip the second factor.
	_, link := req(t, app, http.MethodPost, "/api/v1/users/"+bobID+"/password-reset-link", admin, "")
	_, tok, _ := strings.Cut(link["url"].(string), "#token=")
	_, reset := req(t, app, http.MethodPost, "/api/v1/auth/password-reset/confirm", "", `{"token":"`+tok+`","password":"supersecret"}`)
	if reset["mfa_required"] != true || reset["token"] != nil {
		t.Errorf("reset with MFA = %v; want a challenge, not a session", reset)
	}

	// Guessing is capped per account (5 per 15 minutes in total).
	var last int
	for range 5 {
		last, _ = verify(login()["mfa_token"].(string), "000000")
	}
	if last != http.StatusTooManyRequests {
		t.Errorf("after repeated wrong codes = %d, want 429", last)
	}

	// Lost device: an admin resets it; the password alone works again.
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/users/"+bobID+"/mfa", admin, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("admin reset = %d", resp.StatusCode)
	}
	if body := login(); body["token"] == nil {
		t.Errorf("after reset, sign-in = %v", body)
	}
}
