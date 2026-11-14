package notify_test

import (
	"errors"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/notify"
)

// The reference verifier accepts exactly what the dispatcher signs, and
// rejects a tampered body, a wrong secret, and a delivery replayed outside the
// five-minute window.
func TestVerifySignature(t *testing.T) {
	const secret = "whsec-0123456789abcdef" // gitleaks:allow -- fake test secret
	body := []byte(`{"type":"finding.critical","title":"boom"}`)
	now := time.Unix(1_800_000_000, 0)
	signed := func(ts time.Time, b []byte, sig ...string) http.Header {
		h := http.Header{}
		h.Set(notify.HeaderTimestamp, strconv.FormatInt(ts.Unix(), 10))
		if len(sig) > 0 {
			h.Set(notify.HeaderSignature, sig[0])
		} else {
			h.Set(notify.HeaderSignature, notify.Sign(secret, ts.Unix(), b))
		}
		return h
	}

	// Known answer (Python: hmac.new(secret, b"1800000000." + body, sha256)).
	if got, want := notify.Sign(secret, now.Unix(), body), "v1=a5a721ab87f7005cefe35551a80a329e6aac5a5e1691564b13aecae9f6027204"; got != want {
		t.Errorf("Sign = %q, want %q", got, want)
	}

	cases := []struct {
		name string
		h    http.Header
		body []byte
		at   time.Time
		want error
	}{
		{"valid", signed(now, body), body, now, nil},
		{"valid at the edge of the window", signed(now, body), body, now.Add(notify.SignatureTolerance), nil},
		{"one of several signatures (rotation)", signed(now, body, "v1=00ff, "+notify.Sign(secret, now.Unix(), body)), body, now, nil},
		{"tampered body", signed(now, body), []byte(`{"type":"finding.critical","title":"fine"}`), now, notify.ErrSignatureInvalid},
		{"wrong secret", signed(now, body, notify.Sign("another-secret-value", now.Unix(), body)), body, now, notify.ErrSignatureInvalid},
		{"timestamp swapped after signing", func() http.Header {
			h := signed(now, body)
			h.Set(notify.HeaderTimestamp, strconv.FormatInt(now.Unix()+1, 10))
			return h
		}(), body, now, notify.ErrSignatureInvalid},
		{"replayed 6 minutes later", signed(now, body), body, now.Add(6 * time.Minute), notify.ErrSignatureExpired},
		{"from the future", signed(now.Add(10*time.Minute), body), body, now, notify.ErrSignatureExpired},
		{"unsigned", http.Header{}, body, now, notify.ErrSignatureMissing},
		{"malformed timestamp", http.Header{notify.HeaderTimestamp: {"yesterday"}, notify.HeaderSignature: {"v1=00"}}, body, now, notify.ErrSignatureMalformed},
	}
	for _, c := range cases {
		if err := notify.VerifySignature(secret, c.h, c.body, c.at); !errors.Is(err, c.want) {
			t.Errorf("%s: VerifySignature = %v, want %v", c.name, err, c.want)
		}
	}
}
