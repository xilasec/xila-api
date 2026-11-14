package notify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Webhook signing headers. A generic webhook channel with a signing secret
// signs every delivery; X-Xila-Delivery is sent either way and stays the same
// across retries of one outbox row, so a receiver can drop duplicates.
const (
	HeaderTimestamp = "X-Xila-Timestamp" // unix seconds of this attempt
	HeaderSignature = "X-Xila-Signature" // v1=<hex hmac-sha256(secret, timestamp + "." + body)>
	HeaderDelivery  = "X-Xila-Delivery"  // the delivery id (a UUID)
)

// SignatureTolerance is how far a signed timestamp may be from the receiver's
// clock before VerifySignature rejects it as a replay.
const SignatureTolerance = 5 * time.Minute

// Signing secret bounds (bytes).
const (
	minSecretLen = 16
	maxSecretLen = 256
)

// Signature verification errors.
var (
	ErrSignatureMissing   = errors.New("webhook signature or timestamp missing")
	ErrSignatureInvalid   = errors.New("webhook signature does not match")
	ErrSignatureExpired   = errors.New("webhook timestamp outside the replay window")
	ErrSignatureMalformed = errors.New("webhook timestamp malformed")
)

// Sign returns the X-Xila-Signature value for body sent at timestamp
// (unix seconds): "v1=" + hex(HMAC-SHA256(secret, timestamp + "." + body)).
func Sign(secret string, timestamp int64, body []byte) string {
	return "v1=" + hex.EncodeToString(mac(secret, strconv.FormatInt(timestamp, 10), body))
}

func mac(secret, timestamp string, body []byte) []byte {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(timestamp))
	m.Write([]byte{'.'})
	m.Write(body)
	return m.Sum(nil)
}

// VerifySignature checks a delivery the way a receiver should: the raw body,
// the X-Xila-Timestamp and X-Xila-Signature headers, the shared secret, and a
// timestamp within SignatureTolerance of now (rejecting replays of an old
// delivery). The signature header may carry several comma-separated v1=
// values; any match passes. It is the reference implementation of the
// README's snippets.
func VerifySignature(secret string, h http.Header, body []byte, now time.Time) error {
	ts, sig := h.Get(HeaderTimestamp), h.Get(HeaderSignature)
	if ts == "" || sig == "" {
		return ErrSignatureMissing
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return ErrSignatureMalformed
	}
	if d := now.Sub(time.Unix(sec, 0)); d > SignatureTolerance || d < -SignatureTolerance {
		return ErrSignatureExpired
	}
	want := mac(secret, ts, body)
	for part := range strings.SplitSeq(sig, ",") {
		hexSig, ok := strings.CutPrefix(strings.TrimSpace(part), "v1=")
		if !ok {
			continue
		}
		if got, err := hex.DecodeString(hexSig); err == nil && hmac.Equal(got, want) {
			return nil
		}
	}
	return ErrSignatureInvalid
}

// validSecret checks a signing secret's length.
func validSecret(s string) error {
	if len(s) < minSecretLen || len(s) > maxSecretLen {
		return errors.New("signing_secret must be 16–256 characters")
	}
	return nil
}
