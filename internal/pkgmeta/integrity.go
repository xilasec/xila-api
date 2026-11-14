package pkgmeta

import (
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
)

// Integrity is how a component's SBOM hashes compare with the digests its
// registry publishes for that exact version (Dependency-Track's "component
// integrity"): the artifact you shipped is — or isn't — the one the registry
// served.
type Integrity string

// Integrity verdicts. Unknown — no hash on one side, or no algorithm both
// sides have — is never treated as verified or as a mismatch.
const (
	IntegrityUnknown  Integrity = ""
	IntegrityVerified Integrity = "verified"
	IntegrityMismatch Integrity = "mismatch"
)

// Valid reports whether i is a known verdict.
func (i Integrity) Valid() bool {
	return i == IntegrityUnknown || i == IntegrityVerified || i == IntegrityMismatch
}

// hashAlg normalizes an algorithm name ("SHA-256", "sha256", "SHA_256") to
// sha1 / sha256 / sha384 / sha512; "" for anything else (MD5 proves nothing
// against a motivated attacker; BLAKE/SHA-3 aren't published by registries).
func hashAlg(name string) string {
	n := strings.ToLower(strings.NewReplacer("-", "", "_", "", " ", "").Replace(name))
	switch n {
	case "sha1", "sha256", "sha384", "sha512":
		return n
	}
	return ""
}

var digestLen = map[string]int{"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}

// normalizeDigest returns a digest as lowercase hex, accepting hex (any case)
// or standard / URL-safe base64 (npm's SRI, NuGet). "" when it isn't a
// well-formed digest of that algorithm.
func normalizeDigest(alg, value string) string {
	want := digestLen[alg]
	v := strings.TrimSpace(value)
	if b, err := hex.DecodeString(v); err == nil && len(b) == want {
		return hex.EncodeToString(b)
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(v); err == nil && len(b) == want {
			return hex.EncodeToString(b)
		}
	}
	return ""
}

// addDigest records one published digest (algorithm name + value) in hashes.
func addDigest(hashes map[string][]string, algName, value string) {
	alg := hashAlg(algName)
	if alg == "" {
		return
	}
	if d := normalizeDigest(alg, value); d != "" && !slices.Contains(hashes[alg], d) {
		hashes[alg] = append(hashes[alg], d)
	}
}

// addSRI records a Subresource Integrity string ("sha512-<base64> sha1-…").
func addSRI(hashes map[string][]string, sri string) {
	for _, part := range strings.Fields(sri) {
		if alg, val, ok := strings.Cut(part, "-"); ok {
			addDigest(hashes, alg, val)
		}
	}
}

// VerifyIntegrity compares a component's hashes (algorithm name → digest, as
// the SBOM states them) with a version's published digests. A version may
// publish several artifacts (PyPI wheels per platform + the sdist), so a
// digest matches when it is any of them. Any algorithm both sides know that
// disagrees is a mismatch — even if another agrees: one wrong digest means
// the artifact isn't the one published.
func VerifyIntegrity(component map[string]string, published map[string][]string) Integrity {
	verdict := IntegrityUnknown
	for name, value := range component {
		alg := hashAlg(name)
		if alg == "" || len(published[alg]) == 0 {
			continue
		}
		d := normalizeDigest(alg, value)
		if d == "" {
			continue // an unparseable digest is no evidence either way
		}
		if !slices.Contains(published[alg], d) {
			return IntegrityMismatch
		}
		verdict = IntegrityVerified
	}
	return verdict
}

// nonEmpty is nil for an empty map, so versions without digests don't carry
// an empty "hashes" object into the cached JSON.
func nonEmpty(h map[string][]string) map[string][]string {
	if len(h) == 0 {
		return nil
	}
	return h
}
