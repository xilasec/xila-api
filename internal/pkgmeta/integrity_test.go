package pkgmeta

import (
	"context"
	"testing"
)

func TestVerifyIntegrity(t *testing.T) {
	// left-pad 1.3.0 as npm publishes it.
	published := map[string][]string{}
	addSRI(published, "sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA==")
	addDigest(published, "sha1", "5b8a3a7765dfe001261dde915589e782f8c94d1e")
	sha512hex := published["sha512"][0]

	cases := []struct {
		name      string
		component map[string]string
		want      Integrity
	}{
		{"CycloneDX SHA-512 hex", map[string]string{"SHA-512": sha512hex}, IntegrityVerified},
		{"upper-case hex, other alg spelling", map[string]string{"sha_1": "5B8A3A7765DFE001261DDE915589E782F8C94D1E"}, IntegrityVerified},
		{"base64 digest", map[string]string{"SHA-512": "XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQGinBN9yTQT3bFlCBy/aVx2HrNcqQGsdot8ghrjyrvMCoEA=="}, IntegrityVerified},
		{"tampered tarball", map[string]string{"SHA-1": "0000000000000000000000000000000000000000"}, IntegrityMismatch},
		{"one alg agrees, another doesn't", map[string]string{"SHA-512": sha512hex, "SHA-1": "1111111111111111111111111111111111111111"}, IntegrityMismatch},
		{"only an algorithm the registry doesn't publish", map[string]string{"SHA-256": "a" + sha512hex[:63]}, IntegrityUnknown},
		{"MD5 proves nothing", map[string]string{"MD5": "d41d8cd98f00b204e9800998ecf8427e"}, IntegrityUnknown},
		{"malformed digest", map[string]string{"SHA-1": "not-a-digest"}, IntegrityUnknown},
		{"no hashes", nil, IntegrityUnknown},
	}
	for _, c := range cases {
		if got := VerifyIntegrity(c.component, published); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
	if VerifyIntegrity(map[string]string{"SHA-512": sha512hex}, nil) != IntegrityUnknown {
		t.Error("a version without published digests verified something")
	}
}

// The registries' published digests, from real responses (testdata).
func TestRegistriesPublishDigests(t *testing.T) {
	f := newFake(t, map[string]string{
		"/left-pad":                      "npm_left-pad_dist.json",
		"/requests/json":                 "pypi_requests_digests.json",
		"/crates/libc":                   "cargo_libc_checksums.json",
		"/api/v1/versions/nokogiri.json": "gem_nokogiri.json",
	})
	npm := find(fetch(t, registry(t, NPM, f.srv.URL), "pkg:npm/left-pad@1.3.0"), "1.3.0").Hashes
	if npm["sha1"][0] != "5b8a3a7765dfe001261dde915589e782f8c94d1e" || len(npm["sha512"]) != 1 || npm["sha512"][0][:20] != "5c8e4c3f354d0298c0ca" {
		t.Errorf("npm left-pad 1.3.0 digests = %v", npm)
	}
	py := find(fetch(t, registry(t, PyPI, f.srv.URL), "pkg:pypi/requests@2.31.0"), "2.31.0").Hashes
	if len(py["sha256"]) != 2 || VerifyIntegrity(map[string]string{"SHA-256": "942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1"}, py) != IntegrityVerified {
		t.Errorf("pypi requests 2.31.0 digests = %v (the wheel and the sdist)", py)
	}
	crate := find(fetch(t, registry(t, Cargo, f.srv.URL), "pkg:cargo/libc@0.2.158"), "0.2.158").Hashes
	if len(crate["sha256"]) != 1 || crate["sha256"][0] != "d8adc4bb1803a324070e64a98ae98f38934d91957a99cfb3a43dcbc01bc56439" {
		t.Errorf("cargo libc 0.2.158 digests = %v", crate)
	}
	gem := find(fetch(t, registry(t, Gem, f.srv.URL), "pkg:gem/nokogiri@1.19.4"), "1.19.4").Hashes
	if len(gem["sha256"]) < 4 || VerifyIntegrity(map[string]string{"SHA-256": "17dfb7c1fa194ae02fbf7c51a7afc8d278045ab3fdacfd86f91d02d7b274470b"}, gem) != IntegrityVerified {
		t.Errorf("gem nokogiri 1.19.4 digests = %d (one per platform build)", len(gem["sha256"]))
	}
}

// A sweep verifies the hashed components of the packages it fetched.
func TestSweepRecordsIntegrity(t *testing.T) {
	st := newMemStore("pkg:cargo/libc@0.2.158", "pkg:cargo/libc@0.2.155")
	st.components = []componentHashes{
		{ID: "good", Purl: "pkg:cargo/libc@0.2.158", Hashes: map[string]string{"SHA-256": "d8adc4bb1803a324070e64a98ae98f38934d91957a99cfb3a43dcbc01bc56439"}},
		{ID: "bad", Purl: "pkg:cargo/libc@0.2.155", Hashes: map[string]string{"SHA-256": "d8adc4bb1803a324070e64a98ae98f38934d91957a99cfb3a43dcbc01bc56439"}},
		{ID: "md5", Purl: "pkg:cargo/libc@0.2.155", Hashes: map[string]string{"MD5": "d41d8cd98f00b204e9800998ecf8427e"}},
	}
	f := newFake(t, map[string]string{"/crates/libc": "cargo_libc_checksums.json"})
	svc := NewService(st, map[string]Registry{Cargo: registry(t, Cargo, f.srv.URL)}, Options{})
	if _, err := svc.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"good": "verified", "bad": "mismatch", "md5": ""}
	for id, v := range want {
		if got, ok := st.integrity[id]; !ok || got != v {
			t.Errorf("component %s integrity = %q (recorded %v), want %q", id, got, ok, v)
		}
	}
}
