package netguard

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func withPolicy(t *testing.T, p Policy) {
	t.Helper()
	prev := Default()
	SetDefault(p)
	t.Cleanup(func() { SetDefault(prev) })
}

// Metadata and link-local destinations are refused under every policy — there
// is no configuration in which an integration legitimately talks to them.
func TestMetadataAlwaysRefused(t *testing.T) {
	open := Policy{AllowPrivate: true, AllowLoopback: true, AllowedHosts: []string{"metadata.google.internal"}}
	for _, ip := range []string{"169.254.169.254", "::ffff:169.254.169.254", "fd00:ec2::254", "fe80::1", "0.0.0.0", "224.0.0.1"} {
		if err := open.CheckAddr("metadata.google.internal", netip.MustParseAddr(ip)); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s admitted under the most open policy", ip)
		}
	}
}

func TestPolicyRules(t *testing.T) {
	strict := Policy{}
	onPrem := Policy{AllowPrivate: true}
	cases := []struct {
		p    Policy
		host string
		ip   string
		ok   bool
	}{
		{onPrem, "jira.corp", "10.1.2.3", true},     // self-hosted tracker: allowed by default policy
		{onPrem, "gitlab.corp", "100.64.0.9", true}, // CGNAT counts as private
		{strict, "jira.corp", "10.1.2.3", false},    // OUTBOUND_ALLOW_PRIVATE=false
		{onPrem, "localhost", "127.0.0.1", false},   // loopback off by default
		{Policy{AllowedHosts: []string{"JIRA.corp."}}, "jira.corp", "10.1.2.3", true},
		{onPrem, "example.com", "93.184.216.34", true},
	}
	for _, c := range cases {
		SetDefault(c.p) // normalizes AllowedHosts
		err := Default().CheckAddr(c.host, netip.MustParseAddr(c.ip))
		if (err == nil) != c.ok {
			t.Errorf("%+v %s %s: err = %v, want ok=%v", c.p, c.host, c.ip, err, c.ok)
		}
	}
	SetDefault(Permissive)
}

// The check runs at dial time, after DNS: a hostname resolving to loopback is
// refused just like the literal address.
func TestDialRefusesResolvedLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("internal secret")) }))
	defer srv.Close()
	withPolicy(t, Policy{AllowPrivate: true})

	port := srv.URL[strings.LastIndex(srv.URL, ":"):]
	for _, u := range []string{srv.URL, "http://localhost" + port} {
		_, err := NewClient(5 * time.Second).Get(u)
		if err == nil || !errors.Is(err, ErrBlocked) {
			t.Errorf("GET %s: err = %v, want blocked", u, err)
		}
	}
	if err := CheckURL("http://localhost" + port); !errors.Is(err, ErrBlocked) {
		t.Errorf("CheckURL(localhost) = %v, want blocked", err)
	}
}

// A public-looking endpoint that redirects to the metadata service doesn't get
// the client there: every hop dials through the same check.
func TestRedirectToMetadataRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()
	withPolicy(t, Permissive) // the test server is on loopback; allow it

	_, err := NewClient(5 * time.Second).Get(srv.URL)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("redirect to metadata: err = %v, want blocked", err)
	}
}

func TestCheckURLRejectsOtherSchemes(t *testing.T) {
	for _, u := range []string{"file:///etc/passwd", "gopher://x", "ftp://example.com", "/relative"} {
		if err := CheckURL(u); !errors.Is(err, ErrBlocked) {
			t.Errorf("CheckURL(%q) = %v, want blocked", u, err)
		}
	}
}
