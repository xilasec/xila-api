package saml

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/sso"
)

const (
	publicURL = "https://xila.test"
	idpEntity = "https://idp.test/metadata"
)

// testIdP is an in-process identity provider: a key pair, its metadata, and a
// response builder that signs with goxmldsig exactly like a real IdP would.
type testIdP struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

// Keys are generated once per test binary (RSA generation is slow).
var (
	theIdP   = newTestIdP("idp")
	rogueIdP = newTestIdP("rogue")
	spKeyPEM = func() struct{ cert, key string } {
		certPEM, keyPEM, err := generate("xila.test")
		if err != nil {
			panic(err)
		}
		return struct{ cert, key string }{certPEM, keyPEM}
	}()
)

func newTestIdP(cn string) testIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return testIdP{key: key, cert: cert}
}

func (i testIdP) metadata() string {
	sso, _ := url.Parse("https://idp.test/sso")
	meta, _ := url.Parse(idpEntity)
	idp := crewjam.IdentityProvider{Certificate: i.cert, Key: i.key, SSOURL: *sso, MetadataURL: *meta}
	out, _ := xml.Marshal(idp.Metadata())
	return string(out)
}

// metadataWithSLO is like metadata, plus a SingleLogoutService (HTTP-Redirect)
// — what an IdP that supports Single Logout publishes, needed to build an
// outgoing (SP-initiated) LogoutRequest.
func (i testIdP) metadataWithSLO() string {
	ssoURL, _ := url.Parse("https://idp.test/sso")
	sloURL, _ := url.Parse("https://idp.test/slo")
	meta, _ := url.Parse(idpEntity)
	idp := crewjam.IdentityProvider{Certificate: i.cert, Key: i.key, SSOURL: *ssoURL, LogoutURL: *sloURL, MetadataURL: *meta}
	out, _ := xml.Marshal(idp.Metadata())
	return string(out)
}

// signature returns an enveloped Signature over el (the caller sets it on the
// struct and re-renders the element, as crewjam's IdP does).
func (i testIdP) signature(t *testing.T, el *etree.Element) *etree.Element {
	t.Helper()
	ctx := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore(tls.Certificate{
		Certificate: [][]byte{i.cert.Raw}, PrivateKey: i.key, Leaf: i.cert,
	}))
	// Exclusive C14N, as Keycloak, Entra ID and Okta sign: the signature must
	// survive the assertion being embedded in the Response.
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := ctx.SignEnveloped(el)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed.ChildElements()[len(signed.ChildElements())-1]
}

// signedAssertion renders the assertion signed by this IdP.
func (i testIdP) signedAssertion(t *testing.T, c claims) *etree.Element {
	t.Helper()
	a := c.assertion()
	a.Signature = i.signature(t, a.Element())
	return a.Element()
}

// claims describes one assertion; zero values are the happy path for the
// environment provider.
type claims struct {
	inResponseTo string
	nameID       string
	nameIDFormat string
	audience     string
	acs          string // recipient / destination; default the environment ACS
	issued       time.Time
	notOnOrAfter time.Time
	email        string
	groups       []string
	sessionIndex string // Single Logout addresses a session by NameID + this
}

func (c claims) dest() string {
	if c.acs == "" {
		return publicURL + ACSPath
	}
	return c.acs
}

func (c claims) assertion() *crewjam.Assertion {
	now := time.Now()
	if c.issued.IsZero() {
		c.issued = now
	}
	if c.notOnOrAfter.IsZero() {
		c.notOnOrAfter = now.Add(5 * time.Minute)
	}
	if c.audience == "" {
		c.audience = publicURL + MetadataPath
	}
	if c.nameID == "" {
		c.nameID = "jdoe"
	}
	if c.nameIDFormat == "" {
		c.nameIDFormat = string(crewjam.PersistentNameIDFormat)
	}
	attrs := []crewjam.Attribute{{Name: "email", Values: []crewjam.AttributeValue{{Type: "xs:string", Value: c.email}}}}
	if len(c.groups) > 0 {
		var vals []crewjam.AttributeValue
		for _, g := range c.groups {
			vals = append(vals, crewjam.AttributeValue{Type: "xs:string", Value: g})
		}
		attrs = append(attrs, crewjam.Attribute{Name: "groups", Values: vals})
	}
	return &crewjam.Assertion{
		ID: "id-" + randHex(16), IssueInstant: c.issued, Version: "2.0",
		Issuer: crewjam.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: idpEntity},
		Subject: &crewjam.Subject{
			NameID: &crewjam.NameID{Format: c.nameIDFormat, Value: c.nameID},
			SubjectConfirmations: []crewjam.SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				SubjectConfirmationData: &crewjam.SubjectConfirmationData{
					InResponseTo: c.inResponseTo, NotOnOrAfter: c.notOnOrAfter, Recipient: c.dest(),
				},
			}},
		},
		Conditions: &crewjam.Conditions{
			NotBefore: c.issued.Add(-time.Minute), NotOnOrAfter: c.notOnOrAfter,
			AudienceRestrictions: []crewjam.AudienceRestriction{{Audience: crewjam.Audience{Value: c.audience}}},
		},
		AuthnStatements: []crewjam.AuthnStatement{{AuthnInstant: c.issued, SessionIndex: c.sessionIndex, AuthnContext: crewjam.AuthnContext{
			AuthnContextClassRef: &crewjam.AuthnContextClassRef{Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"},
		}}},
		AttributeStatements: []crewjam.AttributeStatement{{Attributes: attrs}},
	}
}

func response(inResponseTo, dest string) *crewjam.Response {
	return &crewjam.Response{
		ID: "id-" + randHex(16), InResponseTo: inResponseTo, Version: "2.0", IssueInstant: time.Now(),
		Destination: dest,
		Issuer:      &crewjam.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: idpEntity},
		Status:      crewjam.Status{StatusCode: crewjam.StatusCode{Value: crewjam.StatusSuccess}},
	}
}

func responseEl(inResponseTo string, assertions ...*etree.Element) *etree.Element {
	return responseElTo(inResponseTo, publicURL+ACSPath, assertions...)
}

func responseElTo(inResponseTo, dest string, assertions ...*etree.Element) *etree.Element {
	el := response(inResponseTo, dest).Element()
	for _, a := range assertions {
		el.AddChild(a)
	}
	return el
}

// signedResponseEl renders a response signed by this IdP around an (unsigned)
// assertion — the other common IdP setting.
func (i testIdP) signedResponseEl(t *testing.T, c claims) *etree.Element {
	t.Helper()
	r := response(c.inResponseTo, c.dest())
	assertion := c.assertion().Element()
	el := r.Element()
	el.AddChild(assertion)
	r.Signature = i.signature(t, el)
	el = r.Element()
	el.AddChild(assertion)
	return el
}

func encode(t *testing.T, el *etree.Element) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// signedResponse is the common case: assertion signed by the IdP, response not.
func (i testIdP) signedResponse(t *testing.T, c claims) string {
	t.Helper()
	return encode(t, responseElTo(c.inResponseTo, c.dest(), i.signedAssertion(t, c)))
}

// --- harness ---

type memReplay struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (m *memReplay) Consume(_ context.Context, id string, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[id] {
		return ErrReplay
	}
	m.seen[id] = true
	return nil
}

type fakeLogins struct {
	got       []sso.Assertion
	providers []string
}

func (f *fakeLogins) Complete(_ context.Context, p sso.Provider, a sso.Assertion) string {
	f.got = append(f.got, a)
	f.providers = append(f.providers, p.Slug)
	return "/#sso_token=MINTED"
}

// resolver serves fixed providers by slug, like sso.Registry would.
type resolver map[string]sso.Resolved

func (r resolver) Resolve(_ context.Context, kind, slug string) (sso.Resolved, error) {
	res, ok := r[slug]
	if !ok || res.Provider.Kind != kind || !res.Provider.Enabled {
		return sso.Resolved{}, sso.ErrProviderNotFound
	}
	return res, nil
}

// fakeSessions is an in-memory SessionEnder, recording every IdP-initiated
// logout it was asked to carry out.
type fakeSessions struct {
	mu    sync.Mutex
	ended []struct{ nameID, sessionIndex string }
}

func (f *fakeSessions) EndByIdentity(_ context.Context, _ sso.Provider, nameID, sessionIndex string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ended = append(f.ended, struct{ nameID, sessionIndex string }{nameID, sessionIndex})
	return 1, nil
}

type harness struct {
	app      *fiber.App
	svc      *Service
	logins   *fakeLogins
	sessions *fakeSessions
}

// envSAML is the provider SAML_* configures, at the original routes.
func envSAML() sso.Provider {
	return sso.Provider{
		ID: sso.ProviderSAML, Slug: sso.ProviderSAML, Kind: sso.ProviderSAML, Source: sso.SourceEnvironment, Enabled: true,
		Name: "Test SAML", IDPMetadata: theIdP.metadata(), GroupsAttributes: []string{"groups"}, SignRequests: true,
		LinkByEmail: true,
		Endpoints: sso.Endpoints{
			LoginURL: LoginPath, ACSURL: publicURL + ACSPath, SLOURL: publicURL + SLOPath, MetadataURL: publicURL + MetadataPath,
			SPEntityID: publicURL + MetadataPath,
		},
	}
}

// dbSAML is an admin-managed provider served under its slug.
func dbSAML(id, slug string) sso.Provider {
	p := envSAML()
	base := publicURL + "/api/v1/auth/saml/" + slug
	p.ID, p.Slug, p.Source = id, slug, sso.SourceDatabase
	p.Endpoints = sso.Endpoints{
		LoginURL: "/api/v1/auth/saml/" + slug + "/login", ACSURL: base + "/acs", SLOURL: base + "/slo", MetadataURL: base + "/metadata",
		SPEntityID: base + "/metadata",
	}
	return p
}

func build(t *testing.T, p sso.Provider) *Service {
	t.Helper()
	client, err := Protocol{}.Build(context.Background(), withKeys(p))
	if err != nil {
		t.Fatalf("build %s: %v", p.Slug, err)
	}
	return client.(*Service)
}

// withKeys gives the provider the test SP key pair (as its own sp_cert/sp_key).
func withKeys(p sso.Provider) sso.Provider {
	p.SPCert, p.SPKey = spKeyPEM.cert, spKeyPEM.key
	return p
}

func newHarness(t *testing.T, mutate ...func(*sso.Provider)) harness {
	t.Helper()
	p := envSAML()
	for _, m := range mutate {
		m(&p)
	}
	svc := build(t, p)
	logins := &fakeLogins{}
	sessions := &fakeSessions{}
	app := fiber.New()
	NewHandler(resolver{p.Slug: {Provider: p, Client: svc}}, &memReplay{seen: map[string]bool{}}, logins, sessions, true).Register(app.Group("/api/v1/auth"))
	return harness{app: app, svc: svc, logins: logins, sessions: sessions}
}

// login runs GET /saml/login and returns the AuthnRequest id, the RelayState and
// the tracking cookie the browser now holds.
func (h harness) login(t *testing.T) (requestID, relayState string, cookie *http.Cookie) {
	t.Helper()
	resp, err := h.app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/login", nil), -1)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("login: %v / %d", err, resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if !strings.HasPrefix(loc.String(), "https://idp.test/sso?") {
		t.Fatalf("redirect = %s, want the IdP SSO URL", loc)
	}
	q := loc.Query()
	if q.Get("Signature") == "" || q.Get("SigAlg") != dsig.RSASHA256SignatureMethod {
		t.Errorf("AuthnRequest not signed: %s", loc.RawQuery)
	}
	deflated, _ := base64.StdEncoding.DecodeString(q.Get("SAMLRequest"))
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	if err != nil {
		t.Fatalf("inflate SAMLRequest: %v", err)
	}
	var req crewjam.AuthnRequest
	if err := xml.Unmarshal(inflated, &req); err != nil {
		t.Fatalf("AuthnRequest: %v", err)
	}
	if req.AssertionConsumerServiceURL != publicURL+ACSPath {
		t.Errorf("ACS in request = %q", req.AssertionConsumerServiceURL)
	}
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, cookiePrefix) {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteNoneMode || !cookie.Secure {
		t.Fatalf("tracking cookie = %+v, want HttpOnly, Secure, SameSite=None", cookie)
	}
	return req.ID, q.Get("RelayState"), cookie
}

// post submits a SAMLResponse to the ACS like the browser's auto-POST form.
func (h harness) post(t *testing.T, samlResponse, relayState string, cookie *http.Cookie) string {
	t.Helper()
	form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relayState}}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/acs", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		r.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
	resp, err := h.app.Test(r, -1)
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("acs: %v / %d", err, resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

const ok, refused = "/#sso_token=MINTED", "/login?error=sso_failed"

// --- tests ---

func TestSPInitiatedLogin(t *testing.T) {
	h := newHarness(t)
	id, relay, cookie := h.login(t)
	resp := theIdP.signedResponse(t, claims{inResponseTo: id, email: "J.Doe@Example.com", groups: []string{"xila-admins", "devs"}})
	if loc := h.post(t, resp, relay, cookie); loc != ok {
		t.Fatalf("login → %q, want the minted session", loc)
	}
	if len(h.logins.got) != 1 {
		t.Fatalf("logins = %d", len(h.logins.got))
	}
	a := h.logins.got[0]
	if h.logins.providers[0] != sso.ProviderSAML || a.Issuer != idpEntity || a.Subject != "jdoe" ||
		a.SubjectFormat != string(crewjam.PersistentNameIDFormat) || a.Email != "J.Doe@Example.com" ||
		a.EmailTrust != sso.EmailVerified || !slices.Equal(a.Groups, []string{"xila-admins", "devs"}) {
		t.Errorf("assertion = %+v", a)
	}

	// The same response again — even with the request cookie replayed too — is refused.
	if loc := h.post(t, resp, relay, cookie); loc != refused {
		t.Errorf("replayed assertion → %q, want refused", loc)
	}
	if len(h.logins.got) != 1 {
		t.Error("a replay must not log in")
	}
}

// Signing the whole response (assertion unsigned) is the other common IdP setting.
func TestSignedResponse(t *testing.T) {
	h := newHarness(t)
	id, relay, cookie := h.login(t)
	if loc := h.post(t, encode(t, theIdP.signedResponseEl(t, claims{inResponseTo: id, email: "r@x.io"})), relay, cookie); loc != ok {
		t.Fatalf("response-signed login → %q", loc)
	}
}

// A response signed and encrypted the way crewjam's own IdP does it — the
// encryption key comes from our SP metadata.
func TestEncryptedAssertion(t *testing.T) {
	h := newHarness(t)
	id, relay, cookie := h.login(t)

	md, err := h.svc.Metadata()
	if err != nil {
		t.Fatal(err)
	}
	var spMeta crewjam.EntityDescriptor
	if err := xml.Unmarshal(md, &spMeta); err != nil {
		t.Fatal(err)
	}
	metaURL, _ := url.Parse(idpEntity)
	req := &crewjam.IdpAuthnRequest{
		IDP:             &crewjam.IdentityProvider{Certificate: theIdP.cert, Key: theIdP.key, MetadataURL: *metaURL},
		Request:         crewjam.AuthnRequest{ID: id},
		SPSSODescriptor: &spMeta.SPSSODescriptors[0],
		ACSEndpoint:     &crewjam.IndexedEndpoint{Binding: crewjam.HTTPPostBinding, Location: publicURL + ACSPath},
		Assertion:       claims{inResponseTo: id, email: "enc@example.com"}.assertion(),
		Now:             time.Now(),
	}
	if err := req.MakeResponse(); err != nil {
		t.Fatalf("make response: %v", err)
	}
	if req.ResponseEl.FindElement("./EncryptedAssertion") == nil {
		t.Fatal("the test IdP did not encrypt the assertion")
	}
	if loc := h.post(t, encode(t, req.ResponseEl), relay, cookie); loc != ok {
		t.Fatalf("encrypted login → %q", loc)
	}
	if h.logins.got[0].Email != "enc@example.com" {
		t.Errorf("email = %q", h.logins.got[0].Email)
	}
}

func TestRejectedResponses(t *testing.T) {
	past := time.Now().Add(-2 * time.Hour)
	cases := []struct {
		name  string
		build func(t *testing.T, id string) string
	}{
		{"unsigned assertion", func(t *testing.T, id string) string {
			return encode(t, responseEl(id, claims{inResponseTo: id, email: "a@x.io"}.assertion().Element()))
		}},
		{"signed by another key", func(t *testing.T, id string) string {
			return rogueIdP.signedResponse(t, claims{inResponseTo: id, email: "a@x.io"})
		}},
		{"wrong audience", func(t *testing.T, id string) string {
			return theIdP.signedResponse(t, claims{inResponseTo: id, email: "a@x.io", audience: "https://other-sp.test"})
		}},
		{"expired", func(t *testing.T, id string) string {
			return theIdP.signedResponse(t, claims{inResponseTo: id, email: "a@x.io", issued: past, notOnOrAfter: past.Add(5 * time.Minute)})
		}},
		{"InResponseTo another request", func(t *testing.T, _ string) string {
			return theIdP.signedResponse(t, claims{inResponseTo: "id-someone-elses-request", email: "a@x.io"})
		}},
		{"transient NameID", func(t *testing.T, id string) string {
			return theIdP.signedResponse(t, claims{inResponseTo: id, email: "a@x.io", nameIDFormat: string(crewjam.TransientNameIDFormat)})
		}},
		{"tampered signed assertion", func(t *testing.T, id string) string {
			signed := theIdP.signedAssertion(t, claims{inResponseTo: id, email: "victim@x.io"})
			signed.FindElement("./Subject/NameID").SetText("admin")
			return encode(t, responseEl(id, signed))
		}},
		{"tampered signed response", func(t *testing.T, id string) string {
			signed := theIdP.signedResponseEl(t, claims{inResponseTo: id, email: "victim@x.io"})
			signed.FindElement("./Assertion/Subject/NameID").SetText("admin")
			return encode(t, signed)
		}},
		{"signature wrapping: forged unsigned assertion next to a signed one", func(t *testing.T, id string) string {
			forged := claims{inResponseTo: id, nameID: "admin", email: "admin@x.io"}.assertion().Element()
			legit := theIdP.signedAssertion(t, claims{inResponseTo: id, email: "victim@x.io"})
			return encode(t, responseEl(id, forged, legit))
		}},
		{"signature wrapping: legit signed assertion first, forged second", func(t *testing.T, id string) string {
			forged := claims{inResponseTo: id, nameID: "admin", email: "admin@x.io"}.assertion().Element()
			legit := theIdP.signedAssertion(t, claims{inResponseTo: id, email: "victim@x.io"})
			return encode(t, responseEl(id, legit, forged))
		}},
		{"not base64", func(*testing.T, string) string { return "%%%not-base64" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			id, relay, cookie := h.login(t)
			if loc := h.post(t, tc.build(t, id), relay, cookie); loc != refused {
				t.Errorf("→ %q, want refused", loc)
			}
			if len(h.logins.got) != 0 {
				t.Errorf("a rejected response reached the SSO layer: %+v", h.logins.got)
			}
		})
	}
}

// The tracking cookie binds the response to the browser that started the login.
func TestRequestTracking(t *testing.T) {
	h := newHarness(t)
	id, relay, cookie := h.login(t)
	resp := theIdP.signedResponse(t, claims{inResponseTo: id, email: "a@x.io"})

	forged := &http.Cookie{Name: cookie.Name, Value: id + ".9999999999.forged-mac"}
	if loc := h.post(t, resp, relay, forged); loc != refused {
		t.Errorf("forged tracking cookie → %q, want refused", loc)
	}
	// No cookie at all = unsolicited, refused while IdP-initiated login is off.
	if loc := h.post(t, resp, relay, nil); loc != refused {
		t.Errorf("response without the browser's request cookie → %q, want refused", loc)
	}
	if loc := h.post(t, resp, relay, cookie); loc != ok {
		t.Errorf("genuine round trip → %q", loc)
	}
}

func TestIDPInitiated(t *testing.T) {
	unsolicited := func(t *testing.T) string {
		return theIdP.signedResponse(t, claims{email: "a@x.io"})
	}
	off := newHarness(t)
	if loc := off.post(t, unsolicited(t), "", nil); loc != refused {
		t.Errorf("IdP-initiated while disabled → %q, want refused", loc)
	}

	on := newHarness(t, func(p *sso.Provider) { p.AllowIDPInitiated = true })
	if loc := on.post(t, unsolicited(t), "https://evil.example/landing", nil); loc != ok {
		t.Errorf("IdP-initiated while enabled → %q, want a session (RelayState ignored)", loc)
	}
	// Enabling it does not weaken SP-initiated logins: a tracked request still
	// has to be answered by its own response.
	_, relay, cookie := on.login(t)
	if loc := on.post(t, theIdP.signedResponse(t, claims{inResponseTo: "id-other", email: "a@x.io"}), relay, cookie); loc != refused {
		t.Errorf("mismatched InResponseTo with IdP-initiated on → %q, want refused", loc)
	}
}

func TestMetadataAndEmailFallbacks(t *testing.T) {
	h := newHarness(t)
	resp, err := h.app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/metadata", nil), -1)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("metadata: %v / %d", err, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var md crewjam.EntityDescriptor
	if err := xml.Unmarshal(body, &md); err != nil {
		t.Fatalf("metadata xml: %v", err)
	}
	sp := md.SPSSODescriptors[0]
	if md.EntityID != publicURL+MetadataPath || len(sp.AssertionConsumerServices) != 1 ||
		sp.AssertionConsumerServices[0].Location != publicURL+ACSPath ||
		sp.AssertionConsumerServices[0].Binding != crewjam.HTTPPostBinding || *sp.AuthnRequestsSigned != true {
		t.Errorf("metadata = %s", body)
	}

	// Email: the Entra/ADFS claim name, then an emailAddress NameID.
	a := claims{email: "x"}.assertion()
	a.AttributeStatements = []crewjam.AttributeStatement{{Attributes: []crewjam.Attribute{{
		Name:   "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		Values: []crewjam.AttributeValue{{Value: "entra@x.io"}},
	}}}}
	if got := h.svc.email(a); got != "entra@x.io" {
		t.Errorf("email from the WS-Fed claim = %q", got)
	}
	a.AttributeStatements = nil
	a.Subject.NameID = &crewjam.NameID{Format: string(crewjam.EmailAddressNameIDFormat), Value: "nameid@x.io"}
	if got := h.svc.email(a); got != "nameid@x.io" {
		t.Errorf("email from an emailAddress NameID = %q", got)
	}
}

// Database providers each get their own SP (entity id, ACS, metadata) under
// their slug; one provider's request-tracking cookie never completes another's
// login — not even under the other's cookie name, with both on the shared key.
func TestSluggedProvidersAreIsolated(t *testing.T) {
	env := envSAML()
	corp := dbSAML("7d3c1d4e-0000-4000-8000-0000000000c1", "corp")
	lab := dbSAML("7d3c1d4e-0000-4000-8000-0000000000c2", "lab")
	off := dbSAML("7d3c1d4e-0000-4000-8000-0000000000c3", "off")
	off.Enabled = false
	logins := &fakeLogins{}
	app := fiber.New()
	providers := resolver{}
	for _, p := range []sso.Provider{env, corp, lab, off} {
		providers[p.Slug] = sso.Resolved{Provider: p, Client: build(t, p)}
	}
	NewHandler(providers, &memReplay{seen: map[string]bool{}}, logins, &fakeSessions{}, true).Register(app.Group("/api/v1/auth"))
	h := harness{app: app, logins: logins}

	// corp's own metadata.
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/corp/metadata", nil), -1)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("corp metadata: %v / %d", err, resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	var md crewjam.EntityDescriptor
	if err := xml.Unmarshal(body, &md); err != nil {
		t.Fatal(err)
	}
	if md.EntityID != corp.Endpoints.SPEntityID || md.SPSSODescriptors[0].AssertionConsumerServices[0].Location != corp.Endpoints.ACSURL {
		t.Errorf("corp metadata = %s", body)
	}

	// SP-initiated login at corp, answered for corp.
	resp, _ = app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/auth/saml/corp/login", nil), -1)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	inflated, err := io.ReadAll(flate.NewReader(base64.NewDecoder(base64.StdEncoding, strings.NewReader(loc.Query().Get("SAMLRequest")))))
	if err != nil {
		t.Fatal(err)
	}
	var authn crewjam.AuthnRequest
	if err := xml.Unmarshal(inflated, &authn); err != nil {
		t.Fatal(err)
	}
	if authn.AssertionConsumerServiceURL != corp.Endpoints.ACSURL || authn.Issuer.Value != corp.Endpoints.SPEntityID {
		t.Errorf("corp AuthnRequest ACS/issuer = %q / %q", authn.AssertionConsumerServiceURL, authn.Issuer.Value)
	}
	relay := loc.Query().Get("RelayState")
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		cookie = c
	}
	if cookie == nil || cookie.Name != "saml_corp_req_"+relay || cookie.Path != "/api/v1/auth/saml/corp" {
		t.Fatalf("corp tracking cookie = %+v", cookie)
	}
	forCorp := claims{inResponseTo: authn.ID, email: "a@x.io", audience: corp.Endpoints.SPEntityID, acs: corp.Endpoints.ACSURL}
	post := func(slug, samlResponse string, c *http.Cookie) string {
		form := url.Values{"SAMLResponse": {samlResponse}, "RelayState": {relay}}
		r := httptest.NewRequest(http.MethodPost, "/api/v1/auth/saml/"+slug+"/acs", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if c != nil {
			r.AddCookie(c)
		}
		resp, err := app.Test(r, -1)
		if err != nil {
			t.Fatal(err)
		}
		return resp.Header.Get("Location")
	}
	// corp's cookie value under lab's cookie name, with a response made for lab:
	// the MAC is bound to the provider.
	moved := &http.Cookie{Name: "saml_lab_req_" + relay, Value: cookie.Value}
	forLab := claims{inResponseTo: authn.ID, email: "a@x.io", audience: lab.Endpoints.SPEntityID, acs: lab.Endpoints.ACSURL}
	if got := post("lab", theIdP.signedResponse(t, forLab), moved); got != refused {
		t.Errorf("corp's tracking cookie at lab → %q, want refused", got)
	}
	// corp's response at the environment provider's ACS: wrong audience.
	if got := h.post(t, theIdP.signedResponse(t, forCorp), relay, cookie); got != refused {
		t.Errorf("corp's response at the environment ACS → %q, want refused", got)
	}
	if got := post("corp", theIdP.signedResponse(t, forCorp), cookie); got != ok {
		t.Fatalf("corp round trip → %q", got)
	}
	if !slices.Equal(logins.providers, []string{"corp"}) {
		t.Errorf("logins via %v, want exactly one via corp", logins.providers)
	}

	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/api/v1/auth/saml/off/login"},
		{http.MethodGet, "/api/v1/auth/saml/off/metadata"},
		{http.MethodPost, "/api/v1/auth/saml/off/acs"},
		{http.MethodGet, "/api/v1/auth/saml/nope/metadata"},
		{http.MethodGet, "/api/v1/auth/saml/saml/metadata"},
	} {
		if resp, _ := app.Test(httptest.NewRequest(r.method, r.path, nil), -1); resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", r.method, r.path, resp.StatusCode)
		}
	}
}
