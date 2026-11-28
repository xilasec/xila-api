package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/xilasec/xila-api/internal/sso"
)

// sloHarness is the environment provider with an IdP whose metadata
// advertises a SingleLogoutService.
func sloHarness(t *testing.T) harness {
	t.Helper()
	return newHarness(t, func(p *sso.Provider) { p.IDPMetadata = theIdP.metadataWithSLO() })
}

// idpLogoutRequest is what an IdP sends to end a session at this SP.
func idpLogoutRequest(issuer, nameID, sessionIndex string, issued time.Time) *crewjam.LogoutRequest {
	req := &crewjam.LogoutRequest{
		ID: "id-logout-" + randHex(8), Version: "2.0", IssueInstant: issued,
		Destination: publicURL + SLOPath,
		Issuer:      &crewjam.Issuer{Value: issuer},
		NameID:      &crewjam.NameID{Value: nameID},
	}
	if sessionIndex != "" {
		req.SessionIndex = &crewjam.SessionIndex{Value: sessionIndex}
	}
	return req
}

// signedPost renders req with an enveloped signature by idp, base64-encoded
// for the HTTP-POST binding.
func (i testIdP) signedPost(t *testing.T, req *crewjam.LogoutRequest) string {
	t.Helper()
	req.Signature = i.signature(t, req.Element())
	return encode(t, req.Element())
}

// querySigned builds the HTTP-Redirect binding query an IdP like Keycloak
// sends: deflated message, RelayState, SigAlg and a Signature over the three.
func (i testIdP) querySigned(t *testing.T, req *crewjam.LogoutRequest, relayState string) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	raw, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write(raw)
	_ = w.Close()
	q := "SAMLRequest=" + url.QueryEscape(base64.StdEncoding.EncodeToString(buf.Bytes()))
	if relayState != "" {
		q += "&RelayState=" + url.QueryEscape(relayState)
	}
	q += "&SigAlg=" + url.QueryEscape(dsig.RSASHA256SignatureMethod)
	sum := sha256.Sum256([]byte(q))
	sig, err := rsa.SignPKCS1v15(rand.Reader, i.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return q + "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
}

func (h harness) slo(t *testing.T, r *http.Request) *http.Response {
	t.Helper()
	resp, err := h.app.Test(r, -1)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func postSLO(samlRequest string) *http.Request {
	form := url.Values{"SAMLRequest": {samlRequest}, "RelayState": {"rs"}}
	r := httptest.NewRequest(http.MethodPost, SLOPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

var samlResponseField = regexp.MustCompile(`name="SAMLResponse" value="([^"]+)"`)

// The SP-initiated half: the sign-out URL is a signed LogoutRequest to the
// IdP's SLO endpoint naming the session the login recorded.
func TestLogoutRedirect(t *testing.T) {
	h := sloHarness(t)
	loc, ok, err := h.svc.LogoutRedirect("jdoe", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", "sess-42", "")
	if err != nil || !ok {
		t.Fatalf("LogoutRedirect = %q, %v, %v", loc, ok, err)
	}
	u, _ := url.Parse(loc)
	if u.Scheme+"://"+u.Host+u.Path != "https://idp.test/slo" {
		t.Errorf("redirect to %s, want the IdP's SLO URL", loc)
	}
	q := u.Query()
	if q.Get("SigAlg") != dsig.RSASHA256SignatureMethod {
		t.Fatalf("LogoutRequest not signed: %s", u.RawQuery)
	}
	// HTTP-Redirect binding: the signature covers the raw query octets and is
	// checkable with the SP certificate the IdP has from our metadata.
	signedPart, _, _ := strings.Cut(u.RawQuery, "&Signature=")
	sig, _ := base64.StdEncoding.DecodeString(q.Get("Signature"))
	block, _ := pem.Decode([]byte(spKeyPEM.cert))
	spCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := spCert.CheckSignature(x509.SHA256WithRSA, []byte(signedPart), sig); err != nil {
		t.Errorf("query signature does not verify with the SP certificate: %v", err)
	}
	deflated, _ := base64.StdEncoding.DecodeString(q.Get("SAMLRequest"))
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(inflated, []byte("Signature")) {
		t.Error("a Redirect-bound message must not carry an XML signature (Bindings 3.4.4.1)")
	}
	var req crewjam.LogoutRequest
	if err := xml.Unmarshal(inflated, &req); err != nil {
		t.Fatal(err)
	}
	if req.NameID == nil || req.NameID.Value != "jdoe" || req.NameID.Format != "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" {
		t.Errorf("NameID = %+v", req.NameID)
	}
	if req.SessionIndex == nil || req.SessionIndex.Value != "sess-42" || req.Destination != "https://idp.test/slo" {
		t.Errorf("request = %+v", req)
	}

	// An IdP without a SingleLogoutService: nothing to redirect to, so the
	// caller signs out locally only.
	if _, ok, err := newHarness(t).svc.LogoutRedirect("jdoe", "", "s", ""); ok || err != nil {
		t.Errorf("IdP without SLO: ok=%v err=%v, want a plain local sign-out", ok, err)
	}
}

// metadataWithPostSLO advertises Single Logout on the HTTP-POST binding too.
func (i testIdP) metadataWithPostSLO(t *testing.T) string {
	t.Helper()
	ssoURL, _ := url.Parse("https://idp.test/sso")
	sloURL, _ := url.Parse("https://idp.test/slo")
	meta, _ := url.Parse(idpEntity)
	idp := crewjam.IdentityProvider{Certificate: i.cert, Key: i.key, SSOURL: *ssoURL, LogoutURL: *sloURL, MetadataURL: *meta}
	ed := idp.Metadata()
	ed.IDPSSODescriptors[0].SingleLogoutServices = append(ed.IDPSSODescriptors[0].SingleLogoutServices,
		crewjam.Endpoint{Binding: crewjam.HTTPPostBinding, Location: "https://idp.test/slo-post"})
	out, err := xml.Marshal(ed)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func decodeLogoutResponse(t *testing.T, raw []byte) crewjam.LogoutResponse {
	t.Helper()
	var lr crewjam.LogoutResponse
	if err := xml.Unmarshal(raw, &lr); err != nil {
		t.Fatal(err)
	}
	return lr
}

func TestIDPInitiatedLogoutPost(t *testing.T) {
	// The IdP offers POST: answered in the binding the request came in.
	h := newHarness(t, func(p *sso.Provider) { p.IDPMetadata = theIdP.metadataWithPostSLO(t) })
	req := idpLogoutRequest(idpEntity, "jdoe", "sess-42", time.Now())
	resp := h.slo(t, postSLO(theIdP.signedPost(t, req)))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if len(h.sessions.ended) != 1 || h.sessions.ended[0].nameID != "jdoe" || h.sessions.ended[0].sessionIndex != "sess-42" {
		t.Fatalf("ended = %+v", h.sessions.ended)
	}
	body, _ := io.ReadAll(resp.Body)
	m := samlResponseField.FindSubmatch(body)
	if m == nil {
		t.Fatalf("no SAMLResponse form in %s", body)
	}
	raw, _ := base64.StdEncoding.DecodeString(html.UnescapeString(string(m[1])))
	lr := decodeLogoutResponse(t, raw)
	if lr.InResponseTo != req.ID || lr.Status.StatusCode.Value != crewjam.StatusSuccess || lr.Destination != "https://idp.test/slo-post" {
		t.Errorf("LogoutResponse = InResponseTo %q status %q destination %q", lr.InResponseTo, lr.Status.StatusCode.Value, lr.Destination)
	}
	if lr.Signature == nil {
		t.Error("a POST-bound LogoutResponse must be signed")
	}

	// The IdP offers only HTTP-Redirect: a POST-bound request is answered there.
	h = sloHarness(t)
	resp = h.slo(t, postSLO(theIdP.signedPost(t, idpLogoutRequest(idpEntity, "jdoe", "", time.Now()))))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("redirect-only IdP: status %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Host != "idp.test" || loc.Path != "/slo" || loc.Query().Get("Signature") == "" {
		t.Errorf("redirect-only IdP: answered at %s, want a query-signed LogoutResponse at its SLO URL", loc)
	}
}

// Keycloak and most IdPs sign the HTTP-Redirect binding in the query string,
// not inside the message.
func TestIDPInitiatedLogoutRedirect(t *testing.T) {
	h := sloHarness(t)
	req := idpLogoutRequest(idpEntity, "jdoe", "", time.Now())
	resp := h.slo(t, httptest.NewRequest(http.MethodGet, SLOPath+"?"+theIdP.querySigned(t, req, "relay"), nil))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Host != "idp.test" || loc.Query().Get("SAMLResponse") == "" || loc.Query().Get("RelayState") != "relay" {
		t.Errorf("redirect = %s, want a LogoutResponse to the IdP carrying RelayState", loc)
	}
	// No SessionIndex: every session of that principal at this IdP.
	if len(h.sessions.ended) != 1 || h.sessions.ended[0].nameID != "jdoe" || h.sessions.ended[0].sessionIndex != "" {
		t.Errorf("ended = %+v", h.sessions.ended)
	}
}

func TestIDPInitiatedLogoutRefused(t *testing.T) {
	now := time.Now()
	good := func() *crewjam.LogoutRequest { return idpLogoutRequest(idpEntity, "jdoe", "s", now) }
	unsigned := func(t *testing.T) string { t.Helper(); return encode(t, good().Element()) }

	tamperedQuery := func(t *testing.T) string {
		t.Helper()
		q := theIdP.querySigned(t, good(), "relay")
		return strings.Replace(q, "RelayState=relay", "RelayState=evil", 1)
	}
	unsignedQuery := func(t *testing.T) string {
		t.Helper()
		q := theIdP.querySigned(t, good(), "")
		unsigned, _, _ := strings.Cut(q, "&SigAlg=")
		return unsigned
	}
	cases := map[string]func(t *testing.T) *http.Request{
		"unsigned POST":         func(t *testing.T) *http.Request { t.Helper(); return postSLO(unsigned(t)) },
		"signed by another IdP": func(t *testing.T) *http.Request { t.Helper(); return postSLO(rogueIdP.signedPost(t, good())) },
		"wrong issuer": func(t *testing.T) *http.Request {
			t.Helper()
			return postSLO(theIdP.signedPost(t, idpLogoutRequest("https://rogue.test", "jdoe", "s", now)))
		},
		"expired": func(t *testing.T) *http.Request {
			t.Helper()
			return postSLO(theIdP.signedPost(t, idpLogoutRequest(idpEntity, "jdoe", "s", now.Add(-time.Hour))))
		},
		"query signed by another": func(t *testing.T) *http.Request {
			t.Helper()
			return httptest.NewRequest(http.MethodGet, SLOPath+"?"+rogueIdP.querySigned(t, good(), ""), nil)
		},
		"query tampered after signing": func(t *testing.T) *http.Request {
			t.Helper()
			return httptest.NewRequest(http.MethodGet, SLOPath+"?"+tamperedQuery(t), nil)
		},
		"redirect without any signature": func(t *testing.T) *http.Request {
			t.Helper()
			return httptest.NewRequest(http.MethodGet, SLOPath+"?"+unsignedQuery(t), nil)
		},
		"signed POST, edited after signing": func(t *testing.T) *http.Request {
			t.Helper()
			signed, _ := base64.StdEncoding.DecodeString(theIdP.signedPost(t, good()))
			edited := strings.Replace(string(signed), ">jdoe<", ">admin<", 1)
			return postSLO(base64.StdEncoding.EncodeToString([]byte(edited)))
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			h := sloHarness(t)
			resp := h.slo(t, build(t))
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status %d, want 400", resp.StatusCode)
			}
			if len(h.sessions.ended) != 0 {
				t.Errorf("a refused request ended sessions: %+v", h.sessions.ended)
			}
		})
	}
}

// The LogoutResponse completing an SP-initiated logout lands on the login
// page — and so does a rejected one, since the local sign-out already happened.
func TestLogoutResponseLandsOnLogin(t *testing.T) {
	h := sloHarness(t)
	resp := h.slo(t, httptest.NewRequest(http.MethodGet, SLOPath+"?SAMLResponse="+url.QueryEscape("bm90IHhtbA=="), nil))
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/login" {
		t.Errorf("status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}
