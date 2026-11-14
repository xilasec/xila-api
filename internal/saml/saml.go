// Package saml implements Single Sign-On via SAML 2.0, with Xila as the
// service provider. XML signature verification, audience/recipient/destination,
// validity-window and InResponseTo checks are crewjam/saml's (goxmldsig +
// xml-roundtrip-validator underneath); this package adds what it leaves to the
// application — request tracking, replay protection, a single-assertion rule —
// and turns the verified assertion into an sso.Assertion.
//
// Supported: SP-initiated login (HTTP-Redirect AuthnRequest, optionally signed),
// HTTP-POST responses (assertion or response signed, optionally encrypted),
// optional IdP-initiated login, and Single Logout — SP-initiated (HTTP-Redirect
// LogoutRequest) and IdP-initiated (HTTP-Redirect or HTTP-POST LogoutRequest),
// both at one SLO endpoint (slo.go). Not supported: the Artifact binding.
package saml

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/xilasec/xila-api/internal/netguard"
	"github.com/xilasec/xila-api/internal/sso"
)

// Paths of the environment-configured provider (SAML_*), under the public base
// URL. Database providers live at /api/v1/auth/saml/{slug}/….
const (
	MetadataPath = "/api/v1/auth/saml/metadata"
	LoginPath    = "/api/v1/auth/saml/login"
	ACSPath      = "/api/v1/auth/saml/acs"
	SLOPath      = "/api/v1/auth/saml/slo"
)

// Attribute names tried for the email when no email attribute is configured, in
// order: plain names (Keycloak, Okta), the WS-Fed claim (Entra ID, ADFS), the
// LDAP OID (Shibboleth).
var defaultEmailAttributes = []string{
	"email", "mail",
	"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
	"urn:oid:0.9.2342.19200300.100.1.3",
}

// Protocol builds SAML service providers for the provider registry
// (sso.Protocol).
type Protocol struct {
	// Keys holds the shared generated SP key pair, used by every provider
	// without its own (SAML_SP_CERT/KEY, or sp_cert/sp_key).
	Keys *KeyStore
	// HTTPClient fetches IdP metadata; nil = a client with a 15s timeout.
	HTTPClient *http.Client
}

// Build loads the provider's IdP metadata and SP key pair and returns its
// Service.
func (pr Protocol) Build(ctx context.Context, p sso.Provider) (sso.Client, error) {
	idp, err := LoadIDPMetadata(ctx, p.IDPMetadata, p.IDPMetadataURL, pr.HTTPClient)
	if err != nil {
		return nil, err
	}
	var keys KeyPair
	if p.SPKey != "" {
		keys, err = ParseKeyPair(p.SPCert, p.SPKey)
	} else if pr.Keys != nil {
		keys, err = pr.Keys.LoadOrCreate(ctx, p.Endpoints.SPEntityID)
	} else {
		err = errors.New("saml: no SP key pair configured")
	}
	if err != nil {
		return nil, err
	}
	return New(p, idp, keys)
}

// Service is a configured SAML service provider bound to one IdP.
type Service struct {
	sp        crewjam.ServiceProvider // strict: responses must answer a request we made
	idpInit   crewjam.ServiceProvider // lenient copy for IdP-initiated logins (when allowed)
	provider  sso.Provider
	cookieKey []byte
}

// New builds the service provider for p from the IdP metadata (already
// loaded) and the SP key pair. The SP entity id, ACS and metadata URLs are p's
// Endpoints — each provider has its own.
func New(p sso.Provider, idp *crewjam.EntityDescriptor, keys KeyPair) (*Service, error) {
	if len(idp.IDPSSODescriptors) == 0 {
		return nil, errors.New("saml: the IdP metadata has no IDPSSODescriptor")
	}
	acs, err := url.Parse(p.Endpoints.ACSURL)
	if err != nil || p.Endpoints.ACSURL == "" {
		return nil, fmt.Errorf("saml: ACS URL %q: %v", p.Endpoints.ACSURL, err)
	}
	meta, err := url.Parse(p.Endpoints.MetadataURL)
	if err != nil {
		return nil, fmt.Errorf("saml: metadata URL: %w", err)
	}
	slo, err := url.Parse(p.Endpoints.SLOURL)
	if err != nil {
		return nil, fmt.Errorf("saml: SLO URL: %w", err)
	}
	sp := crewjam.ServiceProvider{
		EntityID:    p.Endpoints.SPEntityID,
		Key:         keys.Key,
		Certificate: keys.Cert,
		MetadataURL: *meta,
		AcsURL:      *acs,
		SloURL:      *slo,
		// Advertised in our metadata so an IdP can send either binding;
		// accepting both is also how the SLO handler dispatches a request.
		LogoutBindings: []string{crewjam.HTTPRedirectBinding, crewjam.HTTPPostBinding},
		IDPMetadata:    idp,
		// Unspecified lets the IdP send its configured NameID (persistent or
		// email); a transient one is refused at login.
		AuthnNameIDFormat: crewjam.UnspecifiedNameIDFormat,
	}
	if p.SignRequests {
		sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	}
	if sp.GetSSOBindingLocation(crewjam.HTTPRedirectBinding) == "" {
		return nil, errors.New("saml: the IdP metadata has no HTTP-Redirect SingleSignOnService")
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(keys.Key)
	if err != nil {
		return nil, fmt.Errorf("saml: key: %w", err)
	}
	// The request-tracking MAC key is derived from the SP key — shared by every
	// replica — and, for database providers, bound to the provider too: they
	// may share the generated key, but a tracking cookie of one never
	// validates at another.
	label := "xila-saml-request-tracking"
	if !p.Env() {
		label += ":" + p.ID
	}
	mac := hmac.New(sha256.New, []byte(label))
	mac.Write(keyDER)

	idpInit := sp
	idpInit.AllowIDPInitiated = true
	return &Service{sp: sp, idpInit: idpInit, provider: p, cookieKey: mac.Sum(nil)}, nil
}

// LoadIDPMetadata parses the IdP metadata XML when given, else fetches it
// from metadataURL.
func LoadIDPMetadata(ctx context.Context, metadataXML, metadataURL string, client *http.Client) (*crewjam.EntityDescriptor, error) {
	if metadataXML != "" {
		return ParseMetadata([]byte(metadataXML))
	}
	if client == nil {
		client = netguard.NewClient(15 * time.Second)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return nil, fmt.Errorf("saml metadata url: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch saml metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch saml metadata: HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("read saml metadata: %w", err)
	}
	return ParseMetadata(data)
}

// ParseMetadata parses an EntityDescriptor, or the first entity with an
// IDPSSODescriptor in an EntitiesDescriptor (federation metadata).
func ParseMetadata(data []byte) (*crewjam.EntityDescriptor, error) {
	if err := xrv.Validate(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("saml metadata: %w", err)
	}
	entity := &crewjam.EntityDescriptor{}
	err := xml.Unmarshal(data, entity)
	if err == nil {
		return entity, nil
	}
	entities := &crewjam.EntitiesDescriptor{}
	if xml.Unmarshal(data, entities) != nil {
		return nil, fmt.Errorf("saml metadata: %w", err)
	}
	for i, e := range entities.EntityDescriptors {
		if len(e.IDPSSODescriptors) > 0 {
			return &entities.EntityDescriptors[i], nil
		}
	}
	return nil, errors.New("saml metadata: no entity with an IDPSSODescriptor")
}

// certExpiryWarning is how close to expiry an IdP signing certificate gets a
// warning in the dry run.
const certExpiryWarning = 30 * 24 * time.Hour

// Report describes what the IdP metadata says, for the admin page's dry run.
func (s *Service) Report() sso.Report {
	idp := s.sp.IDPMetadata
	r := sso.Report{Details: []sso.Setting{
		{Label: "IdP entity ID", Value: idp.EntityID},
		{Label: "SSO URL (HTTP-Redirect)", Value: s.sp.GetSSOBindingLocation(crewjam.HTTPRedirectBinding)},
		{Label: "SP entity ID", Value: s.sp.EntityID},
		{Label: "ACS URL", Value: s.sp.AcsURL.String()},
		{Label: "Signed AuthnRequests", Value: strconv.FormatBool(s.provider.SignRequests)},
	}}
	now := time.Now()
	for _, d := range idp.IDPSSODescriptors {
		if d.WantAuthnRequestsSigned != nil && *d.WantAuthnRequestsSigned && !s.provider.SignRequests {
			r.Warnings = append(r.Warnings, "the IdP wants signed AuthnRequests, but request signing is off")
		}
		for _, kd := range d.KeyDescriptors {
			if kd.Use != "" && kd.Use != "signing" {
				continue
			}
			for _, xc := range kd.KeyInfo.X509Data.X509Certificates {
				der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(xc.Data), ""))
				if err != nil {
					continue
				}
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					continue
				}
				expired := now.After(cert.NotAfter)
				r.Certificates = append(r.Certificates, sso.Certificate{
					Subject: cert.Subject.String(), NotAfter: cert.NotAfter, Expired: expired,
				})
				switch {
				case expired:
					r.Warnings = append(r.Warnings, fmt.Sprintf("signing certificate %q expired on %s", cert.Subject, cert.NotAfter.Format(time.DateOnly)))
				case cert.NotAfter.Sub(now) < certExpiryWarning:
					r.Warnings = append(r.Warnings, fmt.Sprintf("signing certificate %q expires on %s", cert.Subject, cert.NotAfter.Format(time.DateOnly)))
				}
			}
		}
	}
	if len(r.Certificates) == 0 {
		r.Warnings = append(r.Warnings, "the IdP metadata carries no signing certificate — no response can be verified")
	}
	return r
}

// Metadata is the SP metadata XML to give the IdP. Only the HTTP-POST ACS is
// advertised (the Artifact binding is not supported).
func (s *Service) Metadata() ([]byte, error) {
	md := s.sp.Metadata()
	for i := range md.SPSSODescriptors {
		var acs []crewjam.IndexedEndpoint
		for _, e := range md.SPSSODescriptors[i].AssertionConsumerServices {
			if e.Binding == crewjam.HTTPPostBinding {
				acs = append(acs, e)
			}
		}
		md.SPSSODescriptors[i].AssertionConsumerServices = acs
	}
	out, err := xml.MarshalIndent(md, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), out...), nil
}

// authnRequest builds the HTTP-Redirect URL for a new AuthnRequest and returns
// the request id to track.
func (s *Service) authnRequest(relayState string) (redirect *url.URL, requestID string, err error) {
	req, err := s.sp.MakeAuthenticationRequest(s.sp.GetSSOBindingLocation(crewjam.HTTPRedirectBinding),
		crewjam.HTTPRedirectBinding, crewjam.HTTPPostBinding)
	if err != nil {
		return nil, "", err
	}
	redirect, err = req.Redirect(relayState, &s.sp)
	if err != nil {
		return nil, "", err
	}
	return redirect, req.ID, nil
}

// Validation errors this package adds on top of crewjam's.
var (
	errNotOneAssertion = errors.New("response must carry exactly one assertion")
	errTransientNameID = errors.New("transient NameID cannot identify a returning user; configure a persistent or email NameID at the IdP")
)

// parse verifies a base64 SAMLResponse. requestID is the AuthnRequest this
// browser made (tracked in its cookie); empty means unsolicited (IdP-initiated),
// which is only accepted when allowed.
func (s *Service) parse(samlResponse, requestID string) (*crewjam.Assertion, error) {
	raw, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, fmt.Errorf("decode SAMLResponse: %w", err)
	}
	// Signature-wrapping hardening: crewjam returns the first assertion that
	// validates, so a response smuggling extra assertions next to a signed one
	// is refused outright rather than trusted to pick the right one.
	if n, err := countAssertions(raw); err != nil {
		return nil, err
	} else if n != 1 {
		return nil, errNotOneAssertion
	}
	sp, ids := &s.sp, []string{requestID}
	if requestID == "" {
		if !s.provider.AllowIDPInitiated {
			return nil, errors.New("unsolicited response (IdP-initiated login is disabled)")
		}
		sp, ids = &s.idpInit, nil
	}
	assertion, err := sp.ParseXMLResponse(raw, ids, sp.AcsURL)
	if err != nil {
		// InvalidResponseError carries the whole response; log only the cause.
		if ire, ok := errors.AsType[*crewjam.InvalidResponseError](err); ok {
			return nil, fmt.Errorf("invalid SAML response: %w", ire.PrivateErr)
		}
		return nil, err
	}
	if assertion.Subject == nil || assertion.Subject.NameID == nil || assertion.Subject.NameID.Value == "" {
		return nil, errors.New("assertion has no NameID")
	}
	if assertion.Subject.NameID.Format == string(crewjam.TransientNameIDFormat) {
		return nil, errTransientNameID
	}
	return assertion, nil
}

// countAssertions counts Assertion + EncryptedAssertion children of the
// Response root (namespace-aware).
func countAssertions(raw []byte) (int, error) {
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return 0, fmt.Errorf("parse SAMLResponse: %w", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "Response" || root.NamespaceURI() != "urn:oasis:names:tc:SAML:2.0:protocol" {
		return 0, errors.New("not a SAML Response")
	}
	n := 0
	for _, el := range root.ChildElements() {
		if (el.Tag == "Assertion" || el.Tag == "EncryptedAssertion") &&
			el.NamespaceURI() == "urn:oasis:names:tc:SAML:2.0:assertion" {
			n++
		}
	}
	return n, nil
}

// replayUntil is how long the assertion id must stay remembered: until every
// validity check crewjam applies would reject it anyway.
func replayUntil(a *crewjam.Assertion) time.Time {
	until := a.IssueInstant.Add(crewjam.MaxIssueDelay)
	if a.Conditions != nil {
		until = later(until, a.Conditions.NotOnOrAfter.Add(crewjam.MaxClockSkew))
	}
	if a.Subject != nil {
		for _, sc := range a.Subject.SubjectConfirmations {
			if sc.SubjectConfirmationData != nil {
				until = later(until, sc.SubjectConfirmationData.NotOnOrAfter.Add(crewjam.MaxClockSkew))
			}
		}
	}
	return later(until, time.Now().Add(crewjam.MaxIssueDelay))
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

// toSSO maps a verified assertion to the protocol-neutral login. SAML has no
// "email verified" claim: the IdP's signed assertion vouches for the address,
// and the provider's link_by_email (SAML_LINK_BY_EMAIL) decides whether that is
// enough to attach to an existing account (sso.Service).
func (s *Service) toSSO(a *crewjam.Assertion) sso.Assertion {
	nameID := a.Subject.NameID
	return sso.Assertion{
		Issuer:        s.sp.IDPMetadata.EntityID,
		Subject:       nameID.Value,
		SubjectFormat: nameID.Format,
		Email:         s.email(a),
		EmailTrust:    sso.EmailVerified,
		Groups:        s.groups(a),
		SessionIndex:  sessionIndexOf(a),
	}
}

// sessionIndexOf returns the AuthnStatement's SessionIndex, when the IdP sent
// one — Single Logout's LogoutRequest/SP-initiated LogoutRequest address a
// session by NameID + SessionIndex; many IdPs omit it, in which case a logout
// addresses every session for that NameID.
func sessionIndexOf(a *crewjam.Assertion) string {
	for _, st := range a.AuthnStatements {
		if st.SessionIndex != "" {
			return st.SessionIndex
		}
	}
	return ""
}

// email reads the configured attribute, or the first common email attribute,
// or an emailAddress-format NameID.
func (s *Service) email(a *crewjam.Assertion) string {
	attr := s.provider.EmailAttribute
	names := defaultEmailAttributes
	if attr != "" {
		names = []string{attr}
	}
	for _, name := range names {
		if v := attributeValues(a, name); len(v) > 0 {
			return v[0]
		}
	}
	if attr == "" && a.Subject.NameID.Format == string(crewjam.EmailAddressNameIDFormat) {
		return a.Subject.NameID.Value
	}
	return ""
}

// groups collects every value of every configured groups attribute.
func (s *Service) groups(a *crewjam.Assertion) []string {
	var out []string
	for _, name := range s.provider.GroupsAttributes {
		out = append(out, attributeValues(a, name)...)
	}
	return out
}

// attributeValues returns the non-empty values of the attribute with this Name
// (or FriendlyName), across all attribute statements.
func attributeValues(a *crewjam.Assertion, name string) []string {
	var out []string
	for _, st := range a.AttributeStatements {
		for _, attr := range st.Attributes {
			if attr.Name != name && attr.FriendlyName != name {
				continue
			}
			for _, v := range attr.Values {
				if val := strings.TrimSpace(v.Value); val != "" {
					out = append(out, val)
				}
			}
		}
	}
	return out
}
