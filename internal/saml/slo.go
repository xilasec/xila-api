package saml

import (
	"bytes"
	"compress/flate"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/beevik/etree"
	crewjam "github.com/crewjam/saml"
	xrv "github.com/mattermost/xml-roundtrip-validator"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
)

// maxLogoutMessageSize bounds an inflated/decoded LogoutRequest or
// LogoutResponse, the same defensive limit ACS parsing applies via
// io.LimitReader elsewhere in this package.
const maxLogoutMessageSize = 1 << 20 // 1 MiB

// LogoutRedirect builds a LogoutRequest (HTTP-Redirect binding, signed in the
// query like the AuthnRequest) for this session and returns the URL to send
// the browser to. ok is false if the IdP's metadata advertises no
// HTTP-Redirect SingleLogoutService — nothing to redirect to, so the caller
// falls back to a plain local sign-out. Implements sso.SAMLLogoutClient.
func (s *Service) LogoutRedirect(nameID, nameIDFormat, sessionIndex, relayState string) (redirectURL string, ok bool, err error) {
	idpURL := s.sp.GetSLOBindingLocation(crewjam.HTTPRedirectBinding)
	if idpURL == "" {
		return "", false, nil
	}
	req := s.logoutRequest(idpURL, nameID, nameIDFormat, sessionIndex)
	u, err := s.redirectURL(idpURL, "SAMLRequest", req.Element(), relayState)
	if err != nil {
		return "", false, err
	}
	return u, true, nil
}

// logoutRequest builds an (unsigned) LogoutRequest for idpURL. Built by hand
// rather than with crewjam's ServiceProvider.MakeLogoutRequest: that helper
// always sends NameID Format "unspecified", where the IdP expects back the
// format it originally asserted.
func (s *Service) logoutRequest(idpURL, nameID, nameIDFormat, sessionIndex string) *crewjam.LogoutRequest {
	req := &crewjam.LogoutRequest{
		ID:           "id-" + randHex(20),
		Version:      "2.0",
		IssueInstant: time.Now(),
		Destination:  idpURL,
		Issuer: &crewjam.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  firstNonEmpty(s.sp.EntityID, s.sp.MetadataURL.String()),
		},
		NameID: &crewjam.NameID{
			Format: nameIDFormat, Value: nameID,
			NameQualifier:   s.sp.IDPMetadata.EntityID,
			SPNameQualifier: s.sp.EntityID,
		},
	}
	if sessionIndex != "" {
		req.SessionIndex = &crewjam.SessionIndex{Value: sessionIndex}
	}
	return req
}

// redirectURL encodes a message for the HTTP-Redirect binding (SAML 2.0
// Bindings §3.4.4): deflate + base64 into param, then RelayState, SigAlg and a
// Signature over those octets, in that order — the same construction crewjam
// uses for the AuthnRequest. The message itself carries no XML signature
// (the binding forbids it). Unsigned when signing requests is turned off.
func (s *Service) redirectURL(dest, param string, el *etree.Element, relayState string) (string, error) {
	var buf bytes.Buffer
	b64 := base64.NewEncoder(base64.StdEncoding, &buf)
	fw, err := flate.NewWriter(b64, flate.BestCompression)
	if err != nil {
		return "", err
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	if _, err := doc.WriteTo(fw); err != nil {
		return "", err
	}
	if err := fw.Close(); err != nil {
		return "", err
	}
	if err := b64.Close(); err != nil {
		return "", err
	}
	u, err := url.Parse(dest)
	if err != nil {
		return "", err
	}
	query := u.RawQuery
	if query != "" {
		query += "&"
	}
	query += param + "=" + url.QueryEscape(buf.String())
	if relayState != "" {
		query += "&RelayState=" + url.QueryEscape(relayState)
	}
	if s.sp.SignatureMethod != "" {
		query += "&SigAlg=" + url.QueryEscape(s.sp.SignatureMethod)
		ctx, err := crewjam.GetSigningContext(&s.sp)
		if err != nil {
			return "", fmt.Errorf("signing context: %w", err)
		}
		sig, err := ctx.SignString(query)
		if err != nil {
			return "", fmt.Errorf("sign %s: %w", param, err)
		}
		query += "&Signature=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sig))
	}
	u.RawQuery = query
	return u.String(), nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// idpSigningCerts returns the IdP's signing certificates from its metadata
// (KeyDescriptors with no Use, or Use="signing"). crewjam's equivalent is
// unexported; a LogoutRequest has no crewjam-provided verifier to call into,
// so this package validates it directly with goxmldsig against these same
// certificates — never hand-rolled cryptography, only the IdP-cert lookup
// crewjam itself does for every other signed message.
func idpSigningCerts(idp *crewjam.EntityDescriptor) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for _, d := range idp.IDPSSODescriptors {
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
				certs = append(certs, cert)
			}
		}
	}
	if len(certs) == 0 {
		return nil, errors.New("the IdP metadata carries no signing certificate")
	}
	return certs, nil
}

// validateEnvelopedSignature verifies el's enveloped <Signature> against the
// IdP's signing certificates (goxmldsig), the same mechanism crewjam's own
// unexported validateSignature uses for every ACS response. It returns the
// element as verified — callers decode that, never the raw input.
func validateEnvelopedSignature(el *etree.Element, idp *crewjam.EntityDescriptor) (*etree.Element, error) {
	sigEl := el.FindElement("./Signature")
	if sigEl == nil {
		return nil, errors.New("saml: message is not signed")
	}
	certs, err := idpSigningCerts(idp)
	if err != nil {
		return nil, err
	}
	// No embedded certificate: fall back to the configured IdP metadata
	// certificates, exactly like crewjam's validateSignature does.
	if el.FindElement("./Signature/KeyInfo/X509Data/X509Certificate") == nil {
		if keyInfo := sigEl.FindElement("KeyInfo"); keyInfo != nil {
			sigEl.RemoveChild(keyInfo)
		}
	}
	validationCtx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: certs})
	validationCtx.IdAttribute = "ID"
	nsCtx, err := etreeutils.NSBuildParentContext(el)
	if err != nil {
		return nil, fmt.Errorf("saml: namespace context: %w", err)
	}
	nsCtx, err = nsCtx.SubContext(el)
	if err != nil {
		return nil, fmt.Errorf("saml: namespace context: %w", err)
	}
	detached, err := etreeutils.NSDetatch(nsCtx, el)
	if err != nil {
		return nil, fmt.Errorf("saml: detach namespace context: %w", err)
	}
	verified, err := validationCtx.Validate(detached)
	if err != nil {
		return nil, fmt.Errorf("saml: signature invalid: %w", err)
	}
	return verified, nil
}

// querySignatureAlgorithms are the SigAlg values accepted on an HTTP-Redirect
// binding signature. SHA-1 is deliberately absent (the stdlib refuses it too).
var querySignatureAlgorithms = map[string]x509.SignatureAlgorithm{
	dsig.RSASHA256SignatureMethod:   x509.SHA256WithRSA,
	dsig.RSASHA384SignatureMethod:   x509.SHA384WithRSA,
	dsig.RSASHA512SignatureMethod:   x509.SHA512WithRSA,
	dsig.ECDSASHA256SignatureMethod: x509.ECDSAWithSHA256,
	dsig.ECDSASHA384SignatureMethod: x509.ECDSAWithSHA384,
	dsig.ECDSASHA512SignatureMethod: x509.ECDSAWithSHA512,
}

// rawQueryValues splits a query string into its parameters WITHOUT decoding
// the values: an HTTP-Redirect signature covers the octets exactly as the
// IdP encoded them (SAML 2.0 Bindings §3.4.4.1), so re-encoding a decoded
// value could change them. A repeated parameter is refused as ambiguous.
func rawQueryValues(rawQuery string) (map[string]string, error) {
	out := map[string]string{}
	for _, part := range strings.Split(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		name, err := url.QueryUnescape(k)
		if err != nil {
			return nil, fmt.Errorf("query parameter %q: %w", k, err)
		}
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("query parameter %q repeated", name)
		}
		out[name] = v
	}
	return out, nil
}

// verifyQuerySignature checks an HTTP-Redirect binding signature: Signature
// over "SAMLRequest=…[&RelayState=…]&SigAlg=…" (raw, as received) with one of
// the IdP's metadata signing certificates. Stdlib x509 verification only.
func verifyQuerySignature(raw map[string]string, messageParam string, idp *crewjam.EntityDescriptor) error {
	sigAlg, err := url.QueryUnescape(raw["SigAlg"])
	if err != nil {
		return fmt.Errorf("SigAlg: %w", err)
	}
	alg, ok := querySignatureAlgorithms[sigAlg]
	if !ok {
		return fmt.Errorf("unsupported SigAlg %q", sigAlg)
	}
	sigB64, err := url.QueryUnescape(raw["Signature"])
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	signed := messageParam + "=" + raw[messageParam]
	if rs, ok := raw["RelayState"]; ok {
		signed += "&RelayState=" + rs
	}
	signed += "&SigAlg=" + raw["SigAlg"]
	certs, err := idpSigningCerts(idp)
	if err != nil {
		return err
	}
	for _, cert := range certs {
		if cert.CheckSignature(alg, []byte(signed), sig) == nil {
			return nil
		}
	}
	return errors.New("saml: redirect-binding signature invalid")
}

func inflateLimited(data []byte) ([]byte, error) {
	zr := flate.NewReader(bytes.NewReader(data))
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, maxLogoutMessageSize))
}

// parseLogoutRequestRedirect decodes a HTTP-Redirect-bound LogoutRequest
// (deflate + base64) from the raw query string and validates it. The IdP may
// sign either the query (SigAlg + Signature, the usual form for this binding,
// e.g. Keycloak) or the message itself (enveloped); one of the two is required.
func (s *Service) parseLogoutRequestRedirect(rawQuery string) (*crewjam.LogoutRequest, error) {
	raw, err := rawQueryValues(rawQuery)
	if err != nil {
		return nil, err
	}
	encoded, err := url.QueryUnescape(raw["SAMLRequest"])
	if err != nil {
		return nil, fmt.Errorf("decode SAMLRequest: %w", err)
	}
	compressed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode SAMLRequest: %w", err)
	}
	msg, err := inflateLimited(compressed)
	if err != nil {
		return nil, fmt.Errorf("inflate SAMLRequest: %w", err)
	}
	querySigned := raw["Signature"] != ""
	if querySigned {
		if err := verifyQuerySignature(raw, "SAMLRequest", s.sp.IDPMetadata); err != nil {
			return nil, err
		}
	}
	return s.parseLogoutRequest(msg, querySigned)
}

// parseLogoutRequestPost decodes a HTTP-POST-bound LogoutRequest (base64)
// and validates it; this binding is always signed inside the message.
func (s *Service) parseLogoutRequestPost(encoded string) (*crewjam.LogoutRequest, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode SAMLRequest: %w", err)
	}
	return s.parseLogoutRequest(raw, false)
}

// parseLogoutRequest validates an IdP-initiated LogoutRequest: well-formed
// XML (xml-roundtrip-validator, like every other message this package
// parses), a valid signature from the IdP's metadata certificate (enveloped,
// unless querySigned says the caller already verified the redirect-binding
// query signature, which covers the whole encoded message), not expired, the
// right issuer and destination, and a NameID to act on.
func (s *Service) parseLogoutRequest(raw []byte, querySigned bool) (*crewjam.LogoutRequest, error) {
	if err := xrv.Validate(bytes.NewReader(raw)); err != nil {
		return nil, fmt.Errorf("saml logout request: %w", err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		return nil, fmt.Errorf("parse logout request: %w", err)
	}
	root := doc.Root()
	if root == nil || root.Tag != "LogoutRequest" || root.NamespaceURI() != "urn:oasis:names:tc:SAML:2.0:protocol" {
		return nil, errors.New("not a SAML LogoutRequest")
	}
	el := root
	if !querySigned {
		verified, err := validateEnvelopedSignature(root, s.sp.IDPMetadata)
		if err != nil {
			return nil, err
		}
		el = verified
	}
	// Decode exactly what was verified, never a second parse of the input.
	out := etree.NewDocument()
	out.SetRoot(el.Copy())
	verifiedBytes, err := out.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("logout request: %w", err)
	}
	var req crewjam.LogoutRequest
	if err := xml.Unmarshal(verifiedBytes, &req); err != nil {
		return nil, fmt.Errorf("decode logout request: %w", err)
	}
	now := time.Now()
	if req.IssueInstant.Add(crewjam.MaxIssueDelay).Before(now) {
		return nil, errors.New("logout request expired")
	}
	if req.NotOnOrAfter != nil && req.NotOnOrAfter.Add(crewjam.MaxClockSkew).Before(now) {
		return nil, errors.New("logout request expired")
	}
	if req.Issuer == nil || req.Issuer.Value != s.sp.IDPMetadata.EntityID {
		return nil, errors.New("logout request issuer does not match the IdP metadata")
	}
	if req.Destination != "" && req.Destination != s.sp.SloURL.String() {
		return nil, errors.New("logout request destination does not match our SLO URL")
	}
	if req.NameID == nil || req.NameID.Value == "" {
		return nil, errors.New("logout request has no NameID")
	}
	return &req, nil
}

// errNoSLOEndpoint: the IdP sent a LogoutRequest but its metadata advertises
// no SingleLogoutService to answer at.
var errNoSLOEndpoint = errors.New("the IdP metadata advertises no SingleLogoutService")

// logoutResponse answers requestID with a Success LogoutResponse at the IdP's
// SingleLogoutService, in the binding the IdP advertises — the one the request
// came in (preferPost) when it offers both. Exactly one of redirect and form
// is set: an HTTP-Redirect URL signed in the query, or an auto-submitting
// HTTP-POST form carrying an enveloped-signed message.
func (s *Service) logoutResponse(requestID, relayState string, preferPost bool) (redirect string, form []byte, err error) {
	postURL := s.sp.GetSLOBindingLocation(crewjam.HTTPPostBinding)
	redirectLoc := s.sp.GetSLOBindingLocation(crewjam.HTTPRedirectBinding)
	usePost := postURL != "" && (preferPost || redirectLoc == "")
	if !usePost && redirectLoc == "" {
		return "", nil, errNoSLOEndpoint
	}
	dest := redirectLoc
	if usePost {
		dest = postURL
	}
	resp := &crewjam.LogoutResponse{
		ID:           "id-" + randHex(20),
		InResponseTo: requestID,
		Version:      "2.0",
		IssueInstant: time.Now(),
		Destination:  dest,
		Issuer: &crewjam.Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  firstNonEmpty(s.sp.EntityID, s.sp.MetadataURL.String()),
		},
		Status: crewjam.Status{StatusCode: crewjam.StatusCode{Value: crewjam.StatusSuccess}},
	}
	if !usePost {
		u, err := s.redirectURL(dest, "SAMLResponse", resp.Element(), relayState)
		return u, nil, err
	}
	if s.sp.SignatureMethod != "" {
		if err := s.sp.SignLogoutResponse(resp); err != nil {
			return "", nil, fmt.Errorf("sign logout response: %w", err)
		}
	}
	return "", resp.Post(relayState), nil
}

// parseLogoutResponseRedirect validates a HTTP-Redirect-bound LogoutResponse
// completing an SP-initiated logout: crewjam checks the IdP's signature,
// Destination, expiry, issuer and a Success status.
func (s *Service) parseLogoutResponseRedirect(encoded string) error {
	return s.sp.ValidateLogoutResponseRedirect(encoded)
}

// parseLogoutResponsePost validates a HTTP-POST-bound LogoutResponse.
func (s *Service) parseLogoutResponsePost(encoded string) error {
	return s.sp.ValidateLogoutResponseForm(encoded)
}
