package sso

import (
	"crypto/rsa"
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/netguard"
)

// Where a provider is configured.
const (
	// SourceEnvironment: OIDC_* / SAML_* — at most one per kind, read-only in
	// the API, slug and id = the kind, served at the original routes
	// (/api/v1/auth/oidc/login, /api/v1/auth/saml/acs…).
	SourceEnvironment = "environment"
	// SourceDatabase: added by an admin at runtime, served at
	// /api/v1/auth/{kind}/{slug}/….
	SourceDatabase = "database"
)

// Provider errors.
var (
	ErrProviderNotFound = errors.New("sso provider not found")
	ErrInvalidProvider  = errors.New("invalid sso provider")
	ErrSlugTaken        = errors.New("another sso provider already uses this slug")
	ErrReadOnly         = errors.New("this provider is configured by environment variables and is read-only here — change it in the environment and restart")
)

const authBase = "/api/v1/auth/"

// Provider is one configured identity provider. Secrets (ClientSecret, SPKey)
// are write-only: never serialized, only reported as HasClientSecret/HasSPKey.
type Provider struct {
	ID        string `json:"id"` // uuid; for environment providers the kind ("oidc" / "saml")
	Slug      string `json:"slug"`
	Kind      string `json:"kind"` // oidc | saml
	Name      string `json:"name"` // login button label
	Source    string `json:"source"`
	Enabled   bool   `json:"enabled"`
	SortOrder int    `json:"sort_order"`

	// OIDC
	Issuer               string   `json:"issuer,omitempty"`
	ClientID             string   `json:"client_id,omitempty"`
	ClientSecret         string   `json:"-"`
	HasClientSecret      bool     `json:"has_client_secret"`
	Scopes               []string `json:"scopes,omitempty"`
	GroupsClaim          string   `json:"groups_claim,omitempty"`
	TrustUnverifiedEmail bool     `json:"trust_unverified_email"`

	// SAML
	IDPMetadataURL    string   `json:"idp_metadata_url,omitempty"`
	IDPMetadata       string   `json:"idp_metadata,omitempty"`
	EntityID          string   `json:"entity_id,omitempty"` // SP entity id override; empty = the default
	EmailAttribute    string   `json:"email_attribute,omitempty"`
	GroupsAttributes  []string `json:"groups_attributes,omitempty"`
	AllowIDPInitiated bool     `json:"allow_idp_initiated"`
	SignRequests      bool     `json:"sign_requests"`
	SPCert            string   `json:"sp_cert,omitempty"` // own SP certificate; empty = the shared generated one
	SPKey             string   `json:"-"`
	HasSPKey          bool     `json:"has_sp_key"`

	// Login policy. AutoCreateUsers nil = the instance default
	// (SSO_AUTO_CREATE_USERS). LinkByEmail lets a first login attach to an
	// existing account with the same email (OIDC: only if the IdP verified it).
	AutoCreateUsers *bool `json:"auto_create_users"`
	LinkByEmail     bool  `json:"link_by_email"`

	Endpoints Endpoints `json:"endpoints"`

	CreatedBy *string   `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at,omitzero"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`

	// Sealed secrets as stored (database providers), opened by
	// ProviderRepository.Unseal only when a client is built.
	clientSecretEnc, spKeyEnc []byte
}

// Endpoints are the provider's URLs on this instance: what the IdP is given,
// and where the login button points.
type Endpoints struct {
	LoginURL    string `json:"login_url"`                 // relative; start a login here
	RedirectURI string `json:"redirect_uri,omitempty"`    // OIDC callback
	ACSURL      string `json:"acs_url,omitempty"`         // SAML assertion consumer service (HTTP-POST)
	SLOURL      string `json:"slo_url,omitempty"`         // SAML Single Logout (HTTP-Redirect + HTTP-POST)
	MetadataURL string `json:"sp_metadata_url,omitempty"` // SAML SP metadata
	SPEntityID  string `json:"sp_entity_id,omitempty"`    // SAML SP entity id (audience)
}

// Env reports whether the provider comes from the environment.
func (p Provider) Env() bool { return p.Source == SourceEnvironment }

// BasePath is the path its routes live under: /api/v1/auth/oidc for the
// environment OIDC provider, /api/v1/auth/oidc/{slug} for a database one.
// Per-login cookies are scoped to it.
func (p Provider) BasePath() string {
	if p.Env() {
		return authBase + p.Kind
	}
	return authBase + p.Kind + "/" + p.Slug
}

// databaseID is the provider_id stored on identities and mappings: the uuid of
// a database provider, nil for an environment one.
func (p Provider) databaseID() *string {
	if p.Env() || p.ID == "" {
		return nil
	}
	return &p.ID
}

// setEndpoints derives a database provider's URLs from PUBLIC_URL.
func (p *Provider) setEndpoints(publicURL string) {
	base := p.BasePath()
	p.Endpoints = Endpoints{LoginURL: base + "/login"}
	switch p.Kind {
	case ProviderOIDC:
		p.Endpoints.RedirectURI = publicURL + base + "/callback"
	case ProviderSAML:
		p.Endpoints.ACSURL = publicURL + base + "/acs"
		p.Endpoints.SLOURL = publicURL + base + "/slo"
		p.Endpoints.MetadataURL = publicURL + base + "/metadata"
		p.Endpoints.SPEntityID = p.EntityID
		if p.Endpoints.SPEntityID == "" {
			p.Endpoints.SPEntityID = p.Endpoints.MetadataURL
		}
	}
}

// EnvProviders are the providers configured by environment: OIDC_* and
// SAML_*, one each at most, at their original routes.
func EnvProviders(cfg config.Config) []Provider {
	var out []Provider
	if o := cfg.OIDC; o.Enabled {
		out = append(out, Provider{
			ID: ProviderOIDC, Slug: ProviderOIDC, Kind: ProviderOIDC, Name: o.ProviderName,
			Source: SourceEnvironment, Enabled: true,
			Issuer: o.Issuer, ClientID: o.ClientID, ClientSecret: o.ClientSecret, HasClientSecret: o.ClientSecret != "",
			Scopes: o.Scopes, GroupsClaim: o.GroupsClaim, TrustUnverifiedEmail: o.TrustUnverifiedEmail,
			LinkByEmail: true,
			Endpoints: Endpoints{
				LoginURL:    authBase + "oidc/login",
				RedirectURI: o.RedirectURL,
			},
		})
	}
	if s := cfg.SAML; s.Enabled {
		out = append(out, Provider{
			ID: ProviderSAML, Slug: ProviderSAML, Kind: ProviderSAML, Name: s.ProviderName,
			Source: SourceEnvironment, Enabled: true,
			IDPMetadataURL: s.IDPMetadataURL, IDPMetadata: s.IDPMetadata, EntityID: s.EntityID,
			EmailAttribute: s.EmailAttribute, GroupsAttributes: s.GroupsAttributes,
			AllowIDPInitiated: s.AllowIDPInitiated, SignRequests: s.SignRequests,
			SPCert: s.SPCert, SPKey: s.SPKey, HasSPKey: s.SPKey != "",
			LinkByEmail: s.LinkByEmail,
			Endpoints: Endpoints{
				LoginURL:    authBase + "saml/login",
				ACSURL:      cfg.PublicURL + authBase + "saml/acs",
				SLOURL:      cfg.PublicURL + authBase + "saml/slo",
				MetadataURL: cfg.PublicURL + authBase + "saml/metadata",
				SPEntityID:  s.EntityID,
			},
		})
	}
	return out
}

// reservedSlugs are path segments of the environment providers' routes and
// their own slugs: /auth/oidc/{slug}/… must never shadow /auth/oidc/login.
var reservedSlugs = []string{"login", "callback", "metadata", "acs", "slo", ProviderOIDC, ProviderSAML}

var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$`)

// ReservedSlug reports whether slug can only name an environment provider.
func ReservedSlug(slug string) bool { return slices.Contains(reservedSlugs, slug) }

// ProviderInput is what an admin sends to create or update a provider, or to
// test a draft. Omitted secrets keep the stored ones on update.
type ProviderInput struct {
	// ID, on a draft test only, merges the draft with that saved provider (so
	// its stored secrets are used).
	ID        string `json:"id"`
	Slug      string `json:"slug"`
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Enabled   *bool  `json:"enabled"` // default true
	SortOrder int    `json:"sort_order"`

	Issuer               string   `json:"issuer"`
	ClientID             string   `json:"client_id"`
	ClientSecret         string   `json:"client_secret"`
	Scopes               []string `json:"scopes"`
	GroupsClaim          string   `json:"groups_claim"`
	TrustUnverifiedEmail bool     `json:"trust_unverified_email"`

	IDPMetadataURL    string   `json:"idp_metadata_url"`
	IDPMetadata       string   `json:"idp_metadata"`
	EntityID          string   `json:"entity_id"`
	EmailAttribute    string   `json:"email_attribute"`
	GroupsAttributes  []string `json:"groups_attributes"`
	AllowIDPInitiated bool     `json:"allow_idp_initiated"`
	SignRequests      *bool    `json:"sign_requests"` // default true
	SPCert            string   `json:"sp_cert"`
	SPKey             string   `json:"sp_key"`

	AutoCreateUsers *bool `json:"auto_create_users"`
	LinkByEmail     *bool `json:"link_by_email"` // default true
}

// Rules are the instance facts provider validation depends on.
type Rules struct {
	PublicURL string // required: every database provider's URLs are built from it
	// AllowHTTP admits http:// issuer and metadata URLs (outside production).
	AllowHTTP bool
	// CanSeal: INTEGRATION_SECRET_KEY is configured, so secrets can be stored.
	CanSeal bool
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrInvalidProvider}, args...)...)
}

// Apply validates the input and returns the provider it describes. existing
// is the stored provider on update (nil on create): its slug and kind cannot
// change, and its secrets are kept when the input omits them.
func (in ProviderInput) Apply(existing *Provider, rules Rules) (Provider, error) {
	var p Provider
	if existing != nil {
		p = *existing
		if in.Slug != "" && in.Slug != existing.Slug {
			return Provider{}, invalid("slug cannot be changed (the IdP registration holds the URLs built from it)")
		}
		if in.Kind != "" && in.Kind != existing.Kind {
			return Provider{}, invalid("kind cannot be changed")
		}
	} else {
		p = Provider{Source: SourceDatabase, Slug: strings.TrimSpace(in.Slug), Kind: in.Kind}
		if !slugPattern.MatchString(p.Slug) {
			return Provider{}, invalid("slug must be 1-40 lower-case letters, digits or dashes, not starting or ending with a dash")
		}
		if ReservedSlug(p.Slug) {
			return Provider{}, invalid("slug %q is reserved", p.Slug)
		}
		if p.Kind != ProviderOIDC && p.Kind != ProviderSAML {
			return Provider{}, invalid("kind must be oidc or saml")
		}
	}
	if rules.PublicURL == "" {
		return Provider{}, invalid("PUBLIC_URL is not set — the provider's redirect/ACS URLs are built from it")
	}
	if !rules.CanSeal {
		return Provider{}, invalid("INTEGRATION_SECRET_KEY is not set — provider secrets cannot be stored")
	}

	p.Name = strings.TrimSpace(in.Name)
	if p.Name == "" || len(p.Name) > 80 {
		return Provider{}, invalid("name (the login button label) is required, at most 80 characters")
	}
	p.Enabled = in.Enabled == nil || *in.Enabled
	p.SortOrder = in.SortOrder
	p.AutoCreateUsers = in.AutoCreateUsers
	p.LinkByEmail = in.LinkByEmail == nil || *in.LinkByEmail

	// The other kind's fields are cleared, never stored.
	p.Issuer, p.ClientID, p.Scopes, p.GroupsClaim, p.TrustUnverifiedEmail = "", "", nil, "", false
	p.IDPMetadataURL, p.IDPMetadata, p.EntityID, p.EmailAttribute = "", "", "", ""
	p.GroupsAttributes, p.AllowIDPInitiated, p.SignRequests = nil, false, false
	p.ClientSecret, p.SPKey = "", ""

	var err error
	switch p.Kind {
	case ProviderOIDC:
		err = in.applyOIDC(&p, existing, rules)
	case ProviderSAML:
		err = in.applySAML(&p, rules)
	}
	if err != nil {
		return Provider{}, err
	}
	p.setEndpoints(rules.PublicURL)
	return p, nil
}

func (in ProviderInput) applyOIDC(p *Provider, existing *Provider, rules Rules) error {
	// Kept exactly (only trimmed of blanks): it must equal the discovery
	// document's issuer, and some IdPs' (Auth0) end with a slash.
	p.Issuer = strings.TrimSpace(in.Issuer)
	if err := checkURL("issuer", p.Issuer, rules.AllowHTTP); err != nil {
		return err
	}
	p.ClientID = strings.TrimSpace(in.ClientID)
	if p.ClientID == "" {
		return invalid("client_id is required")
	}
	p.ClientSecret = in.ClientSecret
	if p.ClientSecret == "" {
		p.clientSecretEnc = nil
		if existing != nil {
			p.clientSecretEnc = existing.clientSecretEnc
		}
		if p.clientSecretEnc == nil {
			return invalid("client_secret is required")
		}
	}
	p.HasClientSecret = true
	p.Scopes = normalizeScopes(in.Scopes)
	p.GroupsClaim = strings.TrimSpace(in.GroupsClaim)
	p.TrustUnverifiedEmail = in.TrustUnverifiedEmail
	p.spKeyEnc, p.SPCert, p.HasSPKey = nil, "", false
	return nil
}

func (in ProviderInput) applySAML(p *Provider, rules Rules) error {
	p.IDPMetadataURL = strings.TrimSpace(in.IDPMetadataURL)
	p.IDPMetadata = strings.TrimSpace(in.IDPMetadata)
	switch {
	case p.IDPMetadata != "":
		if !strings.Contains(p.IDPMetadata, "EntityDescriptor") {
			return invalid("idp_metadata must be the IdP's metadata XML")
		}
	case p.IDPMetadataURL != "":
		if err := checkURL("idp_metadata_url", p.IDPMetadataURL, rules.AllowHTTP); err != nil {
			return err
		}
	default:
		return invalid("idp_metadata_url or idp_metadata is required")
	}
	if !rules.AllowHTTP && !strings.HasPrefix(rules.PublicURL, "https://") {
		return invalid("SAML in production requires an https:// PUBLIC_URL")
	}
	p.EntityID = strings.TrimSpace(in.EntityID)
	p.EmailAttribute = strings.TrimSpace(in.EmailAttribute)
	p.GroupsAttributes = nonEmpty(in.GroupsAttributes)
	p.AllowIDPInitiated = in.AllowIDPInitiated
	p.SignRequests = in.SignRequests == nil || *in.SignRequests
	p.clientSecretEnc, p.HasClientSecret = nil, false

	// Own SP key pair: a new cert + key, a new cert for the stored key, or
	// none (the shared generated key pair).
	cert, key := strings.TrimSpace(in.SPCert), strings.TrimSpace(in.SPKey)
	switch {
	case cert == "" && key != "":
		return invalid("sp_key needs its sp_cert")
	case cert == "":
		p.SPCert, p.spKeyEnc, p.HasSPKey = "", nil, false
	case key == "" && p.spKeyEnc == nil:
		return invalid("sp_cert needs its sp_key")
	case key == "":
		if cert != p.SPCert {
			return invalid("a new sp_cert needs its sp_key")
		}
	default:
		if err := checkKeyPair(cert, key); err != nil {
			return err
		}
		p.SPCert, p.SPKey, p.HasSPKey = cert, key, true
	}
	return nil
}

// checkURL requires an absolute https URL (http outside production).
func checkURL(field, raw string, allowHTTP bool) error {
	u, err := url.Parse(raw)
	if raw == "" || err != nil || u.Host == "" {
		return invalid("%s must be an absolute URL", field)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && allowHTTP:
	case u.Scheme == "http":
		return invalid("%s must use https in production", field)
	default:
		return invalid("%s must be an http(s) URL", field)
	}
	if err := netguard.CheckURL(raw); err != nil {
		return invalid("%s is not an allowed destination: %v", field, err)
	}
	return nil
}

// checkKeyPair accepts a PEM certificate + matching RSA private key (SAML
// encrypted assertions are key-transported with RSA-OAEP).
func checkKeyPair(certPEM, keyPEM string) error {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return invalid("sp_cert/sp_key: %v", err)
	}
	if _, ok := pair.PrivateKey.(*rsa.PrivateKey); !ok {
		return invalid("sp_key must be an RSA key")
	}
	return nil
}

// normalizeScopes trims, drops duplicates and makes sure openid is requested
// (no ID token without it); empty means "openid email profile".
func normalizeScopes(in []string) []string {
	var out []string
	for _, s := range in {
		for f := range strings.FieldsSeq(s) {
			if !slices.Contains(out, f) {
				out = append(out, f)
			}
		}
	}
	if len(out) == 0 {
		return []string{"openid", "email", "profile"}
	}
	if !slices.Contains(out, "openid") {
		out = append([]string{"openid"}, out...)
	}
	return out
}

func nonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}
