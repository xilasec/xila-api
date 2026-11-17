// Package ldap signs people in against an LDAP / Active Directory directory.
// It does only the directory protocol — find the account with a service
// account, bind as it with the password typed — and hands the verified
// identity to the shared SSO layer (internal/sso), which links it to a user,
// syncs group-mapped roles and refuses deactivated accounts, exactly as for
// OIDC and SAML.
package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/secretref"
	"github.com/xilasec/xila-api/internal/sso"
	"github.com/xilasec/xila-api/internal/user"
)

// Login links a verified directory identity to a user (sso.Service).
type Login interface {
	Login(ctx context.Context, p sso.Provider, a sso.Assertion) (user.User, error)
}

// Directory authenticates against the configured directory.
type Directory struct {
	cfg      config.LDAP
	password secretref.Value // the live LDAP_BIND_PASSWORD; nil = cfg.BindPassword
	login    Login
	tls      *tls.Config
	provider sso.Provider
	timeout  time.Duration
}

// New validates the TLS setup and returns the directory.
func New(cfg config.LDAP, login Login) (*Directory, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("ldap: LDAP_URL %q is not a URL", cfg.URL)
	}
	tc := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12}
	if cfg.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, errors.New("ldap: LDAP_CA_CERT holds no PEM certificate")
		}
		tc.RootCAs = pool
	}
	return &Directory{
		cfg: cfg, login: login, tls: tc, timeout: 10 * time.Second,
		provider: sso.Provider{
			ID: sso.ProviderLDAP, Slug: sso.ProviderLDAP, Kind: sso.ProviderLDAP, Name: "Directory (LDAP)",
			Source: sso.SourceEnvironment, Enabled: true, LinkByEmail: cfg.LinkByEmail,
		},
	}, nil
}

// WithBindPassword reads the service account's password per search instead
// of the startup value, so a rotated LDAP_BIND_PASSWORD applies at once.
func (d *Directory) WithBindPassword(v secretref.Value) *Directory {
	d.password = v
	return d
}

// Authenticate checks login/password against the directory and returns the
// linked user. Wrong credentials are auth.ErrInvalidCredentials; a directory
// account Xila won't admit fails with the SSO layer's error (no account,
// conflict, deactivated).
func (d *Directory) Authenticate(ctx context.Context, login, password string) (user.User, error) {
	login = strings.TrimSpace(login)
	// An empty password is an "unauthenticated bind": many servers answer it
	// with success. Never let it through.
	if login == "" || password == "" {
		return user.User{}, auth.ErrInvalidCredentials
	}
	conn, err := d.connect(ctx)
	if err != nil {
		return user.User{}, err
	}
	defer conn.Close()

	if d.cfg.BindDN != "" {
		pass := d.cfg.BindPassword
		if d.password != nil {
			pass = d.password.Get()
		}
		if err := conn.Bind(d.cfg.BindDN, pass); err != nil {
			return user.User{}, fmt.Errorf("ldap: service bind: %w", err)
		}
	}
	attrs := []string{"dn", d.cfg.EmailAttribute, d.cfg.GroupAttribute, "entryUUID", "objectGUID"}
	if d.cfg.UIDAttribute != "" {
		attrs = append(attrs, d.cfg.UIDAttribute)
	}
	filter := strings.ReplaceAll(d.cfg.UserFilter, "{login}", goldap.EscapeFilter(login))
	res, err := conn.Search(goldap.NewSearchRequest(d.cfg.BaseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		2, int(d.timeout.Seconds()), false, filter, attrs, nil))
	if err != nil && !goldap.IsErrorWithCode(err, goldap.LDAPResultSizeLimitExceeded) {
		return user.User{}, fmt.Errorf("ldap: search: %w", err)
	}
	if res == nil || len(res.Entries) != 1 {
		return user.User{}, auth.ErrInvalidCredentials // none, or ambiguous
	}
	entry := res.Entries[0]
	if err := conn.Bind(entry.DN, password); err != nil {
		if goldap.IsErrorWithCode(err, goldap.LDAPResultInvalidCredentials) {
			return user.User{}, auth.ErrInvalidCredentials
		}
		return user.User{}, fmt.Errorf("ldap: user bind: %w", err)
	}

	u, err := d.login.Login(ctx, d.provider, sso.Assertion{
		Issuer:     strings.ToLower(d.cfg.URL),
		Subject:    d.subject(entry),
		Email:      entry.GetAttributeValue(d.cfg.EmailAttribute),
		EmailTrust: sso.EmailVerified, // the organisation's own directory
		Groups:     groups(entry.GetAttributeValues(d.cfg.GroupAttribute)),
	})
	if err != nil && sso.FailureCode(err) == sso.FailureNoEmail {
		return user.User{}, fmt.Errorf("%w: the directory entry has no %s attribute", auth.ErrDirectoryRefused, d.cfg.EmailAttribute)
	}
	return u, err
}

func (d *Directory) connect(ctx context.Context) (*goldap.Conn, error) {
	dialer := &net.Dialer{Timeout: d.timeout}
	if dl, ok := ctx.Deadline(); ok {
		dialer.Deadline = dl
	}
	conn, err := goldap.DialURL(d.cfg.URL, goldap.DialWithDialer(dialer), goldap.DialWithTLSConfig(d.tls))
	if err != nil {
		return nil, fmt.Errorf("ldap: connect: %w", err)
	}
	conn.SetTimeout(d.timeout)
	if strings.HasPrefix(d.cfg.URL, "ldap://") && d.cfg.StartTLS {
		if err := conn.StartTLS(d.tls); err != nil {
			conn.Close()
			return nil, fmt.Errorf("ldap: starttls: %w", err)
		}
	}
	return conn, nil
}

// subject is the account's stable id: the configured attribute, else
// entryUUID (OpenLDAP) or objectGUID (Active Directory), else the DN — which
// changes when the account is moved or renamed, so the ids are preferred.
func (d *Directory) subject(e *goldap.Entry) string {
	for _, attr := range []string{d.cfg.UIDAttribute, "entryUUID", "objectGUID"} {
		if attr == "" {
			continue
		}
		if raw := e.GetRawAttributeValue(attr); len(raw) == 16 && strings.EqualFold(attr, "objectGUID") {
			return formatGUID(raw)
		}
		if v := e.GetAttributeValue(attr); v != "" {
			return v
		}
	}
	return strings.ToLower(e.DN)
}

// formatGUID renders an AD objectGUID (little-endian first three fields) in
// its canonical string form.
func formatGUID(b []byte) string {
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// groups offers each group both as its full DN and as its CN, so a mapping
// can name "CN=xila-admins,OU=Groups,DC=corp,DC=example" or just "xila-admins".
func groups(dns []string) []string {
	out := make([]string, 0, 2*len(dns))
	for _, g := range dns {
		out = append(out, g)
		if dn, err := goldap.ParseDN(g); err == nil && len(dn.RDNs) > 0 {
			for _, a := range dn.RDNs[0].Attributes {
				if strings.EqualFold(a.Type, "cn") {
					out = append(out, a.Value)
				}
			}
		}
	}
	return out
}
