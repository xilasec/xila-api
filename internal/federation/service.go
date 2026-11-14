package federation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/xilasec/xila-api/internal/netguard"
	"github.com/xilasec/xila-api/internal/user"
)

// Exchange failures. Each is a refused identity token (401): the reason is
// logged and reported, but none says which binding came close.
var (
	ErrUnknownIssuer    = errors.New("the token's issuer is not trusted")
	ErrInvalidToken     = errors.New("the identity token is invalid")
	ErrNoBinding        = errors.New("no binding matches the token's claims")
	ErrAmbiguousBinding = errors.New("the token's claims match bindings to different service accounts or projects")
	ErrSuspended        = errors.New("the bound service account is suspended")
	// ErrIssuerUnavailable: discovery or the JWKS couldn't be fetched (503).
	ErrIssuerUnavailable = errors.New("the issuer's discovery document could not be fetched")
)

// Store is the persistence the exchange needs (Repository).
type Store interface {
	EnabledIssuerByURL(ctx context.Context, url string) (Issuer, error)
	EnabledBindings(ctx context.Context, issuerID string) ([]Binding, error)
}

// Accounts loads the bound service account's user row (user.Repository).
type Accounts interface {
	GetByID(ctx context.Context, id string) (user.User, error)
}

// Minter signs the Xila session (auth.Service).
type Minter interface {
	ServiceAccountToken(u user.User, projectID string, ttl time.Duration) (string, error)
}

// Session is the result of a successful exchange.
type Session struct {
	AccessToken      string
	ExpiresIn        time.Duration
	ServiceAccountID string
	BindingID        string
}

// Service exchanges verified identity tokens for Xila sessions.
type Service struct {
	store    Store
	accounts Accounts
	minter   Minter
	ttl      time.Duration
	client   *http.Client

	mu    sync.Mutex
	cache map[string]cachedVerifier // by issuer id
}

type cachedVerifier struct {
	version  time.Time // issuer updated_at: an edit rebuilds it
	verifier *oidc.IDTokenVerifier
}

// NewService constructs a Service. ttl is the session lifetime (≤ 1h, config
// validated). Discovery and JWKS fetches go through netguard.
func NewService(store Store, accounts Accounts, minter Minter, ttl time.Duration) *Service {
	return &Service{
		store: store, accounts: accounts, minter: minter, ttl: ttl,
		client: netguard.NewClient(30 * time.Second),
		cache:  map[string]cachedVerifier{},
	}
}

// Exchange verifies an identity token — signature against the issuer's JWKS,
// iss, aud, exp, nbf — finds the binding its claims satisfy and mints a
// session for the bound service account.
func (s *Service) Exchange(ctx context.Context, rawToken string) (Session, error) {
	iss, err := unverifiedIssuer(rawToken)
	if err != nil {
		return Session{}, ErrInvalidToken
	}
	issuer, err := s.store.EnabledIssuerByURL(ctx, iss)
	if errors.Is(err, ErrNotFound) {
		return Session{}, ErrUnknownIssuer
	}
	if err != nil {
		return Session{}, err
	}
	verifier, err := s.verifier(ctx, issuer)
	if err != nil {
		return Session{}, err
	}
	tok, err := verifier.Verify(ctx, rawToken)
	if err != nil {
		return Session{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}
	var claims map[string]any
	if err := tok.Claims(&claims); err != nil {
		return Session{}, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	bindings, err := s.store.EnabledBindings(ctx, issuer.ID)
	if err != nil {
		return Session{}, err
	}
	b, err := pick(bindings, claims)
	if err != nil {
		return Session{}, err
	}
	u, err := s.accounts.GetByID(ctx, b.ServiceAccountID)
	if err != nil {
		return Session{}, err
	}
	if u.Disabled() {
		return Session{}, ErrSuspended
	}
	project := ""
	if b.ProjectID != nil {
		project = *b.ProjectID
	}
	token, err := s.minter.ServiceAccountToken(u, project, s.ttl)
	if err != nil {
		return Session{}, err
	}
	return Session{AccessToken: token, ExpiresIn: s.ttl, ServiceAccountID: u.ID, BindingID: b.ID}, nil
}

// pick returns the (oldest) binding the claims satisfy. Matches that disagree
// on the service account or project are refused rather than resolved by order:
// which identity a pipeline gets must not hinge on which rule was made first.
func pick(bindings []Binding, claims map[string]any) (Binding, error) {
	var found *Binding
	for i := range bindings {
		b := &bindings[i]
		if !matches(b.Conditions, claims) {
			continue
		}
		if found == nil {
			found = b
			continue
		}
		if found.ServiceAccountID != b.ServiceAccountID || !sameProject(found.ProjectID, b.ProjectID) {
			return Binding{}, ErrAmbiguousBinding
		}
	}
	if found == nil {
		return Binding{}, ErrNoBinding
	}
	return *found, nil
}

func sameProject(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// verifier returns the issuer's cached verifier, building it (discovery, which
// also locates the JWKS) on first use and after an edit. go-oidc's key set
// refetches the JWKS when a token names an unknown key, so key rotation needs
// no rebuild.
func (s *Service) verifier(ctx context.Context, i Issuer) (*oidc.IDTokenVerifier, error) {
	s.mu.Lock()
	c, ok := s.cache[i.ID]
	s.mu.Unlock()
	if ok && c.version.Equal(i.UpdatedAt) {
		return c.verifier, nil
	}
	v, err := s.build(ctx, i)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.cache[i.ID] = cachedVerifier{version: i.UpdatedAt, verifier: v}
	s.mu.Unlock()
	return v, nil
}

func (s *Service) build(ctx context.Context, i Issuer) (*oidc.IDTokenVerifier, error) {
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, s.client), i.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrIssuerUnavailable, i.IssuerURL, err)
	}
	// ClientID is the expected audience; go-oidc checks iss, aud, exp and nbf.
	return provider.Verifier(&oidc.Config{ClientID: i.Audience}), nil
}

// Test runs discovery for an issuer from scratch (nothing cached), for the
// admin page's "test" button.
func (s *Service) Test(ctx context.Context, i Issuer) error {
	_, err := s.build(ctx, i)
	return err
}

// unverifiedIssuer reads the iss claim to choose the issuer whose keys then
// verify the token; nothing else in the payload is trusted before that.
func unverifiedIssuer(raw string) (string, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", errors.New("not a compact JWS")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &c); err != nil || c.Iss == "" {
		return "", errors.New("no iss claim")
	}
	return c.Iss, nil
}
