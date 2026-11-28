package pkgmeta

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/netguard"
	"github.com/xilasec/xila-api/internal/secretbox"
)

// Auth types a private registry may use.
const (
	AuthNone   = "none"
	AuthBasic  = "basic"
	AuthBearer = "bearer"
)

// ErrRegistryNotFound is returned for an unknown private registry id.
var ErrRegistryNotFound = errors.New("registry not found")

// PrivateRegistry is one admin-configured package registry (M13 13.11), tried
// in sort order before the ecosystem's public one. An internal registry is the
// only kind an internal (first-party) component is ever looked up in; the
// others, and then the public registry, serve every other component.
// Credentials are write-only: the API reports only whether they're set.
type PrivateRegistry struct {
	ID          string    `json:"id"`
	Ecosystem   string    `json:"ecosystem"`
	URL         string    `json:"url"`
	AuthType    string    `json:"auth_type"`
	Username    string    `json:"username"`
	HasPassword bool      `json:"has_password"`
	HasToken    bool      `json:"has_token"`
	Internal    bool      `json:"internal"`
	SortOrder   int       `json:"sort_order"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// RegistryInput is a create or update request. On update a nil Password or
// Token keeps the stored one; "" clears it.
type RegistryInput struct {
	Ecosystem string  `json:"ecosystem"`
	URL       string  `json:"url"`
	AuthType  string  `json:"auth_type"`
	Username  string  `json:"username"`
	Password  *string `json:"password"`
	Token     *string `json:"token"`
	Internal  bool    `json:"internal"`
	SortOrder int     `json:"sort_order"`
}

// RegistryError is a request PrivateRegistries refuses (a 400).
type RegistryError struct{ msg string }

func (e *RegistryError) Error() string { return e.msg }

// PrivateRegistries stores the configured registries, sealing their
// credentials, and builds their clients for a sweep.
type PrivateRegistries struct {
	db   *pgxpool.Pool
	keys *secretbox.Keyring
	cfg  RegistryConfig
}

// NewPrivateRegistries constructs the store; cfg supplies the User-Agent,
// politeness rate and timeout every registry client uses.
func NewPrivateRegistries(db *pgxpool.Pool, keys *secretbox.Keyring, cfg RegistryConfig) *PrivateRegistries {
	return &PrivateRegistries{db: db, keys: keys, cfg: cfg}
}

// sealAAD binds a sealed credential to its row and purpose.
func sealAAD(id, what string) string { return "pkgmeta_registry:" + id + ":" + what }

const registryColumns = `id, ecosystem, url, auth_type, username, password_enc IS NOT NULL, token_enc IS NOT NULL,
	internal, sort_order, created_at, updated_at`

func scanRegistry(row pgx.Row) (PrivateRegistry, error) {
	var r PrivateRegistry
	err := row.Scan(&r.ID, &r.Ecosystem, &r.URL, &r.AuthType, &r.Username, &r.HasPassword, &r.HasToken,
		&r.Internal, &r.SortOrder, &r.CreatedAt, &r.UpdatedAt)
	return r, err
}

// List returns every registry, per ecosystem in the order they're tried.
func (p *PrivateRegistries) List(ctx context.Context) ([]PrivateRegistry, error) {
	rows, err := p.db.Query(ctx, `SELECT `+registryColumns+` FROM pkgmeta_registries ORDER BY ecosystem, sort_order, created_at`)
	if err != nil {
		return nil, fmt.Errorf("list registries: %w", err)
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (PrivateRegistry, error) { return scanRegistry(row) })
	if err != nil {
		return nil, fmt.Errorf("scan registry: %w", err)
	}
	return out, nil
}

func (p *PrivateRegistries) get(ctx context.Context, id string) (PrivateRegistry, error) {
	r, err := scanRegistry(p.db.QueryRow(ctx, `SELECT `+registryColumns+` FROM pkgmeta_registries WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return PrivateRegistry{}, ErrRegistryNotFound
	}
	if err != nil {
		return PrivateRegistry{}, fmt.Errorf("get registry: %w", err)
	}
	return r, nil
}

// validate checks a request against what will be stored: hasPassword and
// hasToken say whether a credential is set after it.
func (in *RegistryInput) validate(hasPassword, hasToken bool) error {
	in.Ecosystem = strings.ToLower(strings.TrimSpace(in.Ecosystem))
	in.URL = strings.TrimRight(strings.TrimSpace(in.URL), "/")
	in.Username = strings.TrimSpace(in.Username)
	if in.AuthType == "" {
		in.AuthType = AuthNone
	}
	switch {
	case !Supported(in.Ecosystem):
		return &RegistryError{"unsupported ecosystem " + in.Ecosystem}
	case netguard.CheckURL(in.URL) != nil:
		return &RegistryError{"url must be an http(s) URL outbound requests may reach"}
	case in.AuthType != AuthNone && in.AuthType != AuthBasic && in.AuthType != AuthBearer:
		return &RegistryError{"auth_type must be none, basic or bearer"}
	case in.AuthType == AuthBasic && (in.Username == "" || !hasPassword):
		return &RegistryError{"basic auth needs a username and a password"}
	case in.AuthType == AuthBearer && !hasToken:
		return &RegistryError{"bearer auth needs a token"}
	}
	return nil
}

// sealed returns the column value for a credential: nil to clear it.
func (p *PrivateRegistries) sealed(id, what string, v *string) ([]byte, error) {
	if v == nil || *v == "" {
		return nil, nil
	}
	return p.keys.Seal(*v, sealAAD(id, what))
}

// Create stores a new registry.
func (p *PrivateRegistries) Create(ctx context.Context, in RegistryInput, actor string) (PrivateRegistry, error) {
	if err := in.validate(in.Password != nil && *in.Password != "", in.Token != nil && *in.Token != ""); err != nil {
		return PrivateRegistry{}, err
	}
	id := uuid.NewString()
	pw, err := p.sealed(id, "password", in.Password)
	if err != nil {
		return PrivateRegistry{}, err
	}
	tok, err := p.sealed(id, "token", in.Token)
	if err != nil {
		return PrivateRegistry{}, err
	}
	if _, err := p.db.Exec(ctx, `
		INSERT INTO pkgmeta_registries (id, ecosystem, url, auth_type, username, password_enc, token_enc, internal, sort_order, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NULLIF($10, '')::uuid)`,
		id, in.Ecosystem, in.URL, in.AuthType, in.Username, pw, tok, in.Internal, in.SortOrder, actor); err != nil {
		return PrivateRegistry{}, fmt.Errorf("create registry: %w", err)
	}
	return p.get(ctx, id)
}

// Update replaces a registry's settings; credentials are kept unless given.
func (p *PrivateRegistries) Update(ctx context.Context, id string, in RegistryInput) (PrivateRegistry, error) {
	cur, err := p.get(ctx, id)
	if err != nil {
		return PrivateRegistry{}, err
	}
	hasPassword := cur.HasPassword
	if in.Password != nil {
		hasPassword = *in.Password != ""
	}
	hasToken := cur.HasToken
	if in.Token != nil {
		hasToken = *in.Token != ""
	}
	if err := in.validate(hasPassword, hasToken); err != nil {
		return PrivateRegistry{}, err
	}
	pw, err := p.sealed(id, "password", in.Password)
	if err != nil {
		return PrivateRegistry{}, err
	}
	tok, err := p.sealed(id, "token", in.Token)
	if err != nil {
		return PrivateRegistry{}, err
	}
	if _, err := p.db.Exec(ctx, `
		UPDATE pkgmeta_registries SET ecosystem = $2, url = $3, auth_type = $4, username = $5,
			password_enc = CASE WHEN $6 THEN $7 ELSE password_enc END,
			token_enc = CASE WHEN $8 THEN $9 ELSE token_enc END,
			internal = $10, sort_order = $11, updated_at = now()
		WHERE id = $1`,
		id, in.Ecosystem, in.URL, in.AuthType, in.Username, in.Password != nil, pw, in.Token != nil, tok,
		in.Internal, in.SortOrder); err != nil {
		return PrivateRegistry{}, fmt.Errorf("update registry: %w", err)
	}
	return p.get(ctx, id)
}

// Delete removes a registry.
func (p *PrivateRegistries) Delete(ctx context.Context, id string) error {
	tag, err := p.db.Exec(ctx, `DELETE FROM pkgmeta_registries WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete registry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRegistryNotFound
	}
	return nil
}

// configured is one private registry's client, for a sweep.
type configured struct {
	ecosystem string
	internal  bool
	reg       Registry
}

// load builds every registry's client, credentials opened, in the order they
// are tried. One whose credentials can't be opened is left out (and logged
// by the caller through the error), never tried without them.
func (p *PrivateRegistries) load(ctx context.Context) ([]configured, error) {
	rows, err := p.db.Query(ctx, `SELECT id, ecosystem, url, auth_type, username, password_enc, token_enc, internal
		FROM pkgmeta_registries ORDER BY ecosystem, sort_order, created_at`)
	if err != nil {
		return nil, fmt.Errorf("load registries: %w", err)
	}
	defer rows.Close()
	rps := p.cfg.RequestsPerSecond
	if rps <= 0 {
		rps = 5
	}
	timeout := p.cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	hc := netguard.NewClient(timeout)
	var out []configured
	var errs []error
	for rows.Next() {
		var (
			id, eco, base, authType, user string
			pwEnc, tokEnc                 []byte
			internal                      bool
		)
		if err := rows.Scan(&id, &eco, &base, &authType, &user, &pwEnc, &tokEnc, &internal); err != nil {
			return nil, fmt.Errorf("scan registry: %w", err)
		}
		auth, err := p.authFor(id, base, authType, user, pwEnc, tokEnc)
		if err != nil {
			errs = append(errs, fmt.Errorf("registry %s: %w", id, err))
			continue
		}
		g := &getter{hc: hc, ua: p.cfg.UserAgent, every: time.Second / time.Duration(rps), auth: auth}
		if reg := newRegistry(eco, base, g); reg != nil {
			out = append(out, configured{ecosystem: eco, internal: internal, reg: reg})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, errors.Join(errs...)
}

// authFor is the request signer for one registry: its credentials, on
// requests to its own host only.
func (p *PrivateRegistries) authFor(id, base, authType, user string, pwEnc, tokEnc []byte) (func(*http.Request), error) {
	if authType == AuthNone {
		return nil, nil
	}
	u, err := url.Parse(base)
	if err != nil {
		return nil, err
	}
	host := u.Host
	switch authType {
	case AuthBasic:
		pw, err := p.keys.Open(pwEnc, sealAAD(id, "password"))
		if err != nil {
			return nil, err
		}
		return func(r *http.Request) {
			if r.URL.Host == host {
				r.SetBasicAuth(user, pw)
			}
		}, nil
	case AuthBearer:
		tok, err := p.keys.Open(tokEnc, sealAAD(id, "token"))
		if err != nil {
			return nil, err
		}
		return func(r *http.Request) {
			if r.URL.Host == host {
				r.Header.Set("Authorization", "Bearer "+tok)
			}
		}, nil
	}
	return nil, fmt.Errorf("unknown auth type %q", authType)
}
