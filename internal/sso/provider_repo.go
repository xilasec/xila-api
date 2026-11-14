package sso

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/secretbox"
)

// ProviderRepository stores the admin-managed providers. Secrets are sealed
// with INTEGRATION_SECRET_KEY, bound to the provider id and the column, so a
// ciphertext copied to another row or column does not decrypt.
type ProviderRepository struct {
	db        *pgxpool.Pool
	cipher    *secretbox.Cipher
	publicURL string
}

// NewProviderRepository constructs a ProviderRepository. publicURL
// (PUBLIC_URL) is what the providers' redirect/ACS/metadata URLs are built
// from; a nil cipher means providers can be listed but not stored.
func NewProviderRepository(db *pgxpool.Pool, cipher *secretbox.Cipher, publicURL string) *ProviderRepository {
	return &ProviderRepository{db: db, cipher: cipher, publicURL: publicURL}
}

// CanSeal reports whether secrets can be stored (INTEGRATION_SECRET_KEY set).
func (r *ProviderRepository) CanSeal() bool { return r.cipher != nil }

const providerColumns = `id, slug, kind, name, enabled, sort_order,
	issuer, client_id, client_secret_enc, scopes, groups_claim, trust_unverified_email,
	idp_metadata_url, idp_metadata, entity_id, email_attribute, groups_attributes,
	allow_idp_initiated, sign_requests, sp_cert_pem, sp_key_enc,
	auto_create_users, link_by_email, created_by, created_at, updated_at`

func (r *ProviderRepository) scan(row pgx.Row) (Provider, error) {
	p := Provider{Source: SourceDatabase}
	var createdBy *string
	err := row.Scan(&p.ID, &p.Slug, &p.Kind, &p.Name, &p.Enabled, &p.SortOrder,
		&p.Issuer, &p.ClientID, &p.clientSecretEnc, &p.Scopes, &p.GroupsClaim, &p.TrustUnverifiedEmail,
		&p.IDPMetadataURL, &p.IDPMetadata, &p.EntityID, &p.EmailAttribute, &p.GroupsAttributes,
		&p.AllowIDPInitiated, &p.SignRequests, &p.SPCert, &p.spKeyEnc,
		&p.AutoCreateUsers, &p.LinkByEmail, &createdBy, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Provider{}, ErrProviderNotFound
	}
	if err != nil {
		return Provider{}, fmt.Errorf("scan sso provider: %w", err)
	}
	p.CreatedBy = createdBy
	p.HasClientSecret = p.clientSecretEnc != nil
	p.HasSPKey = p.spKeyEnc != nil
	p.setEndpoints(r.publicURL)
	return p, nil
}

// List returns every stored provider, by sort order then name.
func (r *ProviderRepository) List(ctx context.Context) ([]Provider, error) {
	rows, err := r.db.Query(ctx, `SELECT `+providerColumns+` FROM sso_providers ORDER BY sort_order, name, slug`)
	if err != nil {
		return nil, fmt.Errorf("list sso providers: %w", err)
	}
	defer rows.Close()
	out := []Provider{}
	for rows.Next() {
		p, err := r.scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Get returns one provider by id.
func (r *ProviderRepository) Get(ctx context.Context, id string) (Provider, error) {
	if _, err := uuid.Parse(id); err != nil {
		return Provider{}, ErrProviderNotFound
	}
	return r.scan(r.db.QueryRow(ctx, `SELECT `+providerColumns+` FROM sso_providers WHERE id = $1`, id))
}

// GetBySlug returns one provider by slug — what every login request reads, so
// a change made on any replica applies on the next request.
func (r *ProviderRepository) GetBySlug(ctx context.Context, slug string) (Provider, error) {
	return r.scan(r.db.QueryRow(ctx, `SELECT `+providerColumns+` FROM sso_providers WHERE slug = $1`, slug))
}

func secretAAD(id, column string) string { return "sso-provider:" + id + ":" + column }

// seal encrypts the plaintext secrets the provider carries (new ones); absent
// ones keep their stored ciphertext.
func (r *ProviderRepository) seal(p *Provider) error {
	if p.ClientSecret != "" {
		enc, err := r.cipher.Seal(p.ClientSecret, secretAAD(p.ID, "client_secret"))
		if err != nil {
			return err
		}
		p.clientSecretEnc = enc
	}
	if p.SPKey != "" {
		enc, err := r.cipher.Seal(p.SPKey, secretAAD(p.ID, "sp_key"))
		if err != nil {
			return err
		}
		p.spKeyEnc = enc
	}
	return nil
}

// Unseal decrypts a stored provider's secrets into ClientSecret / SPKey, for
// building its client; a plaintext one already set (a draft being tested)
// wins. Environment providers carry theirs in clear already.
func (r *ProviderRepository) Unseal(p *Provider) error {
	if p.clientSecretEnc != nil && p.ClientSecret == "" {
		s, err := r.cipher.Open(p.clientSecretEnc, secretAAD(p.ID, "client_secret"))
		if err != nil {
			return fmt.Errorf("client secret: %w", err)
		}
		p.ClientSecret = s
	}
	if p.spKeyEnc != nil && p.SPKey == "" {
		s, err := r.cipher.Open(p.spKeyEnc, secretAAD(p.ID, "sp_key"))
		if err != nil {
			return fmt.Errorf("sp key: %w", err)
		}
		p.SPKey = s
	}
	return nil
}

func mapWriteErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return ErrSlugTaken
		case "23514":
			return fmt.Errorf("%w: %s", ErrInvalidProvider, pgErr.ConstraintName)
		}
	}
	return err
}

// Create stores a validated provider (ProviderInput.Apply), sealing its
// secrets. createdBy may be empty (API token without a user).
func (r *ProviderRepository) Create(ctx context.Context, p Provider, createdBy string) (Provider, error) {
	p.ID = uuid.NewString()
	if err := r.seal(&p); err != nil {
		return Provider{}, err
	}
	var by *string
	if createdBy != "" {
		by = &createdBy
	}
	_, err := r.db.Exec(ctx, `INSERT INTO sso_providers (id, slug, kind, name, enabled, sort_order,
		issuer, client_id, client_secret_enc, scopes, groups_claim, trust_unverified_email,
		idp_metadata_url, idp_metadata, entity_id, email_attribute, groups_attributes,
		allow_idp_initiated, sign_requests, sp_cert_pem, sp_key_enc,
		auto_create_users, link_by_email, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)`,
		p.ID, p.Slug, p.Kind, p.Name, p.Enabled, p.SortOrder,
		p.Issuer, p.ClientID, p.clientSecretEnc, orEmpty(p.Scopes), p.GroupsClaim, p.TrustUnverifiedEmail,
		p.IDPMetadataURL, p.IDPMetadata, p.EntityID, p.EmailAttribute, orEmpty(p.GroupsAttributes),
		p.AllowIDPInitiated, p.SignRequests, p.SPCert, p.spKeyEnc,
		p.AutoCreateUsers, p.LinkByEmail, by)
	if err != nil {
		return Provider{}, fmt.Errorf("create sso provider: %w", mapWriteErr(err))
	}
	return r.Get(ctx, p.ID)
}

// Update stores a validated provider over its row. updated_at always moves
// forward: it is the version every replica compares its cached client to.
func (r *ProviderRepository) Update(ctx context.Context, p Provider) (Provider, error) {
	if err := r.seal(&p); err != nil {
		return Provider{}, err
	}
	tag, err := r.db.Exec(ctx, `UPDATE sso_providers SET name = $2, enabled = $3, sort_order = $4,
		issuer = $5, client_id = $6, client_secret_enc = $7, scopes = $8, groups_claim = $9, trust_unverified_email = $10,
		idp_metadata_url = $11, idp_metadata = $12, entity_id = $13, email_attribute = $14, groups_attributes = $15,
		allow_idp_initiated = $16, sign_requests = $17, sp_cert_pem = $18, sp_key_enc = $19,
		auto_create_users = $20, link_by_email = $21,
		updated_at = GREATEST(now(), updated_at + interval '1 microsecond')
		WHERE id = $1`,
		p.ID, p.Name, p.Enabled, p.SortOrder,
		p.Issuer, p.ClientID, p.clientSecretEnc, orEmpty(p.Scopes), p.GroupsClaim, p.TrustUnverifiedEmail,
		p.IDPMetadataURL, p.IDPMetadata, p.EntityID, p.EmailAttribute, orEmpty(p.GroupsAttributes),
		p.AllowIDPInitiated, p.SignRequests, p.SPCert, p.spKeyEnc,
		p.AutoCreateUsers, p.LinkByEmail)
	if err != nil {
		return Provider{}, fmt.Errorf("update sso provider: %w", mapWriteErr(err))
	}
	if tag.RowsAffected() == 0 {
		return Provider{}, ErrProviderNotFound
	}
	return r.Get(ctx, p.ID)
}

// Delete removes a provider and the group mappings scoped to it. Its users
// keep their accounts and identities (provider_id is cleared): they can still
// sign in with a password, or through another provider with the same issuer.
func (r *ProviderRepository) Delete(ctx context.Context, id string) error {
	if _, err := uuid.Parse(id); err != nil {
		return ErrProviderNotFound
	}
	tag, err := r.db.Exec(ctx, `DELETE FROM sso_providers WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete sso provider: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrProviderNotFound
	}
	return nil
}

// LinkedIdentities counts, per provider id, the identities that last signed in
// through it.
func (r *ProviderRepository) LinkedIdentities(ctx context.Context) (map[string]int, error) {
	rows, err := r.db.Query(ctx, `SELECT provider_id::text, count(*) FROM user_identities
		WHERE provider_id IS NOT NULL GROUP BY provider_id`)
	if err != nil {
		return nil, fmt.Errorf("count linked identities: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
