package secretbox_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/secretbox"
)

func keyA() []byte { return bytes.Repeat([]byte{0xA}, 32) }
func keyB() []byte { return bytes.Repeat([]byte{0xB}, 32) }

func TestRekeyMovesRowsFromPreviousToPrimary(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()

	ringA, err := secretbox.NewKeyring(keyA(), nil)
	if err != nil {
		t.Fatal(err)
	}

	// --- seed one row per registry entry, sealed with key A ---

	// issue_trackers.token_enc: AAD = project_id.
	project1 := mustProject(t, pool, "p1")
	issueToken, err := ringA.Seal("gh_token", project1)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, `INSERT INTO issue_trackers (project_id, kind, base_url, target, token_enc)
		VALUES ($1, 'github', 'https://github.com', 'org/repo', $2)`, project1, issueToken)

	// connectors.token_enc: AAD = project_id. A second row, on another
	// project, is deliberately garbage: no configured key will ever open it.
	project2 := mustProject(t, pool, "p2")
	connToken, err := ringA.Seal("dt_token", project2)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, `INSERT INTO connectors (project_id, kind, base_url, remote_project, token_enc)
		VALUES ($1, 'dependency-track', 'https://dt.test', '1', $2)`, project2, connToken)
	project3 := mustProject(t, pool, "p3")
	garbage := []byte("not a valid sealed value, ever")
	mustExec(t, pool, `INSERT INTO connectors (project_id, kind, base_url, remote_project, token_enc)
		VALUES ($1, 'dependency-track', 'https://dt.test', '2', $2)`, project3, garbage)

	// notification_channels.{signing_secret,url_enc}: AAD = the row's own id,
	// so the id is generated client-side before sealing.
	channelID := uuid.NewString()
	signingSecret, err := ringA.Seal("whsec", channelID)
	if err != nil {
		t.Fatal(err)
	}
	urlSecret, err := ringA.Seal("https://hooks.example/x", channelID)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, `INSERT INTO notification_channels (id, name, type, url, signing_secret, url_enc)
		VALUES ($1, 'c', 'webhook', 'https://hooks.example', $2, $3)`, channelID, signingSecret, urlSecret)

	// users.mfa_secret_enc: AAD = "mfa:" + user id.
	userID := mustUser(t, pool, "alice@xila.io")
	mfaSecret, err := ringA.Seal("totp-secret", "mfa:"+userID)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, `UPDATE users SET mfa_secret_enc = $2, mfa_enabled_at = now() WHERE id = $1`, userID, mfaSecret)

	// saml_sp_keys.key_enc: AAD = the fixed constant "saml-sp-key".
	spKey, err := ringA.Seal("-----BEGIN KEY-----", "saml-sp-key")
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, `INSERT INTO saml_sp_keys (id, cert_pem, key_enc) VALUES (1, 'cert', $1)`, spKey)

	// sso_providers.{client_secret_enc,sp_key_enc}: AAD = "sso-provider:" + id + ":" + column.
	providerID := uuid.NewString()
	clientSecret, err := ringA.Seal("oidc-secret", "sso-provider:"+providerID+":client_secret")
	if err != nil {
		t.Fatal(err)
	}
	providerSPKey, err := ringA.Seal("-----BEGIN SP KEY-----", "sso-provider:"+providerID+":sp_key")
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, pool, `INSERT INTO sso_providers (id, slug, kind, name, issuer, client_id, client_secret_enc, sp_cert_pem, sp_key_enc)
		VALUES ($1, 'okta', 'oidc', 'Okta', 'https://idp.test', 'cid', $2, 'sp-cert', $3)`, providerID, clientSecret, providerSPKey)

	// --- rotate: key A becomes previous, key B becomes primary ---
	ringB, err := secretbox.NewKeyring(keyB(), [][]byte{keyA()})
	if err != nil {
		t.Fatal(err)
	}

	statuses, err := secretbox.Rekey(ctx, pool, ringB)
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}
	byCol := indexStatuses(statuses)

	want := []string{
		"issue_trackers.token_enc", "connectors.token_enc",
		"notification_channels.signing_secret", "notification_channels.url_enc",
		"users.mfa_secret_enc", "saml_sp_keys.key_enc",
		"sso_providers.client_secret_enc", "sso_providers.sp_key_enc",
	}
	for _, key := range want {
		st, ok := byCol[key]
		if !ok {
			t.Fatalf("Rekey did not report a status for %s", key)
		}
		if key == "connectors.token_enc" {
			continue // asserted separately below (two rows: one previous, one unreadable)
		}
		if st.Previous != 1 || st.Primary != 0 || st.Unreadable != 0 {
			t.Errorf("%s: Rekey pass status = %+v, want exactly 1 previous row", key, st)
		}
	}
	conn := byCol["connectors.token_enc"]
	if conn.Total != 2 || conn.Previous != 1 || conn.Unreadable != 1 || conn.Primary != 0 {
		t.Fatalf("connectors.token_enc: Rekey pass status = %+v, want total 2 (1 previous, 1 unreadable)", conn)
	}

	// The garbled row must be left exactly as it was — counted, never rewritten.
	var stillGarbled []byte
	if err := pool.QueryRow(ctx, `SELECT token_enc FROM connectors WHERE project_id = $1`, project3).Scan(&stillGarbled); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stillGarbled, garbage) {
		t.Error("an unreadable row was rewritten by Rekey")
	}

	// --- after Rekey, a read-only Status scan shows every column at primary ---
	after, err := secretbox.Status(ctx, pool, ringB)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	afterByCol := indexStatuses(after)
	for _, key := range want {
		if key == "connectors.token_enc" {
			continue
		}
		st := afterByCol[key]
		if st.Primary != 1 || st.Previous != 0 {
			t.Errorf("%s: post-rekey status = %+v, want 1 primary, 0 previous", key, st)
		}
	}
	conn2 := afterByCol["connectors.token_enc"]
	if conn2.Primary != 1 || conn2.Previous != 0 || conn2.Unreadable != 1 {
		t.Errorf("connectors.token_enc: post-rekey status = %+v, want 1 primary, 0 previous, 1 unreadable", conn2)
	}

	// --- every row now opens with key B alone (key A fully removed) ---
	bOnly, err := secretbox.NewKeyring(keyB(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if plain, err := bOnly.Open(issueToken, project1); err == nil {
		t.Errorf("issue_trackers.token_enc still opens with the pre-rekey ciphertext (%q) — the row wasn't actually re-sealed", plain)
	}
	var reRead []byte
	if err := pool.QueryRow(ctx, `SELECT token_enc FROM issue_trackers WHERE project_id = $1`, project1).Scan(&reRead); err != nil {
		t.Fatal(err)
	}
	if plain, err := bOnly.Open(reRead, project1); err != nil || plain != "gh_token" {
		t.Errorf("issue_trackers.token_enc after rekey: Open with key B alone = %q, %v", plain, err)
	}
}

func indexStatuses(statuses []secretbox.ColumnStatus) map[string]secretbox.ColumnStatus {
	m := make(map[string]secretbox.ColumnStatus, len(statuses))
	for _, s := range statuses {
		m[s.Table+"."+s.Column] = s
	}
	return m
}

func mustExec(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// mustProject creates a fresh org/team/project chain and returns the
// project id.
func mustProject(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(), `
		WITH o AS (INSERT INTO organizations (slug, name) VALUES ($1, $1) RETURNING id),
		     tm AS (INSERT INTO teams (org_id, slug, name) SELECT id, $1, $1 FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id, $1, $1 FROM tm RETURNING id`, slug).Scan(&id)
	if err != nil {
		t.Fatalf("create project %s: %v", slug, err)
	}
	return id
}

func mustUser(t *testing.T, pool *pgxpool.Pool, email string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id`,
		email).Scan(&id); err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}
	return id
}
