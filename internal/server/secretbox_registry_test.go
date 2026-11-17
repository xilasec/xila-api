package server

import (
	"context"
	"testing"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/secretbox"
)

// TestSealedColumnsRegistered guards secretbox.Registry (the Rekey/Status
// pass) against drift: every bytea column in the public schema whose name
// follows the sealed-value naming convention (`*_enc`, `sealed_*`, `*_sealed`)
// must be in the registry, or a rotation silently misses it.
//
// The heuristic is name-based and cannot catch a sealed column that doesn't
// follow the convention — notification_channels.signing_secret predates it
// and is sealed anyway; secretbox.Registry documents that exception. A new
// sealed column should follow the `*_enc` convention so this test catches a
// missing registry entry automatically; if it can't, add it to Registry by
// hand and extend this test's documented exceptions.
func TestSealedColumnsRegistered(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()

	rows, err := pool.Query(ctx, `
		SELECT table_name, column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND data_type = 'bytea'
		  AND (column_name LIKE '%\_enc' ESCAPE '\'
		    OR column_name LIKE 'sealed\_%' ESCAPE '\'
		    OR column_name LIKE '%\_sealed' ESCAPE '\')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	registered := make(map[string]bool, len(secretbox.Registry))
	for _, c := range secretbox.Registry {
		registered[c.Table+"."+c.Column] = true
	}

	var found int
	for rows.Next() {
		var table, column string
		if err := rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		found++
		if !registered[table+"."+column] {
			t.Errorf("%s.%s looks sealed (bytea, matches the *_enc/sealed_*/*_sealed convention) but is missing from secretbox.Registry", table, column)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if found == 0 {
		t.Fatal("no bytea column matched the sealed-value naming convention — the query itself is broken")
	}

	// And the converse: every registry entry must name a real bytea column,
	// catching a typo'd table or column name.
	for _, c := range secretbox.Registry {
		var dataType string
		err := pool.QueryRow(ctx, `SELECT data_type FROM information_schema.columns
			WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2`, c.Table, c.Column).Scan(&dataType)
		if err != nil {
			t.Errorf("registry entry %s.%s: %v", c.Table, c.Column, err)
			continue
		}
		if dataType != "bytea" {
			t.Errorf("registry entry %s.%s is %s, not bytea", c.Table, c.Column, dataType)
		}
	}
}
