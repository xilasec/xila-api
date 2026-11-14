package database_test

import (
	"context"
	"io"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/database"
)

// lateDatabase returns a DSN for a port that refuses connections until delay
// has passed, then proxies to the real test database — Postgres still booting.
func lateDatabase(t *testing.T, delay time.Duration) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set TEST_DATABASE_URL to run database integration tests")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	target := u.Host

	// Reserve a free port, then free it so connections are refused for now.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		l, err := net.Listen("tcp", addr)
		if err != nil {
			return
		}
		go func() { <-ctx.Done(); l.Close() }()
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				up, err := net.Dial("tcp", target)
				if err != nil {
					return
				}
				defer up.Close()
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	u.Host = addr
	return u.String()
}

// The API waits for a database that is still starting instead of exiting (which
// on Kubernetes means a crash loop with growing back-off on every fresh install).
func TestConnectWaitsForDatabaseToStart(t *testing.T) {
	dsn := lateDatabase(t, 1500*time.Millisecond)

	if _, err := database.Connect(context.Background(), dsn, database.PoolConfig{}); err == nil {
		t.Fatal("without StartupWait, connecting before the database is up succeeded")
	}

	start := time.Now()
	pool, err := database.Connect(context.Background(), dsn, database.PoolConfig{StartupWait: 20 * time.Second})
	if err != nil {
		t.Fatalf("connect with StartupWait: %v", err)
	}
	defer pool.Close()
	if waited := time.Since(start); waited > 10*time.Second {
		t.Errorf("took %v to notice the database was up", waited)
	}
}

// It still gives up: a database that never comes up is an error after the wait.
func TestConnectGivesUpAfterStartupWait(t *testing.T) {
	dsn := lateDatabase(t, time.Hour)
	start := time.Now()
	if _, err := database.Connect(context.Background(), dsn, database.PoolConfig{StartupWait: 1200 * time.Millisecond}); err == nil {
		t.Fatal("connect to a database that never started succeeded")
	}
	if waited := time.Since(start); waited < time.Second || waited > 8*time.Second {
		t.Errorf("gave up after %v, want about the 1.2s StartupWait", waited)
	}
}
