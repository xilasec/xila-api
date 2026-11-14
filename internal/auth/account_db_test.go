package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/user"
)

type mail struct{ to, body string }

type fakeMailer chan mail

func (fakeMailer) SMTPConfigured() bool { return true }
func (m fakeMailer) SendText(_ context.Context, to, _, body string) error {
	m <- mail{to, body}
	return nil
}

// Self-service reset mails a link only to an active account that has a
// password; SSO-only and unknown addresses get nothing (and the caller can't
// tell the difference).
func TestRequestResetMailsOnlyPasswordAccounts(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	users := user.NewRepository(pool)
	svc := auth.NewService(users, config.JWT{Secret: "s", TTL: time.Hour}, true)
	mails := make(fakeMailer, 4)
	svc.EnableResetMail(mails, "https://xila.example.com/")

	hash, _ := bcrypt.GenerateFromPassword([]byte("supersecret"), bcrypt.MinCost)
	if _, err := users.Create(ctx, "owner@xila.io", string(hash)); err != nil {
		t.Fatal(err)
	}
	bob, err := users.Create(ctx, "bob@xila.io", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := users.Create(ctx, "sso-only@xila.io", ""); err != nil {
		t.Fatal(err)
	}

	for _, email := range []string{"nobody@xila.io", "sso-only@xila.io"} {
		svc.RequestReset(ctx, email)
	}
	svc.RequestReset(ctx, " Bob@Xila.io ")
	var m mail
	select {
	case m = <-mails:
	case <-time.After(5 * time.Second):
		t.Fatal("no reset mail for an active password account")
	}
	if m.to != "bob@xila.io" {
		t.Fatalf("mail went to %q (unknown/SSO-only addresses must get none)", m.to)
	}
	i := strings.Index(m.body, "https://xila.example.com/reset-password#token=")
	if i < 0 {
		t.Fatalf("mail has no reset link: %s", m.body)
	}
	token := strings.Fields(m.body[i+len("https://xila.example.com/reset-password#token="):])[0]

	if _, u, err := svc.ConfirmReset(ctx, token, "brandnewpass"); err != nil || u.ID != bob.ID {
		t.Fatalf("confirm = %v, %v", u.ID, err)
	}
	if _, _, err := svc.ConfirmReset(ctx, token, "again-and-again"); !errors.Is(err, user.ErrResetInvalid) {
		t.Errorf("second use = %v, want ErrResetInvalid", err)
	}

	// A deactivated account's outstanding link dies with the deactivation.
	svc.RequestReset(ctx, "bob@xila.io")
	m = <-mails
	i = strings.Index(m.body, "#token=")
	token = strings.Fields(m.body[i+len("#token="):])[0]
	if _, err := users.SetDisabled(ctx, bob.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.ConfirmReset(ctx, token, "brandnewpass2"); !errors.Is(err, user.ErrResetInvalid) {
		t.Errorf("reset of a deactivated account = %v, want ErrResetInvalid", err)
	}
	select {
	case m := <-mails:
		t.Errorf("unexpected extra mail to %s", m.to)
	case <-time.After(100 * time.Millisecond):
	}
}
