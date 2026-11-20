package reportschedule

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/evidence"
	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/report"
	"github.com/xilasec/xila-api/internal/user"
)

type fakeStore struct {
	status string
	errMsg string
	sent   int
}

func (f *fakeStore) ListByOwner(context.Context, string) ([]Schedule, error) { return nil, nil }
func (f *fakeStore) ListAll(context.Context) ([]Schedule, error)             { return nil, nil }
func (f *fakeStore) ListEnabled(context.Context) ([]Schedule, error)         { return nil, nil }
func (f *fakeStore) Get(context.Context, string) (Schedule, error)           { return Schedule{}, nil }
func (f *fakeStore) Create(context.Context, Schedule) (Schedule, error)      { return Schedule{}, nil }
func (f *fakeStore) Update(context.Context, Schedule) (Schedule, error)      { return Schedule{}, nil }
func (f *fakeStore) Delete(context.Context, string) error                    { return nil }
func (f *fakeStore) ListRuns(context.Context, string, int) ([]Run, error)    { return nil, nil }
func (f *fakeStore) RecordRun(_ context.Context, _, status, errMsg string, sent int) error {
	f.status, f.errMsg, f.sent = status, errMsg, sent
	return nil
}

type fakeReports struct{ fail bool }

func (f fakeReports) Project(ctx context.Context, projectID string, opts report.Options) (report.Report, error) {
	if f.fail {
		return report.Report{}, errors.New("boom")
	}
	return report.Report{Project: &project.Project{Slug: "demo"}}, nil
}
func (f fakeReports) Portfolio(ctx context.Context, pids []string, opts report.Options) (report.Report, error) {
	return report.Report{}, nil
}

type fakeEvidence struct{}

func (fakeEvidence) Build(ctx context.Context, projectID, framework string) (evidence.Report, error) {
	return evidence.Report{}, nil
}

type fakeTemplates struct{}

func (fakeTemplates) Get(ctx context.Context, id string) (report.Template, error) {
	return report.DefaultTemplate(), nil
}

type fakeMembership struct {
	admin    bool
	projects []string
}

func (f fakeMembership) AdminStatus(context.Context, string) (bool, bool, error) {
	return f.admin, false, nil
}
func (f fakeMembership) ProjectIDsForUser(context.Context, string) ([]string, error) {
	return f.projects, nil
}

type fakeUsers struct{ u user.User }

func (f fakeUsers) GetByID(context.Context, string) (user.User, error) { return f.u, nil }

type fakeChannels struct{}

func (fakeChannels) Get(context.Context, string) (notify.Channel, error) {
	return notify.Channel{}, nil
}

type fakeMailer struct {
	sent      [][]string
	sentCh    int
	failEmail bool
}

func (f *fakeMailer) SendAttachment(ctx context.Context, to []string, subject, body string, att notify.Attachment) error {
	if f.failEmail {
		return errors.New("smtp down")
	}
	f.sent = append(f.sent, to)
	return nil
}
func (f *fakeMailer) SendTo(ctx context.Context, ch notify.Channel, e notify.Event) error {
	f.sentCh++
	return nil
}

func newTestService(store Store, reports Reports, membership Membership, users Users, mail Mailer) *Service {
	return NewService(store, reports, fakeEvidence{}, fakeTemplates{}, membership, users, fakeChannels{}, mail, "https://xila.test")
}

func TestRunDeliversEmailOnSuccess(t *testing.T) {
	store := &fakeStore{}
	mail := &fakeMailer{}
	pid := "p1"
	svc := newTestService(store, fakeReports{}, fakeMembership{admin: true}, fakeUsers{}, mail)
	sch := Schedule{ID: "s1", OwnerID: "u1", Kind: KindProject, ProjectID: &pid, RecipientEmails: []string{"a@x.io"}}
	if err := svc.run(context.Background(), sch); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(mail.sent) != 1 {
		t.Fatalf("expected one email sent, got %d", len(mail.sent))
	}
	if store.status != "success" || store.sent != 1 {
		t.Fatalf("expected recorded success with 1 recipient, got status=%q sent=%d", store.status, store.sent)
	}
}

func TestRunFailsForDisabledOwner(t *testing.T) {
	store := &fakeStore{}
	mail := &fakeMailer{}
	pid := "p1"
	disabledUser := fakeUsers{u: user.User{DisabledAt: timePtr(nowForTest())}}
	svc := newTestService(store, fakeReports{}, fakeMembership{admin: true}, disabledUser, mail)
	sch := Schedule{ID: "s1", OwnerID: "u1", Kind: KindProject, ProjectID: &pid, RecipientEmails: []string{"a@x.io"}}
	err := svc.run(context.Background(), sch)
	if !errors.Is(err, ErrOwnerUnavailable) {
		t.Fatalf("expected ErrOwnerUnavailable, got %v", err)
	}
	if len(mail.sent) != 0 {
		t.Fatalf("expected no email sent for a deactivated owner")
	}
	if store.status != "failure" {
		t.Fatalf("expected recorded failure, got %q", store.status)
	}
}

func TestRunFailsForLostProjectAccess(t *testing.T) {
	store := &fakeStore{}
	mail := &fakeMailer{}
	pid := "p1"
	svc := newTestService(store, fakeReports{}, fakeMembership{admin: false, projects: []string{"other"}}, fakeUsers{}, mail)
	sch := Schedule{ID: "s1", OwnerID: "u1", Kind: KindProject, ProjectID: &pid, RecipientEmails: []string{"a@x.io"}}
	err := svc.run(context.Background(), sch)
	if !errors.Is(err, ErrOwnerUnavailable) {
		t.Fatalf("expected ErrOwnerUnavailable, got %v", err)
	}
	if len(mail.sent) != 0 {
		t.Fatalf("expected no email sent when the owner lost project access")
	}
}
func nowForTest() time.Time { return time.Now() }
func TestRunDeliversLinkToChannel(t *testing.T) {
	store := &fakeStore{}
	mail := &fakeMailer{}
	pid := "p1"
	svc := newTestService(store, fakeReports{}, fakeMembership{admin: true}, fakeUsers{}, mail)
	sch := Schedule{ID: "s1", OwnerID: "u1", Kind: KindProject, ProjectID: &pid, RecipientChannelIDs: []string{"c1"}}
	if err := svc.run(context.Background(), sch); err != nil {
		t.Fatalf("run: %v", err)
	}
	if mail.sentCh != 1 {
		t.Fatalf("expected one channel notification, got %d", mail.sentCh)
	}
	if len(mail.sent) != 0 {
		t.Fatalf("a channel recipient must not get the HTML attachment")
	}
}
