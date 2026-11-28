package notify

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeLog struct {
	mu sync.Mutex
	ds []Delivery
}

func (f *fakeLog) LogDelivery(_ context.Context, d Delivery) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ds = append(f.ds, d)
	return nil
}

func captureServer(t *testing.T) (*httptest.Server, func() []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var bodies []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
			t.Errorf("body not JSON: %v", err)
		}
		mu.Lock()
		bodies = append(bodies, m)
		mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv, func() []map[string]any { mu.Lock(); defer mu.Unlock(); return bodies }
}

var sampleEvent = Event{
	Type: EventCriticalFinding, Title: "New critical", Text: "2 new", Severity: "critical",
	Fields: map[string]string{"project": "web", "count": "2"},
}

func TestTeamsPayload(t *testing.T) {
	srv, bodies := captureServer(t)
	svc := &Service{client: srv.Client(), maxAttempts: 1}
	if err := svc.SendTo(context.Background(), Channel{Name: "t", Type: TypeTeams, URL: srv.URL}, sampleEvent); err != nil {
		t.Fatal(err)
	}

	got := bodies()
	if len(got) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(got))
	}
	want := `{"@context":"https://schema.org/extensions","@type":"MessageCard","sections":[{"facts":[{"name":"count","value":"2"},{"name":"project","value":"web"}]}],"summary":"New critical","text":"2 new","themeColor":"B71C1C","title":"[CRITICAL] New critical"}`
	if b, _ := json.Marshal(got[0]); string(b) != want {
		t.Errorf("teams card =\n%s\nwant\n%s", b, want)
	}
}

func TestThemeColor(t *testing.T) {
	for sev, want := range map[string]string{"critical": "B71C1C", "HIGH": "E65100", "medium": "F9A825", "low": "1565C0", "": "6E7781", "info": "6E7781"} {
		if got := themeColor(sev); got != want {
			t.Errorf("themeColor(%q) = %s, want %s", sev, got, want)
		}
	}
}

func TestMattermostPayload(t *testing.T) {
	srv, bodies := captureServer(t)
	svc := &Service{client: srv.Client(), maxAttempts: 1}
	if err := svc.SendTo(context.Background(), Channel{Name: "m", Type: TypeMattermost, URL: srv.URL}, sampleEvent); err != nil {
		t.Fatal(err)
	}
	got := bodies()
	if len(got) != 1 {
		t.Fatalf("deliveries = %d, want 1", len(got))
	}
	wantText := "[CRITICAL] *New critical*\n2 new\n• count: 2\n• project: web"
	if got[0]["text"] != wantText || got[0]["username"] != "Xila" || len(got[0]) != 2 {
		t.Errorf("mattermost payload = %v", got[0])
	}
}

func TestValidateTarget(t *testing.T) {
	cases := []struct {
		typ, target string
		ok          bool
	}{
		{TypeWebhook, "https://x.example/hook", true},
		{TypeSlack, "http://x.example", true},
		{TypeTeams, "https://outlook.office.com/webhook/abc", true},
		{TypeMattermost, "ftp://x.example", false},
		{TypeTeams, "not a url", false},
		{TypeWebhook, "https://", false},
		{TypeEmail, "alice@example.com, Bob <bob@example.com>", true},
		{TypeEmail, "alice@example.com, nope", false},
		{TypeEmail, " , ", false},
		{"pager", "https://x.example", false},
	}
	for _, c := range cases {
		if err := ValidateTarget(c.typ, c.target); (err == nil) != c.ok {
			t.Errorf("ValidateTarget(%q,%q) err=%v, want ok=%v", c.typ, c.target, err, c.ok)
		}
	}
	got, _ := ParseRecipients("alice@example.com, Bob <bob@example.com>")
	if strings.Join(got, "|") != "alice@example.com|bob@example.com" {
		t.Errorf("ParseRecipients = %v", got)
	}
}

// fakeSMTP is a minimal in-process SMTP server: EHLO, AUTH PLAIN, MAIL, RCPT,
// DATA, QUIT. failFirst rejects that many DATA transactions with a 451.
type fakeSMTP struct {
	ln        net.Listener
	mu        sync.Mutex
	failFirst int
	sessions  int
	auth      string
	from      string
	rcpts     []string
	data      string
}

func newFakeSMTP(t *testing.T, failFirst int) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeSMTP{ln: ln, failFirst: failFirst}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeSMTP) port() int { return f.ln.Addr().(*net.TCPAddr).Port }

func (f *fakeSMTP) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := func(s string) { io.WriteString(c, s+"\r\n") }
	w("220 fake ESMTP")
	var from string
	var rcpts []string
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		cmd := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			w("250-fake")
			w("250 AUTH PLAIN")
		case strings.HasPrefix(cmd, "AUTH PLAIN"):
			dec, _ := base64.StdEncoding.DecodeString(strings.TrimSpace(line[len("AUTH PLAIN"):]))
			f.mu.Lock()
			f.auth = string(dec)
			f.mu.Unlock()
			w("235 ok")
		case strings.HasPrefix(cmd, "MAIL FROM:"):
			from = strings.Trim(line[len("MAIL FROM:"):], "<> ")
			w("250 ok")
		case strings.HasPrefix(cmd, "RCPT TO:"):
			rcpts = append(rcpts, strings.Trim(line[len("RCPT TO:"):], "<> "))
			w("250 ok")
		case cmd == "DATA":
			w("354 go")
			var b strings.Builder
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				b.WriteString(strings.TrimPrefix(l, "."))
			}
			f.mu.Lock()
			f.sessions++
			fail := f.sessions <= f.failFirst
			if !fail {
				f.from, f.rcpts, f.data = from, rcpts, b.String()
			}
			f.mu.Unlock()
			if fail {
				w("451 try later")
			} else {
				w("250 queued")
			}
		case cmd == "QUIT":
			w("221 bye")
			return
		default:
			w("502 unknown")
		}
	}
}

func TestEmailDelivery(t *testing.T) {
	f := newFakeSMTP(t, 0)
	svc, _, logs := testService([]Channel{{ID: "c1", Name: "mail", Type: TypeEmail, URL: "alice@example.com, Bob <bob@example.com>", Enabled: true}}, nil)
	svc.smtp = SMTPConfig{Host: "127.0.0.1", Port: f.port(), Username: "u", Password: "p", From: "Xila <xila@example.com>", TLS: "none"}
	svc.Notify(context.Background(), sampleEvent)
	if _, err := svc.DispatchDue(context.Background()); err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.from != "xila@example.com" || strings.Join(f.rcpts, ",") != "alice@example.com,bob@example.com" {
		t.Errorf("envelope from=%q rcpts=%v", f.from, f.rcpts)
	}
	if f.auth != "\x00u\x00p" {
		t.Errorf("auth = %q", f.auth)
	}
	msg, err := mail.ReadMessage(strings.NewReader(f.data))
	if err != nil {
		t.Fatalf("parse message: %v", err)
	}
	if s := msg.Header.Get("Subject"); s != "New critical" {
		t.Errorf("subject = %q", s)
	}
	mt, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if mt != "multipart/alternative" {
		t.Fatalf("content-type = %q", mt)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	parts := map[string]string{}
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		b, _ := io.ReadAll(p)
		ct, _, _ := mime.ParseMediaType(p.Header.Get("Content-Type"))
		parts[ct] = string(b)
	}
	if want := "[CRITICAL] New critical\r\n\r\n2 new\r\n\r\ncount: 2\r\nproject: web\r\n"; parts["text/plain"] != want {
		t.Errorf("plain part = %q, want %q", parts["text/plain"], want)
	}
	if !strings.Contains(parts["text/html"], "<h2>New critical</h2>") || !strings.Contains(parts["text/html"], "<th align=\"left\">project</th><td>web</td>") {
		t.Errorf("html part = %q", parts["text/html"])
	}
	logs.mu.Lock()
	defer logs.mu.Unlock()
	if len(logs.ds) != 1 || !logs.ds[0].Delivered || logs.ds[0].StatusCode != nil || logs.ds[0].Attempts != 1 {
		t.Errorf("delivery log = %+v", logs.ds)
	}
}

func TestEmailRetriesOnFailure(t *testing.T) {
	f := newFakeSMTP(t, 2) // first two transactions fail, third succeeds
	logs := &fakeLog{}
	svc := &Service{
		logger: logs, maxAttempts: 3, backoff: time.Millisecond,
		smtp: SMTPConfig{Host: "127.0.0.1", Port: f.port(), From: "xila@example.com", TLS: "none"},
	}
	err := svc.SendTo(context.Background(), Channel{ID: "c1", Name: "mail", Type: TypeEmail, URL: "a@example.com"}, Event{Type: EventTest, Title: "t"})
	if err != nil {
		t.Fatalf("SendTo: %v", err)
	}
	if len(logs.ds) != 1 || logs.ds[0].Attempts != 3 || !logs.ds[0].Delivered {
		t.Errorf("delivery log = %+v, want delivered on attempt 3", logs.ds)
	}

	// Always failing: error text recorded, status 0 (nil).
	f2 := newFakeSMTP(t, 99)
	svc.smtp.Port = f2.port()
	logs.ds = nil
	if err := svc.SendTo(context.Background(), Channel{Name: "mail", Type: TypeEmail, URL: "a@example.com"}, Event{Type: EventTest}); err == nil {
		t.Fatal("want error")
	}
	if d := logs.ds[0]; d.Delivered || d.Attempts != 3 || d.StatusCode != nil || !strings.Contains(d.Error, "451") {
		t.Errorf("failed delivery log = %+v", d)
	}
}

func TestEmailWithoutSMTPFails(t *testing.T) {
	logs := &fakeLog{}
	svc := &Service{logger: logs, maxAttempts: 3}
	err := svc.SendTo(context.Background(), Channel{Name: "mail", Type: TypeEmail, URL: "a@example.com"}, Event{Type: EventTest})
	if !errors.Is(err, ErrSMTPNotConfigured) || logs.ds[0].Error != "SMTP is not configured" {
		t.Errorf("err = %v log = %+v", err, logs.ds)
	}
}

func TestStartTLSRequired(t *testing.T) {
	f := newFakeSMTP(t, 0) // does not advertise STARTTLS
	svc := &Service{maxAttempts: 1, smtp: SMTPConfig{Host: "127.0.0.1", Port: f.port(), From: "x@example.com"}}
	err := svc.SendTo(context.Background(), Channel{Type: TypeEmail, URL: "a@example.com"}, Event{Type: EventTest})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Errorf("err = %v, want STARTTLS refusal", err)
	}
}
