package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Channel types.
const (
	TypeWebhook    = "webhook"
	TypeSlack      = "slack"
	TypeTeams      = "teams"
	TypeMattermost = "mattermost"
	TypeEmail      = "email"
	TypeKafka      = "kafka"
)

// ErrSMTPNotConfigured is returned when an email channel is used without SMTP.
var ErrSMTPNotConfigured = errors.New("SMTP is not configured")

// SMTPConfig is the outbound mail server used by email channels.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLS      string // "starttls" (default) | "tls" (implicit) | "none"
}

// Configured reports whether email can be sent.
func (c SMTPConfig) Configured() bool { return c.Host != "" && c.From != "" }

// ValidateTarget checks a channel's url field for its type: an http(s) URL for
// the webhook-style types, a comma-separated list of addresses for email, a
// topic name for kafka.
func ValidateTarget(typ, target string) error {
	switch typ {
	case TypeWebhook, TypeSlack, TypeTeams, TypeMattermost:
		u, err := url.Parse(target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("url must be an http(s) URL")
		}
		return nil
	case TypeEmail:
		_, err := ParseRecipients(target)
		return err
	case TypeKafka:
		if !kafkaTopicRe.MatchString(target) {
			return errors.New("topic must be 1–249 characters of letters, numbers, '.', '_' or '-'")
		}
		return nil
	default:
		return errors.New("type must be one of webhook, slack, teams, mattermost, email, kafka")
	}
}

// ParseRecipients splits a comma-separated recipient list into bare addresses.
func ParseRecipients(list string) ([]string, error) {
	var out []string
	for part := range strings.SplitSeq(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		a, err := mail.ParseAddress(part)
		if err != nil {
			return nil, fmt.Errorf("invalid recipient %q", part)
		}
		out = append(out, a.Address)
	}
	if len(out) == 0 {
		return nil, errors.New("at least one email recipient is required")
	}
	return out, nil
}

// emailMessage builds a multipart/alternative (plain + HTML) message for an
// event, returning it with the recipient list.
func (s *Service) emailMessage(ch Channel, e Event) ([]byte, []string, error) {
	if !s.smtp.Configured() {
		return nil, nil, ErrSMTPNotConfigured
	}
	rcpts, err := ParseRecipients(ch.URL)
	if err != nil {
		return nil, nil, err
	}
	subject := e.Title
	if subject == "" {
		subject = "Xila notification"
	}

	var plain, rich strings.Builder
	if e.Severity != "" {
		fmt.Fprintf(&plain, "[%s] ", strings.ToUpper(e.Severity))
	}
	plain.WriteString(e.Title + "\n")
	if e.Text != "" {
		plain.WriteString("\n" + e.Text + "\n")
	}
	rich.WriteString("<html><body><h2>" + html.EscapeString(subject) + "</h2>")
	if e.Severity != "" {
		rich.WriteString("<p><strong>Severity:</strong> " + html.EscapeString(strings.ToUpper(e.Severity)) + "</p>")
	}
	if e.Text != "" {
		rich.WriteString("<p>" + strings.ReplaceAll(html.EscapeString(e.Text), "\n", "<br>") + "</p>")
	}
	if len(e.Fields) > 0 {
		plain.WriteString("\n")
		rich.WriteString("<table>")
		for _, k := range sortedKeys(e.Fields) {
			fmt.Fprintf(&plain, "%s: %s\n", k, e.Fields[k])
			rich.WriteString("<tr><th align=\"left\">" + html.EscapeString(k) + "</th><td>" + html.EscapeString(e.Fields[k]) + "</td></tr>")
		}
		rich.WriteString("</table>")
	}
	rich.WriteString("</body></html>")

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, part := range []struct{ ctype, content string }{
		{"text/plain; charset=utf-8", plain.String()},
		{"text/html; charset=utf-8", rich.String()},
	} {
		w, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {part.ctype},
			"Content-Transfer-Encoding": {"8bit"},
		})
		if err != nil {
			return nil, nil, err
		}
		w.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(part.content, "\r\n", "\n"), "\n", "\r\n")))
	}
	mw.Close()

	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\n", s.smtp.From)
	fmt.Fprintf(&msg, "To: %s\r\n", strings.Join(rcpts, ", "))
	fmt.Fprintf(&msg, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&msg, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	msg.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&msg, "Content-Type: multipart/alternative; boundary=%q\r\n\r\n", mw.Boundary())
	msg.Write(body.Bytes())
	return msg.Bytes(), rcpts, nil
}

// sendMail performs one SMTP transaction (STARTTLS, implicit TLS or plain).
func (s *Service) sendMail(ctx context.Context, rcpts []string, msg []byte) error {
	cfg := s.smtp
	if s.smtpPass != nil {
		cfg.Password = s.smtpPass.Get()
	}
	port := cfg.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(port))
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	if cfg.TLS == "tls" {
		tc := tls.Client(conn, tlsCfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			conn.Close()
			return fmt.Errorf("smtp tls: %w", err)
		}
		conn = tc
	}
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp greeting: %w", err)
	}
	defer c.Close()
	if err := c.Hello("xila"); err != nil {
		return fmt.Errorf("smtp ehlo: %w", err)
	}
	if cfg.TLS == "" || cfg.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp server does not support STARTTLS")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(mailAddress(cfg.From)); err != nil {
		return fmt.Errorf("smtp mail from: %w", err)
	}
	for _, r := range rcpts {
		if err := c.Rcpt(r); err != nil {
			return fmt.Errorf("smtp rcpt %s: %w", r, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	return c.Quit()
}

// mailAddress extracts the bare address from a From value like "Xila <x@y>".
func mailAddress(from string) string {
	if a, err := mail.ParseAddress(from); err == nil {
		return a.Address
	}
	return from
}

// SendText sends one plain-text email (account mail: password reset). It goes
// straight out, not through a channel or the delivery log.
func (s *Service) SendText(ctx context.Context, to, subject, body string) error {
	if !s.smtp.Configured() {
		return ErrSMTPNotConfigured
	}
	addr, err := mail.ParseAddress(to)
	if err != nil {
		return fmt.Errorf("recipient: %w", err)
	}
	var msg bytes.Buffer
	fmt.Fprintf(&msg, "From: %s\r\n", s.smtp.From)
	fmt.Fprintf(&msg, "To: %s\r\n", addr.String())
	fmt.Fprintf(&msg, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&msg, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	msg.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n")
	msg.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	return s.sendMail(ctx, []string{addr.Address}, msg.Bytes())
}
