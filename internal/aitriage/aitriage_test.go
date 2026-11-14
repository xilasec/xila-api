package aitriage

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/netguard"
)

// A SAST finding's scanner snippet is sent with credentials scrubbed; a
// finding without one sends none; a secret finding sends neither its snippet
// nor its description, and the value its scanner matched is scrubbed from
// every field. Hand-written findings in the shapes the bandit and gitleaks
// parsers produce.
func TestBuildPromptMinimisesAndRedacts(t *testing.T) {
	const pw = "hunter2-Pr0d-S3cret" // gitleaks:allow -- fake credential for the redaction test
	sast := finding.Finding{
		Scanner: "bandit", Category: domain.CategorySAST, RuleID: "B105",
		Title: "B105: Possible hardcoded password", Severity: domain.SeverityLow,
		FilePath: "app/settings.py", Line: new(12), CWE: new(259),
		Description: "Possible hardcoded password: '" + pw + "'",
		Metadata:    map[string]any{"code": "11 DEBUG = False\n12 DB_PASSWORD = \"" + pw + "\"\n13 aws = 'AKIAIOSFODNN7EXAMPLE'\n"}, // gitleaks:allow -- AWS's documented example key
	}
	p := BuildPrompt(sast, KindFalsePositive)
	if strings.Contains(p.User, pw) || strings.Contains(p.User, "AKIAIOSFODNN7EXAMPLE") { // gitleaks:allow -- AWS's documented example key
		t.Fatalf("secret leaked into the prompt:\n%s", p.User)
	}
	for _, want := range []string{"code snippet (from the scanner)", "DB_PASSWORD = " + Redacted, "location: app/settings.py:12", "cwe: CWE-259", "rule_id: B105"} {
		if !strings.Contains(p.User, want) {
			t.Errorf("prompt lacks %q:\n%s", want, p.User)
		}
	}
	if !strings.Contains(p.System, `"proposed_status": "false_positive" | "confirmed" | null`) {
		t.Errorf("system prompt lacks the schema:\n%s", p.System)
	}

	noSnippet := sast
	noSnippet.Metadata = map[string]any{"confidence": "high"}
	if p := BuildPrompt(noSnippet, KindFix); strings.Contains(p.User, "code snippet") {
		t.Errorf("snippet sent although the scanner provided none:\n%s", p.User)
	}

	const token = "ghp_0123456789abcdefghijklmnopqrstuvwxyzAB" // gitleaks:allow -- fake token for the redaction test
	secret := finding.Finding{
		Scanner: "ggshield", Category: domain.CategorySecret, RuleID: "github_token",
		Title: "GitHub token " + token[:12] + "…", Severity: domain.SeverityHigh, FilePath: ".env",
		Description: "Secret detected: " + token,
		Metadata:    map[string]any{"match": "opaque-vendor-key-9f8e7d6c", "snippet": "TOKEN=" + token},
	}
	secret.Title = "Leaked key opaque-vendor-key-9f8e7d6c in .env"
	p = BuildPrompt(secret, KindFalsePositive)
	if strings.Contains(p.User, token) || strings.Contains(p.User, "opaque-vendor-key-9f8e7d6c") ||
		strings.Contains(p.User, "code snippet") || strings.Contains(p.User, "description:") {
		t.Fatalf("secret finding prompt leaks:\n%s", p.User)
	}
	if !strings.Contains(p.User, "title: Leaked key "+Redacted+" in .env") {
		t.Errorf("matched value not scrubbed from the title:\n%s", p.User)
	}
	if p.Hash() == BuildPrompt(secret, KindFix).Hash() {
		t.Error("prompt hash ignores the kind's system prompt")
	}
}

func TestParseAnswer(t *testing.T) {
	ok := `{"verdict":"false_positive","rationale":"Test fixture only.","confidence":0.82,"proposed_status":"false_positive","proposed_severity":null,"fix":""}`
	a, err := ParseAnswer(KindFalsePositive, "```json\n"+ok+"\n```")
	if err != nil || a.ProposedStatus == nil || *a.ProposedStatus != domain.FindingFalsePositive || a.Confidence != 0.82 {
		t.Fatalf("valid answer: %+v %v", a, err)
	}
	a, err = ParseAnswer(KindExploitability, `{"verdict":"not_exploitable","rationale":"Behind auth.","confidence":0.5,"proposed_status":null,"proposed_severity":"low","fix":""}`)
	if err != nil || a.ProposedSeverity == nil || *a.ProposedSeverity != domain.SeverityLow || a.ProposedStatus != nil {
		t.Fatalf("exploitability: %+v %v", a, err)
	}
	bad := map[string]string{
		"out-of-set status":     strings.Replace(ok, `"proposed_status":"false_positive"`, `"proposed_status":"remediated"`, 1),
		"status for this kind":  strings.Replace(ok, `"proposed_status":"false_positive"`, `"proposed_status":"wont_fix"`, 1),
		"severity on fp":        strings.Replace(ok, `"proposed_severity":null`, `"proposed_severity":"low"`, 1),
		"unknown key":           strings.Replace(ok, `"fix":""`, `"fix":"","apply":true`, 1),
		"missing key":           strings.Replace(ok, `,"fix":""`, ``, 1),
		"missing nullable key":  strings.Replace(ok, `"proposed_severity":null,`, ``, 1),
		"confidence > 1":        strings.Replace(ok, `0.82`, `1.5`, 1),
		"unknown verdict":       strings.Replace(ok, `"verdict":"false_positive"`, `"verdict":"probably"`, 1),
		"contradiction":         strings.Replace(ok, `"verdict":"false_positive"`, `"verdict":"true_positive"`, 1),
		"empty rationale":       strings.Replace(ok, `"Test fixture only."`, `"  "`, 1),
		"trailing data":         ok + ` {"verdict":"x"}`,
		"prose":                 "Sure! " + ok,
		"array":                 `[` + ok + `]`,
		"html is fine as text?": strings.Replace(ok, `"fix":""`, `"fix":"<script>alert(1)</script>"`, 1), // fix on a non-fix kind
	}
	for name, raw := range bad {
		if _, err := ParseAnswer(KindFalsePositive, raw); !errors.Is(err, ErrInvalidAnswer) {
			t.Errorf("%s: err = %v, want ErrInvalidAnswer", name, err)
		}
	}
	if _, err := ParseAnswer(KindFix, `{"verdict":"fix_available","rationale":"r","confidence":0.9,"proposed_status":null,"proposed_severity":null,"fix":""}`); !errors.Is(err, ErrInvalidAnswer) {
		t.Errorf("fix_available without a fix accepted: %v", err)
	}
}

// Both providers speak their wire protocol through netguard; a provider's
// error body stays out of the public message.
func TestProviders(t *testing.T) {
	netguard.SetDefault(netguard.Permissive)
	var got struct {
		path, auth, apiKey, version string
		body                        map[string]any
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path, got.auth, got.apiKey, got.version = r.URL.Path, r.Header.Get("Authorization"), r.Header.Get("x-api-key"), r.Header.Get("anthropic-version")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got.body)
		switch r.URL.Path {
		case "/v1/chat/completions":
			_, _ = io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"{\"a\":1}"}}]}`)
		case "/v1/messages":
			_, _ = io.WriteString(w, `{"content":[{"type":"text","text":"{\"b\":"},{"type":"text","text":"2}"}]}`)
		default:
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"error":"bad key sk-internal-detail"}`)
		}
	}))
	defer srv.Close()
	prompt := Prompt{System: "sys", User: "usr"}

	oa, _ := NewProvider(config.AI{Provider: config.AIProviderOpenAI, BaseURL: srv.URL + "/v1", Model: "m1", APIKey: "k1", Timeout: 5e9})
	out, err := oa.Complete(context.Background(), prompt)
	if err != nil || out != `{"a":1}` || got.path != "/v1/chat/completions" || got.auth != "Bearer k1" || got.body["model"] != "m1" {
		t.Fatalf("openai: %q %v %+v", out, err, got)
	}
	if msgs := got.body["messages"].([]any); len(msgs) != 2 || msgs[0].(map[string]any)["content"] != "sys" || msgs[1].(map[string]any)["content"] != "usr" {
		t.Errorf("openai messages = %v", msgs)
	}

	an, _ := NewProvider(config.AI{Provider: config.AIProviderAnthropic, BaseURL: srv.URL, Model: "m2", APIKey: "k2", Timeout: 5e9})
	out, err = an.Complete(context.Background(), prompt)
	if err != nil || out != `{"b":2}` || got.path != "/v1/messages" || got.apiKey != "k2" || got.version != anthropicVersion ||
		got.body["system"] != "sys" || got.auth != "" {
		t.Fatalf("anthropic: %q %v %+v", out, err, got)
	}

	bad, _ := NewProvider(config.AI{Provider: config.AIProviderOpenAI, BaseURL: srv.URL + "/nope", Model: "m", Timeout: 5e9})
	_, err = bad.Complete(context.Background(), prompt)
	var re RemoteError
	if !errors.As(err, &re) || strings.Contains(re.Public(), "sk-internal-detail") || !strings.Contains(err.Error(), "sk-internal-detail") {
		t.Errorf("error = %v (public %q)", err, re.Public())
	}
}
