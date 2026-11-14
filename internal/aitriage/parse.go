package aitriage

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/xilasec/xila-api/internal/domain"
)

// Answer is a model's validated answer.
type Answer struct {
	Verdict          string
	Rationale        string
	Confidence       float64
	ProposedStatus   *domain.FindingStatus
	ProposedSeverity *domain.Severity
	Fix              string
}

// ErrInvalidAnswer: the model's output doesn't match the schema; the
// proposal is recorded as invalid and can't be accepted.
var ErrInvalidAnswer = errors.New("the model's answer is invalid")

// Answer limits.
const (
	maxRationale = 4000
	maxFix       = 8000
)

// rawAnswer is the wire schema; every key is required (null where allowed).
type rawAnswer struct {
	Verdict          *string         `json:"verdict"`
	Rationale        *string         `json:"rationale"`
	Confidence       *float64        `json:"confidence"`
	ProposedStatus   json.RawMessage `json:"proposed_status"`
	ProposedSeverity json.RawMessage `json:"proposed_severity"`
	Fix              *string         `json:"fix"`
}

// What each kind may answer.
var (
	verdicts = map[Kind][]string{
		KindFalsePositive:  {"false_positive", "true_positive", "uncertain"},
		KindExploitability: {"exploitable", "not_exploitable", "uncertain"},
		KindFix:            {"fix_available", "no_fix"},
	}
	statuses = map[Kind][]domain.FindingStatus{
		KindFalsePositive:  {domain.FindingFalsePositive, domain.FindingConfirmed},
		KindExploitability: {domain.FindingConfirmed, domain.FindingWontFix, domain.FindingRiskAccepted},
	}
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidAnswer, fmt.Sprintf(format, args...))
}

// unfence strips one markdown code fence wrapping the whole answer (models
// without a JSON mode add it); nothing else is tolerated.
func unfence(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") || !strings.HasSuffix(s, "```") || len(s) < 6 {
		return s
	}
	s = strings.TrimSuffix(strings.TrimPrefix(s, "```"), "```")
	s = strings.TrimPrefix(s, "json")
	return strings.TrimSpace(s)
}

// nullableEnum decodes a key that is null or one of allowed.
// A missing key leaves raw empty; null arrives as the literal "null".
func nullableEnum[T ~string](name string, raw json.RawMessage, allowed []T) (*T, error) {
	if len(raw) == 0 {
		return nil, invalid("%s is missing", name)
	}
	if string(raw) == "null" {
		return nil, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, invalid("%s must be a string or null", name)
	}
	v := T(s)
	if !slices.Contains(allowed, v) {
		return nil, invalid("%s %q is not allowed here", name, s)
	}
	return &v, nil
}

// ParseAnswer validates a model's raw output against kind's schema: exactly
// one JSON object with exactly the schema's keys, enums from the allowed
// sets (an out-of-set status makes the whole answer invalid), bounded text.
func ParseAnswer(kind Kind, raw string) (Answer, error) {
	dec := json.NewDecoder(strings.NewReader(unfence(raw)))
	dec.DisallowUnknownFields()
	var r rawAnswer
	if err := dec.Decode(&r); err != nil {
		return Answer{}, invalid("not the expected JSON object (%v)", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Answer{}, invalid("trailing data after the JSON object")
	}
	if r.Verdict == nil || r.Rationale == nil || r.Confidence == nil || r.Fix == nil {
		return Answer{}, invalid("verdict, rationale, confidence and fix are required")
	}
	a := Answer{Verdict: *r.Verdict, Rationale: strings.TrimSpace(*r.Rationale), Confidence: *r.Confidence, Fix: strings.TrimSpace(*r.Fix)}
	if !slices.Contains(verdicts[kind], a.Verdict) {
		return Answer{}, invalid("verdict %q is not one of %s", a.Verdict, strings.Join(verdicts[kind], ", "))
	}
	if a.Rationale == "" || utf8.RuneCountInString(a.Rationale) > maxRationale {
		return Answer{}, invalid("rationale must be 1–%d characters", maxRationale)
	}
	if a.Confidence < 0 || a.Confidence > 1 {
		return Answer{}, invalid("confidence must be between 0 and 1")
	}
	var err error
	if a.ProposedStatus, err = nullableEnum("proposed_status", r.ProposedStatus, statuses[kind]); err != nil {
		return Answer{}, err
	}
	var severities []domain.Severity
	if kind == KindExploitability {
		severities = []domain.Severity{domain.SeverityCritical, domain.SeverityHigh, domain.SeverityMedium, domain.SeverityLow, domain.SeverityInfo}
	}
	if a.ProposedSeverity, err = nullableEnum("proposed_severity", r.ProposedSeverity, severities); err != nil {
		return Answer{}, err
	}
	switch {
	case kind == KindFix && a.Verdict == "fix_available" && a.Fix == "":
		return Answer{}, invalid("fix is required when a fix is available")
	case kind != KindFix && a.Fix != "":
		return Answer{}, invalid("fix must be empty for a %s question", kind)
	case utf8.RuneCountInString(a.Fix) > maxFix:
		return Answer{}, invalid("fix is longer than %d characters", maxFix)
	}
	// A verdict that contradicts its proposed status is not a proposal.
	if kind == KindFalsePositive && a.ProposedStatus != nil &&
		(a.Verdict == "uncertain" || (*a.ProposedStatus == domain.FindingFalsePositive) != (a.Verdict == "false_positive")) {
		return Answer{}, invalid("proposed_status %q contradicts verdict %q", *a.ProposedStatus, a.Verdict)
	}
	return a, nil
}
