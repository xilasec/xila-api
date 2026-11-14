package scanner

import (
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// TestSSL parses the CSV output of testssl.sh (`testssl.sh --csvfile out.csv
// <host>`), whose columns are id, fqdn/ip, port, severity, finding, cve, cwe.
//
// testssl.sh writes one row per check it ran; rows rated OK or INFO are passed
// checks and facts (offered protocols, cipher lists), and WARN / FATAL / DEBUG
// rows are diagnostics of the scan itself, so only LOW, MEDIUM, HIGH and
// CRITICAL rows become findings. The rule id is the check id ("BREACH",
// "LUCKY13"), the location is host:port. A hostname resolving to several IPs is
// tested once per IP; the same check failing on several of them is one finding
// on the hostname, with the IPs kept in metadata. A report whose only verdict is
// a FATAL scan problem (target unreachable) is rejected rather than read as clean.
type TestSSL struct{}

// NewTestSSL constructs a testssl.sh parser.
func NewTestSSL() TestSSL { return TestSSL{} }

// Scanner returns the tool identifier.
func (TestSSL) Scanner() string { return "testssl" }

// PrimaryCategory is the scan-level category for testssl.sh reports.
func (TestSSL) PrimaryCategory() domain.Category { return domain.CategoryDAST }

// Parse implements Parser.
func (TestSSL) Parse(r io.Reader) ([]ParsedFinding, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("decode testssl csv: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))] = i
	}
	for _, need := range []string{"id", "fqdn/ip", "port", "severity", "finding"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("decode testssl csv: no %q column — not a testssl.sh CSV report", need)
		}
	}
	get := func(rec []string, name string) string {
		if i, ok := col[name]; ok && i < len(rec) {
			return strings.TrimSpace(rec[i])
		}
		return ""
	}

	out := []ParsedFinding{}
	byKey := map[string]int{}
	var fatal string
	for {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode testssl csv: %w", err)
		}
		sev := strings.ToUpper(get(rec, "severity"))
		switch sev {
		case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		case "FATAL":
			fatal = get(rec, "finding")
			continue
		default: // OK, INFO, WARN, DEBUG
			continue
		}
		id, finding, port := get(rec, "id"), get(rec, "finding"), get(rec, "port")
		host, ip, _ := strings.Cut(get(rec, "fqdn/ip"), "/")
		target := firstNonEmpty(host, ip)
		if port != "" {
			target += ":" + port
		}
		key := id + "\x00" + target
		if i, ok := byKey[key]; ok {
			f := &out[i]
			if s := normalizeSeverity(sev); s.Weight() > f.Severity.Weight() {
				f.Severity = s
			}
			if ip != "" {
				if ips, _ := f.Metadata["ips"].([]string); !slices.Contains(ips, ip) {
					f.Metadata["ips"] = append(ips, ip)
				}
			}
			continue
		}
		fields := strings.Fields(get(rec, "cve"))
		f := ParsedFinding{
			Category:    domain.CategoryDAST,
			RuleID:      id,
			Title:       id + ": " + finding,
			Description: finding,
			Severity:    normalizeSeverity(sev),
			CWE:         cweFirst(strings.Fields(get(rec, "cwe"))...),
			CVE:         cvesFrom(fields...),
			FilePath:    target,
			URL:         target,
			Metadata:    map[string]any{"host": host, "port": port},
		}
		if ip != "" {
			f.Metadata["ips"] = []string{ip}
		}
		byKey[key] = len(out)
		out = append(out, f)
	}
	if len(out) == 0 && fatal != "" {
		return nil, fmt.Errorf("testssl.sh could not scan the target: %s", fatal)
	}
	return out, nil
}
