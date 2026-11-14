package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixture: a CONSTRUCTED Steampipe/Powerpipe benchmark export (no openly
// licensed real export with per-resource rows was found), shaped exactly per the
// upstream export template (turbot/steampipe
// pkg/control/controldisplay/templates/json/output.tmpl, AGPL-3.0 — this is
// the template that produces the file, not vendored code) and the
// ControlRun/ResultRow/GroupSummary JSON field names from
// turbot/powerpipe's internal/controlexecute package (Apache-2.0).
func TestSteampipeParse(t *testing.T) {
	out := parseFixture(t, NewSteampipe(), "steampipe_s3_benchmark.json")
	// One alarm result row, plus one synthetic finding for the control whose
	// query itself errored (no per-resource rows at all) = 2.
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2: %v", len(out), out)
	}
	for _, f := range out {
		if f.Category != domain.CategoryCloud {
			t.Errorf("category = %s, want cloud", f.Category)
		}
	}

	versioning := findByRule(t, out, "aws_compliance.control.s3_bucket_versioning_enabled")
	if versioning.Title != "2.1.3 Ensure S3 Bucket versioning is enabled" ||
		versioning.Severity != domain.SeverityMedium ||
		versioning.FilePath != "arn:aws:s3:::my-app-logs" {
		t.Errorf("versioning finding = %+v", versioning)
	}
	if versioning.Description != "Bucket versioning disabled." {
		t.Errorf("description = %q, want the alarm row's reason", versioning.Description)
	}
	if versioning.Metadata["region"] != "us-east-1" || versioning.Metadata["account_id"] != "012345678901" {
		t.Errorf("dimensions not flattened into metadata: %v", versioning.Metadata)
	}
	if versioning.Metadata["benchmark"] != "CIS v4.0.0 / 2 Storage" {
		t.Errorf("benchmark path = %v", versioning.Metadata["benchmark"])
	}
	// The "ok" row for my-app-assets must never surface as a finding.
	for _, f := range out {
		if f.FilePath == "arn:aws:s3:::my-app-assets" {
			t.Errorf("an ok result became a finding: %+v", f)
		}
	}

	logging := findByRule(t, out, "aws_compliance.control.s3_bucket_logging_enabled")
	if logging.Severity != domain.SeverityLow || logging.FilePath != "" {
		t.Errorf("errored-control finding = %+v", logging)
	}
	if !strings.Contains(logging.Description, "no such host") {
		t.Errorf("errored-control description = %q, want the run_error", logging.Description)
	}
}

// Fixture: a real export from ciaran-finnegan/steampipe-security-controls-module
// (steampipe_benchmark/all-20220729-084831.custom.json, MIT), written with a
// custom template that keeps only per-control counts — no result rows. Every
// control in alarm must still surface (one finding each), never silently vanish.
func TestSteampipeSummaryOnlyExport(t *testing.T) {
	out := parseFixture(t, NewSteampipe(), "steampipe_custom_summary.json")
	if len(out) != 8 {
		t.Fatalf("got %d findings, want 8 (every control has alarms)", len(out))
	}
	total := 0
	for _, f := range out {
		n, _ := f.Metadata["alarm_count"].(int)
		total += n
		if f.FilePath != "" || f.Category != domain.CategoryCloud {
			t.Errorf("finding %+v: want a control-level cloud finding", f)
		}
	}
	if total != 114 {
		t.Errorf("alarm counts sum to %d, want 114 (the export's root summary)", total)
	}
	dmarc := findByRule(t, out, "control.INF_001")
	if dmarc.Metadata["alarm_count"] != 12 || !strings.HasPrefix(dmarc.Title, "INF-001 - Organisational email domains without DMARC") {
		t.Errorf("INF_001 = %+v", dmarc)
	}
	if dmarc.Metadata["benchmark"] != "steampipe_dashboard / Security Controls Reporting Dashboard / Infrastructure" {
		t.Errorf("benchmark path = %v", dmarc.Metadata["benchmark"])
	}
}

func TestSteampipeRejectsMalformed(t *testing.T) {
	if _, err := NewSteampipe().Parse(strings.NewReader(`{"not":"steampipe"}`)); err == nil {
		t.Error("want error for JSON without group_id/groups/controls")
	}
	if _, err := NewSteampipe().Parse(strings.NewReader("not json")); err == nil {
		t.Error("want error for non-JSON input")
	}
}
