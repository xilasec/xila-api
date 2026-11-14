package asset

import (
	"os"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/scanner"
)

// evidenceOf builds inference input exactly as ScanEvidence reads it back from
// a stored finding (rule_id, file_path, metadata.resource_arn/categories).
func evidenceOf(scannerName string, f scanner.ParsedFinding) Evidence {
	e := Evidence{Scanner: scannerName, Category: f.Category, RuleID: f.RuleID, Resource: f.FilePath}
	e.ResourceARN, _ = f.Metadata["resource_arn"].(string)
	e.Categories, _ = f.Metadata["categories"].([]string)
	return e
}

// A real Prowler v3 run (an S3 bucket with a public bucket policy, SSH open to
// the internet): the checks Prowler itself classifies "internet-exposed" infer
// internet; a missing public-access *block* or an encryption gap infers nothing.
func TestInferFromProwlerReport(t *testing.T) {
	raw, err := os.Open("testdata/prowler_v3_public_bucket.json")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	parsed, err := scanner.Prowler{}.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed) != 5 { // the PASS record is not a finding
		t.Fatalf("parsed %d findings, want 5", len(parsed))
	}
	want := map[string]domain.Exposure{
		"s3_bucket_public_access":                                      domain.ExposureInternet,
		"ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22": domain.ExposureInternet,
		"s3_bucket_level_public_access_block":                          domain.ExposureUnknown,
		"s3_bucket_kms_encryption":                                     domain.ExposureUnknown,
		"ec2_ebs_default_encryption":                                   domain.ExposureUnknown,
	}
	for _, f := range parsed {
		got, reason := Infer(evidenceOf("prowler", f))
		if got != want[f.RuleID] {
			t.Errorf("%s: Infer = %q, want %q", f.RuleID, got, want[f.RuleID])
		}
		if f.RuleID == "s3_bucket_public_access" &&
			reason != "prowler s3_bucket_public_access failed on arn:aws:s3:::agentic-lab-exposed-bucket-53a94e59: the resource is publicly exposed" {
			t.Errorf("reason = %q", reason)
		}
	}
}

func TestInferRules(t *testing.T) {
	cloud := func(sc, rule string, cats ...string) Evidence {
		return Evidence{Scanner: sc, Category: domain.CategoryCloud, RuleID: rule, Resource: "r", Categories: cats}
	}
	cases := []struct {
		name string
		e    Evidence
		want domain.Exposure
	}{
		// Prowler reports without Categories (older versions) fall back to the check id.
		{"prowler fallback: public", cloud("prowler", "rds_instance_no_public_access"), domain.ExposureInternet},
		{"prowler fallback: internet ingress", cloud("prowler", "ec2_securitygroup_allow_ingress_from_internet_to_any_port"), domain.ExposureInternet},
		{"prowler fallback: a missing block is no proof", cloud("prowler", "s3_account_level_public_access_blocks"), domain.ExposureUnknown},
		{"prowler fallback: unrelated", cloud("prowler", "iam_root_mfa_enabled"), domain.ExposureUnknown},
		{"prowler categories win over the id", cloud("prowler", "s3_bucket_public_write_acl", "encryption"), domain.ExposureUnknown},
		{"scoutsuite open to all", cloud("scoutsuite", "ec2-security-group-opens-all-ports-to-all"), domain.ExposureInternet},
		{"scoutsuite publicly accessible", cloud("scoutsuite", "rds-instance-publicly-accessible"), domain.ExposureInternet},
		{"scoutsuite unrelated", cloud("scoutsuite", "cloudstorage-bucket-no-logging"), domain.ExposureUnknown},
		{"security hub public S3 read", cloud("aws-security-hub", "aws-foundational-security-best-practices/v/1.0.0/S3.2"), domain.ExposureInternet},
		{"security hub block-public-access setting", cloud("aws-security-hub", "aws-foundational-security-best-practices/v/1.0.0/S3.8"), domain.ExposureUnknown},
		{"security hub CIS 4.1", cloud("aws-security-hub", "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0/rule/4.1"), domain.ExposureInternet},
		{"public rule from a non-cloud scan", Evidence{Scanner: "prowler", Category: domain.CategoryIaC, RuleID: "s3_bucket_public_access"}, domain.ExposureUnknown},
		{"other cloud scanners say nothing", cloud("kubescape", "public_endpoint"), domain.ExposureUnknown},
		{"DAST reached it", Evidence{Scanner: "zap", Category: domain.CategoryDAST, RuleID: "10038"}, domain.ExposureInternal},
		{"SCA says nothing", Evidence{Scanner: "trivy", Category: domain.CategorySCA, RuleID: "CVE-2024-1"}, domain.ExposureUnknown},
	}
	for _, c := range cases {
		if got, _ := Infer(c.e); got != c.want {
			t.Errorf("%s: Infer = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestProposeBuiltFrom(t *testing.T) {
	// This image has 40 OS packages. debian (20, all shared) and python (30, all
	// shared) are both bases; python, the larger, is the closest parent.
	// app2 contains all 40 of ours: it is built from this image. tiny (3) is
	// below the evidence threshold; other (25, 10 shared) is unrelated; same
	// (40/40) is a rebuild of this image.
	got := ProposeBuiltFrom(40, []Overlap{
		{AssetID: "debian", Total: 20, Shared: 20},
		{AssetID: "python", Total: 30, Shared: 30},
		{AssetID: "app2", Total: 55, Shared: 40},
		{AssetID: "tiny", Total: 3, Shared: 3},
		{AssetID: "other", Total: 25, Shared: 10},
		{AssetID: "same", Total: 40, Shared: 40},
	})
	if len(got) != 2 {
		t.Fatalf("proposals = %+v, want python as base and app2 as derived", got)
	}
	if !got[0].Base || got[0].Other.AssetID != "python" {
		t.Errorf("first = %+v, want python as this image's base", got[0])
	}
	if got[1].Base || got[1].Other.AssetID != "app2" {
		t.Errorf("second = %+v, want app2 built from this image", got[1])
	}
	if p := ProposeBuiltFrom(3, []Overlap{{AssetID: "big", Total: 50, Shared: 3}}); len(p) != 0 {
		t.Errorf("a 3-package image proves nothing as a base: %+v", p)
	}
}
