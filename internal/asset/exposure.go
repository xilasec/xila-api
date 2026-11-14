package asset

import (
	"slices"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Evidence is one live finding as exposure inference reads it.
type Evidence struct {
	AssetID     *string // the finding's own asset (its scan's target)
	Scanner     string
	Category    domain.Category
	RuleID      string
	Resource    string   // file_path: the flagged resource id for cloud scanners
	ResourceARN string   // metadata.resource_arn (Prowler)
	Categories  []string // metadata.categories (Prowler's check classification)
}

// Infer applies the exposure inference rules to one finding. It returns
// ExposureUnknown when the finding says nothing about reachability.
//
//  1. Cloud public exposure ⇒ internet. A failing cloud-posture check whose rule
//     means "this resource is reachable from / readable by the internet":
//     - prowler: the check is classified "internet-exposed" (Prowler's own
//     Categories). Reports without Categories fall back to the check id: it
//     names "public"/"internet" and is not a "…public_access_block" setting
//     (a missing block is a hardening gap, not proof of exposure).
//     - scoutsuite: the rule id names public/publicly/world/allusers/internet,
//     or opens something "…-to-all".
//     - aws-security-hub: the control is one of publicFSBPControls (AWS
//     Foundational Security Best Practices controls that fail only when the
//     resource is public), or CIS AWS 4.1/4.2 (SSH/RDP open to 0.0.0.0/0).
//  2. A DAST/network finding ⇒ internal. The scanner reached the asset over the
//     network, so it is not isolated; where the scanner ran is unknown, so it
//     is not proof of internet exposure.
func Infer(e Evidence) (domain.Exposure, string) {
	if e.Category == domain.CategoryCloud && publicExposureRule(e) {
		return domain.ExposureInternet, e.Scanner + " " + e.RuleID + " failed on " +
			firstNonEmpty(e.ResourceARN, e.Resource, "the asset") + ": the resource is publicly exposed"
	}
	if e.Category == domain.CategoryDAST {
		return domain.ExposureInternal, e.Scanner + " reached the asset over the network (" +
			firstNonEmpty(e.RuleID, "a DAST finding") + ")"
	}
	return domain.ExposureUnknown, ""
}

// publicFSBPControls are the AWS Security Hub FSBP controls whose failure means
// the resource itself is publicly reachable or readable.
var publicFSBPControls = []string{
	"S3.2", "S3.3", // S3 buckets prohibit public read / write access
	"EC2.1",                                // EBS snapshots not publicly restorable
	"EC2.9",                                // EC2 instances without a public IPv4 address
	"EC2.13", "EC2.14", "EC2.18", "EC2.19", // security groups open to 0.0.0.0/0
	"RDS.1", "RDS.2", // RDS snapshots / instances not public
	"Lambda.1",             // Lambda policies prohibit public access
	"ES.2", "Opensearch.2", // domains not publicly accessible
	"Redshift.1",  // clusters prohibit public access
	"DMS.1",       // replication instances not public
	"EKS.1",       // cluster endpoints not publicly accessible
	"EMR.1",       // primary nodes without public IPs
	"SageMaker.1", // notebooks without direct internet access
	"SSM.4",       // SSM documents not public
}

func publicExposureRule(e Evidence) bool {
	switch e.Scanner {
	case "prowler":
		if len(e.Categories) > 0 {
			return slices.Contains(e.Categories, "internet-exposed")
		}
		tokens := strings.Split(strings.ToLower(e.RuleID), "_")
		if slices.Contains(tokens, "block") || slices.Contains(tokens, "blocks") {
			return false
		}
		return slices.ContainsFunc(tokens, func(t string) bool {
			return t == "public" || t == "publicly" || t == "internet"
		})
	case "scoutsuite":
		id := strings.ToLower(e.RuleID)
		if strings.HasSuffix(id, "-to-all") {
			return true
		}
		return slices.ContainsFunc(strings.Split(id, "-"), func(t string) bool {
			return t == "public" || t == "publicly" || t == "world" || t == "allusers" || t == "internet"
		})
	case "aws-security-hub":
		gen := e.RuleID
		control := gen[strings.LastIndexByte(gen, '/')+1:]
		if strings.Contains(gen, "cis-aws-foundations-benchmark") {
			return control == "4.1" || control == "4.2"
		}
		return strings.Contains(gen, "aws-foundational-security-best-practices") &&
			slices.Contains(publicFSBPControls, control)
	}
	return false
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
