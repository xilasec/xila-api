package connector

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/securityhub"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"net/http"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// AWS Security Hub CSPM, per its official API reference
// (https://docs.aws.amazon.com/securityhub/latest/APIReference/API_GetFindings.html)
// and the AWS Security Finding Format
// (https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html):
//
//   - GetFindings, filtered to RecordState ACTIVE and WorkflowStatus not
//     SUPPRESSED/RESOLVED (an optional remote_project filter narrows further by
//     ProductName and/or SeverityLabel), paged with NextToken. Security Hub is
//     regional: base_url holds a comma-separated region list, and every region
//     is queried and merged into one pull.
//   - Auth is the AWS SDK default credential chain (environment, shared
//     config/credentials file, EC2/ECS/EKS instance roles) unless static keys
//     are sealed in the token, optionally followed by one STS AssumeRole if
//     role_arn is set.
//
// A finding whose Workflow.Status is SUPPRESSED carries that over as a remote
// triage verdict (an analyst already dismissed it in Security Hub); RESOLVED
// findings aren't fetched (RecordState ACTIVE excludes them), so the next pull
// auto-closes them.
const awsSessionName = "xila-security-hub"

type awsSecurityHub struct {
	regions                      []string
	roleARN, filter              string
	accessKeyID, secretAccessKey string
	sessionToken                 string
	hc                           *http.Client
	// endpoint/stsEndpoint override the regional Security Hub / global STS
	// endpoints in tests; empty (the zero value) in production, where the SDK
	// resolves them from the region.
	endpoint, stsEndpoint string
}

type awsCredentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

func parseAWSCredentials(token string) (awsCredentials, error) {
	var c awsCredentials
	if err := json.Unmarshal([]byte(token), &c); err != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" {
		return awsCredentials{}, invalid(`token must be JSON {"access_key_id": "...", "secret_access_key": "...", "session_token": "..." (optional)}`)
	}
	return c, nil
}

// awsConfig resolves the credentials for region: the sealed static keys if
// given, else the AWS SDK's own default credential chain; then, if role_arn is
// set, one STS AssumeRole swaps them for temporary role credentials.
func (a *awsSecurityHub) awsConfig(ctx context.Context, region string) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{config.WithRegion(region), config.WithHTTPClient(a.hc)}
	if a.accessKeyID != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(a.accessKeyID, a.secretAccessKey, a.sessionToken)))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, remoteErr("aws: resolve credentials: %v", err)
	}
	if a.roleARN == "" {
		return cfg, nil
	}
	stsClient := sts.NewFromConfig(cfg, func(o *sts.Options) {
		o.HTTPClient = a.hc
		if a.stsEndpoint != "" {
			o.BaseEndpoint = aws.String(a.stsEndpoint)
		}
	})
	out, err := stsClient.AssumeRole(ctx, &sts.AssumeRoleInput{
		RoleArn:         aws.String(a.roleARN),
		RoleSessionName: aws.String(awsSessionName),
	})
	if err != nil {
		return aws.Config{}, remoteErr("aws: assume role %s: %v", a.roleARN, err)
	}
	cfg.Credentials = credentials.NewStaticCredentialsProvider(
		aws.ToString(out.Credentials.AccessKeyId), aws.ToString(out.Credentials.SecretAccessKey), aws.ToString(out.Credentials.SessionToken))
	return cfg, nil
}

func (a *awsSecurityHub) client(ctx context.Context, region string) (*securityhub.Client, error) {
	cfg, err := a.awsConfig(ctx, region)
	if err != nil {
		return nil, err
	}
	return securityhub.NewFromConfig(cfg, func(o *securityhub.Options) {
		o.HTTPClient = a.hc
		if a.endpoint != "" {
			o.BaseEndpoint = aws.String(a.endpoint)
		}
	}), nil
}

// findingFilters is RecordState ACTIVE and WorkflowStatus not SUPPRESSED or
// RESOLVED, narrowed by the optional "product=...,severity=..." filter.
// Multiple NOT_EQUALS values on the same field are ANDed (exclude every listed
// value); multiple EQUALS values are ORed, so repeating "severity=" admits
// several labels.
func (a *awsSecurityHub) findingFilters() *types.AwsSecurityFindingFilters {
	f := &types.AwsSecurityFindingFilters{
		RecordState: []types.StringFilter{
			{Value: aws.String("ACTIVE"), Comparison: types.StringFilterComparisonEquals},
		},
		WorkflowStatus: []types.StringFilter{
			{Value: aws.String("SUPPRESSED"), Comparison: types.StringFilterComparisonNotEquals},
			{Value: aws.String("RESOLVED"), Comparison: types.StringFilterComparisonNotEquals},
		},
	}
	if a.filter == "" {
		return f
	}
	for kv := range strings.SplitSeq(a.filter, ",") {
		key, val, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		sf := types.StringFilter{Value: aws.String(val), Comparison: types.StringFilterComparisonEquals}
		switch key {
		case "product":
			f.ProductName = append(f.ProductName, sf)
		case "severity":
			f.SeverityLabel = append(f.SeverityLabel, sf)
		}
	}
	return f
}

// Check queries the first region for one finding, so a bad key, region or
// role fails fast.
func (a *awsSecurityHub) Check(ctx context.Context) (string, error) {
	cl, err := a.client(ctx, a.regions[0])
	if err != nil {
		return "", err
	}
	if _, err := cl.GetFindings(ctx, &securityhub.GetFindingsInput{MaxResults: aws.Int32(1)}); err != nil {
		return "", remoteErr("aws securityhub get-findings: %v", err)
	}
	return "AWS Security Hub (" + strconv.Itoa(len(a.regions)) + " region(s))", nil
}

func (a *awsSecurityHub) Fetch(ctx context.Context) ([]finding.Finding, error) {
	out := []finding.Finding{}
	for _, region := range a.regions {
		cl, err := a.client(ctx, region)
		if err != nil {
			return nil, err
		}
		var next *string
		for page := 0; ; page++ {
			if page >= maxPages {
				return nil, remoteErr("aws securityhub: more than %d pages of findings in %s", maxPages, region)
			}
			resp, err := cl.GetFindings(ctx, &securityhub.GetFindingsInput{
				Filters: a.findingFilters(), MaxResults: aws.Int32(100), NextToken: next,
			})
			if err != nil {
				return nil, remoteErr("aws securityhub get-findings (%s): %v", region, err)
			}
			for _, f := range resp.Findings {
				out = append(out, awsToFinding(f))
			}
			if resp.NextToken == nil || *resp.NextToken == "" {
				break
			}
			next = resp.NextToken
		}
	}
	return uniqueByFingerprint(out), nil
}

// Category is Cloud (CSPM) by default; a container-related resource narrows
// it, and any finding carrying ASFF Vulnerabilities (e.g. Inspector) is SCA.
func (a *awsSecurityHub) Category(fs []finding.Finding) domain.Category {
	return mostCommonCategory(fs, domain.CategoryCloud)
}

func awsResourceCategory(resourceType string) domain.Category {
	switch {
	case strings.Contains(resourceType, "Container") || strings.Contains(resourceType, "Ecs") || strings.Contains(resourceType, "Eks"):
		return domain.CategoryContainer
	}
	return domain.CategoryCloud
}

func awsToFinding(f types.AwsSecurityFinding) finding.Finding {
	id := aws.ToString(f.Id)
	sev := domain.SeverityInfo
	if f.Severity != nil {
		if s, ok := mapSeverity(string(f.Severity.Label)); ok {
			sev = s
		}
	}
	ruleID := aws.ToString(f.GeneratorId)
	if f.Compliance != nil && aws.ToString(f.Compliance.SecurityControlId) != "" {
		ruleID = aws.ToString(f.Compliance.SecurityControlId)
	}
	category := domain.CategoryCloud
	arn := ""
	if len(f.Resources) > 0 {
		arn = aws.ToString(f.Resources[0].Id)
		category = awsResourceCategory(aws.ToString(f.Resources[0].Type))
	}
	if len(f.Vulnerabilities) > 0 {
		category = domain.CategorySCA
	}
	cves := []string{}
	pkg := ""
	for _, v := range f.Vulnerabilities {
		cves = addCVE(cves, aws.ToString(v.Id))
		if pkg == "" {
			for _, p := range v.VulnerablePackages {
				pkg = aws.ToString(p.Name)
				break
			}
		}
	}
	desc := aws.ToString(f.Description)
	if f.Remediation != nil && f.Remediation.Recommendation != nil {
		desc = withSection(desc, "Remediation", aws.ToString(f.Remediation.Recommendation.Text))
	}
	meta := map[string]any{"source": "aws-security-hub", "finding_id": id, "aws_account_id": aws.ToString(f.AwsAccountId)}
	if arn != "" {
		meta["resource_arn"] = arn
	}
	if f.Workflow != nil {
		meta["workflow_status"] = string(f.Workflow.Status)
		if f.Workflow.Status == types.WorkflowStatusSuppressed {
			meta["remote_triage"] = string(domain.FindingFalsePositive)
			meta["remote_triage_reason"] = "AWS Security Hub: workflow suppressed"
		}
	}
	return finding.Finding{
		Fingerprint: fingerprint(KindAWSSecurityHub, id),
		Category:    category,
		RuleID:      ruleID,
		Title:       aws.ToString(f.Title),
		Description: desc,
		Severity:    sev,
		CVE:         cves,
		PackageName: pkg,
		FilePath:    arn,
		Metadata:    meta,
	}
}
