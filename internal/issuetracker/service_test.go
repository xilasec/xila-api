package issuetracker

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

func TestInputNormalize(t *testing.T) {
	off := false
	cases := []struct {
		name    string
		in      Input
		want    Tracker
		wantErr string
	}{
		{
			name: "github defaults",
			in:   Input{Kind: "GitHub", Target: " acme/web ", Labels: []string{"security", " security ", ""}},
			want: Tracker{ProjectID: "p", Kind: KindGitHub, BaseURL: "https://api.github.com", Target: "acme/web",
				IssueType: "Bug", DoneTransition: "Done", ReopenTransition: "To Do",
				MinSeverity: domain.SeverityHigh, Enabled: true, Labels: []string{"security"}},
		},
		{
			name: "gitlab self-managed, path target, disabled",
			in: Input{Kind: KindGitLab, BaseURL: "https://git.acme.io/", Target: "group/sub/web",
				MinSeverity: domain.SeverityMedium, AutoCreate: true, Enabled: &off},
			want: Tracker{ProjectID: "p", Kind: KindGitLab, BaseURL: "https://git.acme.io", Target: "group/sub/web",
				IssueType: "Bug", DoneTransition: "Done", ReopenTransition: "To Do",
				MinSeverity: domain.SeverityMedium, AutoCreate: true, Enabled: false, Labels: []string{}},
		},
		{
			name: "jira with workflow names",
			in: Input{Kind: KindJira, BaseURL: "https://acme.atlassian.net", Target: "SEC", JiraEmail: " bot@acme.io ",
				IssueType: "Vulnerability", DoneTransition: "Resolve", ReopenTransition: "Reopen", MinSeverity: domain.SeverityCritical},
			want: Tracker{ProjectID: "p", Kind: KindJira, BaseURL: "https://acme.atlassian.net", Target: "SEC",
				JiraEmail: "bot@acme.io", IssueType: "Vulnerability", DoneTransition: "Resolve", ReopenTransition: "Reopen",
				MinSeverity: domain.SeverityCritical, Enabled: true, Labels: []string{}},
		},
		{
			name: "azure-devops with work item type",
			in: Input{Kind: KindAzureDevOps, BaseURL: "https://dev.azure.com/acme/", Target: "WebApp", IssueType: "Task",
				DoneTransition: "Resolved", ReopenTransition: "New"},
			want: Tracker{ProjectID: "p", Kind: KindAzureDevOps, BaseURL: "https://dev.azure.com/acme", Target: "WebApp",
				IssueType: "Task", DoneTransition: "Resolved", ReopenTransition: "New",
				MinSeverity: domain.SeverityHigh, Enabled: true, Labels: []string{}},
		},
		{
			name: "azure-devops default state values",
			in:   Input{Kind: KindAzureDevOps, BaseURL: "https://tfs.acme.local/DefaultCollection", Target: "WebApp"},
			want: Tracker{ProjectID: "p", Kind: KindAzureDevOps, BaseURL: "https://tfs.acme.local/DefaultCollection", Target: "WebApp",
				IssueType: "Bug", DoneTransition: "Closed", ReopenTransition: "Active",
				MinSeverity: domain.SeverityHigh, Enabled: true, Labels: []string{}},
		},
		{
			name: "linear defaults",
			in:   Input{Kind: KindLinear, Target: "team-eng"},
			want: Tracker{ProjectID: "p", Kind: KindLinear, BaseURL: "https://api.linear.app", Target: "team-eng",
				IssueType: "Bug", DoneTransition: "completed", ReopenTransition: "unstarted",
				MinSeverity: domain.SeverityHigh, Enabled: true, Labels: []string{}},
		},
		{
			name: "servicenow defaults to the incident table",
			in:   Input{Kind: KindServiceNow, BaseURL: "https://acme.service-now.com", AuthUser: " bot "},
			want: Tracker{ProjectID: "p", Kind: KindServiceNow, BaseURL: "https://acme.service-now.com", Target: "incident",
				AuthUser: "bot", IssueType: "Bug", DoneTransition: "Resolved", ReopenTransition: "New",
				MinSeverity: domain.SeverityHigh, Enabled: true, Labels: []string{}},
		},
		{name: "unknown kind", in: Input{Kind: "trello", Target: "x"}, wantErr: "kind must be"},
		{name: "jira needs a url", in: Input{Kind: KindJira, Target: "SEC"}, wantErr: "base_url is required"},
		{name: "bad scheme", in: Input{Kind: KindGitHub, BaseURL: "file:///etc", Target: "a/b"}, wantErr: "http(s) URL"},
		{name: "missing target", in: Input{Kind: KindGitLab}, wantErr: "target is required"},
		{name: "github target", in: Input{Kind: KindGitHub, Target: "a/b/c"}, wantErr: "owner/repo"},
		{name: "jira target", in: Input{Kind: KindJira, BaseURL: "https://j.io", Target: "SEC/1"}, wantErr: "project key"},
		{name: "azure-devops needs a url", in: Input{Kind: KindAzureDevOps, Target: "WebApp"}, wantErr: "base_url is required"},
		{name: "azure-devops target", in: Input{Kind: KindAzureDevOps, BaseURL: "https://dev.azure.com/acme", Target: "a/b"}, wantErr: "project name"},
		{name: "linear target", in: Input{Kind: KindLinear, Target: "team eng"}, wantErr: "team id"},
		{name: "servicenow needs a url", in: Input{Kind: KindServiceNow, Target: "incident"}, wantErr: "base_url is required"},
		{name: "servicenow target", in: Input{Kind: KindServiceNow, BaseURL: "https://acme.service-now.com", Target: "a/b"}, wantErr: "table name"},
		{name: "bad severity", in: Input{Kind: KindGitHub, Target: "a/b", MinSeverity: "urgent"}, wantErr: "min_severity"},
		{name: "comma label", in: Input{Kind: KindGitHub, Target: "a/b", Labels: []string{"a,b"}}, wantErr: "labels"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.in.Normalize("p")
			if c.wantErr != "" {
				var verr ValidationError
				if !errors.As(err, &verr) || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want ValidationError containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("got  %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestBuildIssue(t *testing.T) {
	cwe, line := 89, 12
	cvss, epss := 9.8, 0.4321
	f := finding.Finding{
		ID: "f-1", Title: "SQL injection in pkgA", Description: "Unsanitized input reaches a query.",
		Severity: domain.SeverityCritical, Scanner: "trivy", RuleID: "CVE-2024-1",
		PackageName: "pkgA", PackageVersion: "1.0", FixedVersion: "1.1",
		CVE: []string{"CVE-2024-1", "CVE-2024-2"}, CWE: &cwe, CVSS: &cvss, EPSS: &epss, KEV: true,
		FilePath: "go.mod", Line: &line, URL: "https://avd.aquasec.com/nvd/cve-2024-1",
	}
	got := BuildIssue(f, []string{"security"}, "https://xila.example.com")
	want := Issue{
		Title: "[critical] SQL injection in pkgA",
		Body: "Unsanitized input reaches a query.\n\n" +
			"Severity: critical\n" +
			"Scanner: trivy\n" +
			"Rule: CVE-2024-1\n" +
			"Package: pkgA@1.0\n" +
			"Fixed version: 1.1\n" +
			"CVEs: CVE-2024-1, CVE-2024-2\n" +
			"CWE: CWE-89\n" +
			"CVSS: 9.8\n" +
			"EPSS: 0.432 (43.2% chance of exploitation in 30 days)\n" +
			"Known exploited (CISA KEV): yes\n" +
			"Location: go.mod:12\n" +
			"Reference: https://avd.aquasec.com/nvd/cve-2024-1\n" +
			"\nView in Xila: https://xila.example.com/findings/f-1\n",
		Labels: []string{"security"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %#v\nwant %#v", got, want)
	}

	// Sparse finding, no public URL: only what's known, and no link back.
	minimal := BuildIssue(finding.Finding{ID: "f-2", Title: "Leaked key", Severity: domain.SeverityHigh, Scanner: "gitleaks"}, nil, "")
	if minimal.Body != "Severity: high\nScanner: gitleaks\nKnown exploited (CISA KEV): no\n" {
		t.Errorf("minimal body = %q", minimal.Body)
	}

	long := BuildIssue(finding.Finding{Title: strings.Repeat("x", 400), Severity: domain.SeverityLow}, nil, "")
	if n := len([]rune(long.Title)); n != maxTitle || !strings.HasSuffix(long.Title, "…") {
		t.Errorf("long title = %d runes, want %d ending in …", n, maxTitle)
	}
}
