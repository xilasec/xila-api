package vulnmatch_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/scanner"
	"github.com/xilasec/xila-api/internal/vulnmatch"
)

// TestFeedRuleMutesOnlyOnHealthyRuns: a mute rule keeps an advisory from
// becoming a finding, and the finding it already produced closes — on a
// complete run. When a source failed, nothing is closed, mute or not.
func TestFeedRuleMutesOnlyOnHealthyRuns(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findingRepo := finding.NewRepository(pool)
	ingest := scan.NewService(scan.NewRepository(pool), findingRepo, project.NewRepository(pool),
		scanner.NewRegistry(scanner.NewTrivy()), nil, nil, scan.NewRepository(pool))

	var projectID, sbomID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-fr','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO sboms (project_id, artifact, version) VALUES ($1,'web','1') RETURNING id`,
		projectID).Scan(&sbomID); err != nil {
		t.Fatal(err)
	}
	const lodash, babel = "pkg:npm/lodash@4.17.20", "pkg:npm/%40babel/traverse@7.0.0"
	if _, err := pool.Exec(ctx, `INSERT INTO sbom_components (sbom_id, project_id, name, version, purl)
		VALUES ($1,$2,'lodash','4.17.20',$3), ($1,$2,'traverse','7.0.0',$4)`, sbomID, projectID, lodash, babel); err != nil {
		t.Fatal(err)
	}

	osv := &stubSource{byPurl: map[string][]vulnmatch.Vuln{
		lodash: {{ID: "GHSA-35jh-r3h4-6jhm", Summary: "Command Injection", Severity: domain.SeverityHigh, CVEs: []string{"CVE-2021-23337"}}},
		babel:  {{ID: "GHSA-67hx-6x53-jw92", Summary: "Arbitrary code", Severity: domain.SeverityCritical}},
	}}
	gh := &flakySource{}
	multi := vulnmatch.NewMultiSource(
		vulnmatch.NamedSource{Name: vulnmatch.SourceOSV, Source: osv},
		vulnmatch.NamedSource{Name: vulnmatch.SourceGitHub, Source: gh},
	)
	rules := vulnmatch.NewFeedRuleRepository(pool)
	svc := vulnmatch.NewService(sbom.NewRepository(pool), ingest, multi).WithFeedRules(rules, findingRepo)

	// A tagging rule: the finding carries the tag and names the rule.
	tagRule := vulnmatch.FeedRule{Name: "tag babel", Enabled: true, PackageGlob: "@babel/*", Action: vulnmatch.FeedAddTags, Tags: []string{"toolchain"}}
	if err := tagRule.Validate(); err != nil {
		t.Fatal(err)
	}
	tagRule, err := rules.Create(ctx, tagRule, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := svc.Match(ctx); err != nil || n != 2 {
		t.Fatalf("first match = %d, %v", n, err)
	}
	byRule := func() map[string]finding.Finding {
		list, err := findingRepo.List(ctx, finding.Filter{ProjectID: projectID})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]finding.Finding{}
		for _, f := range list {
			out[f.RuleID] = f
		}
		return out
	}
	got := byRule()
	b := got["GHSA-67hx-6x53-jw92"]
	if !slices.Equal(b.Tags, []string{"toolchain"}) {
		t.Errorf("babel tags = %v, want the rule's tag", b.Tags)
	}
	refs, _ := b.Metadata["feed_rules"].([]any)
	if len(refs) != 1 || refs[0].(map[string]any)["id"] != tagRule.ID {
		t.Errorf("metadata.feed_rules = %v, want the tag rule", b.Metadata["feed_rules"])
	}
	lodashID := got["GHSA-35jh-r3h4-6jhm"].ID

	// An admin mutes the lodash advisory by an id glob.
	mute := vulnmatch.FeedRule{Name: "accepted lodash", Enabled: true, IDGlob: "GHSA-35jh-*", Action: vulnmatch.FeedMute}
	if err := mute.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := rules.Create(ctx, mute, nil); err != nil {
		t.Fatal(err)
	}

	// A run where GitHub failed: partial → nothing closes, muted or not.
	gh.err = errors.New("github down")
	n, err := svc.Match(ctx)
	if _, partial := errors.AsType[*vulnmatch.PartialError](err); !partial {
		t.Fatalf("match with a failed source = %d, %v; want a partial error", n, err)
	}
	if f, _ := findingRepo.Get(ctx, lodashID); f.Status != domain.FindingOpen {
		t.Fatalf("after a partial run the muted finding is %q — a failed source must never close findings", f.Status)
	}

	// A healthy run: the muted advisory is missing from the complete set and
	// its finding auto-closes; the other stays open.
	gh.err = nil
	if _, err := svc.Match(ctx); err != nil {
		t.Fatal(err)
	}
	if f, _ := findingRepo.Get(ctx, lodashID); f.Status != domain.FindingRemediated {
		t.Errorf("after a healthy run the muted finding is %q, want remediated", f.Status)
	}
	if f := byRule()["GHSA-67hx-6x53-jw92"]; f.Status != domain.FindingOpen {
		t.Errorf("unmuted finding = %q, want open", f.Status)
	}
	// And the muted advisory isn't recorded against the snapshot either.
	var snap int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sbom_vulns WHERE vuln_id = 'GHSA-35jh-r3h4-6jhm'`).Scan(&snap); err != nil || snap != 0 {
		t.Errorf("muted advisory snapshot rows = %d, %v", snap, err)
	}
}

// flakySource answers nothing, or fails.
type flakySource struct{ err error }

func (f *flakySource) Query(context.Context, []string) (map[string][]vulnmatch.Vuln, error) {
	if f.err != nil {
		return nil, f.err
	}
	return map[string][]vulnmatch.Vuln{}, nil
}

func TestJVNMirrorEnrichesMatches(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := vulnmatch.NewJVNRepository(pool)
	if err := repo.Upsert(ctx, []vulnmatch.JVNEntry{
		{ID: "JVNDB-2021-000001", CVEs: []string{"CVE-2021-44228"}, CPEs: []string{}},
		{ID: "JVNDB-2021-000002", CVEs: []string{"CVE-2021-1", "CVE-2021-44228"}, CPEs: []string{}},
	}); err != nil {
		t.Fatal(err)
	}
	m, err := vulnmatch.NewSources([]string{"private", "jvn"}, vulnmatch.SourceDeps{
		Private: vulnmatch.NewAdvisoryRepository(pool, ""), JVN: repo,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(m.Names(), []string{"private", "jvn"}) {
		t.Errorf("names = %v", m.Names())
	}
	out := m.Enrich(ctx, map[string][]vulnmatch.Vuln{
		"pkg:maven/x@1": {{ID: "GHSA-jfh8", CVEs: []string{"CVE-2021-44228"}}},
	})
	if v := out["pkg:maven/x@1"][0]; !slices.Equal(v.Aliases, []string{"JVNDB-2021-000001", "JVNDB-2021-000002"}) {
		t.Errorf("aliases = %v", v.Aliases)
	}
	if _, err := vulnmatch.NewSources([]string{"jvn"}, vulnmatch.SourceDeps{JVN: repo}); err == nil {
		t.Error("jvn alone matches nothing; it must be refused as the only source")
	}
}
