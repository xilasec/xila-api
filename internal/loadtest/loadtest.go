// Package loadtest seeds a realistic multi-tenant dataset directly through the
// product's own repositories (org/team/project/user, plus a bulk COPY for the
// findings themselves — the one place a one-row-at-a-time repository call
// would dominate the measurement instead of the thing being measured) and
// measures the hot paths at scale: ingest throughput through the real
// scan.Service, and list/portfolio/component HTTP latency. See docs/SCALE.md
// for how to run it and the numbers it produced.
//
// The dataset deliberately mirrors a real portfolio rather than one giant flat
// table: a handful of "monorepo" projects carry most of the findings (so a
// single project's dedup/list queries are exercised at real scale), and many
// small projects carry the rest (so portfolio-wide and cross-project queries
// see a realistic number of rows to scan).
package loadtest

import "fmt"

// Config sizes the seeded dataset.
type Config struct {
	Orgs        int
	TeamsPerOrg int

	// BigProjects each get BigProjectFindings findings — the "monorepo" tier
	// that makes a single project's dedup/list cost visible at scale.
	BigProjects        int
	BigProjectFindings int

	// SmallProjects each get SmallProjectFindings findings, spread evenly
	// across every seeded team — the long tail of a real portfolio.
	SmallProjects        int
	SmallProjectFindings int

	// ComponentsPerProject is the SBOM component count seeded for every
	// project (big and small), for the /components endpoints.
	ComponentsPerProject int

	// Scanners findings round-robin across; len(Scanners) >= 2 is required for
	// the dataset to contain cross-tool CVE overlap (what Deduplicate groups).
	Scanners []string

	// AdminEmail/AdminPassword bootstrap the instance's first user (owner +
	// admin, bypasses RBAC) so the HTTP benchmarks can authenticate.
	AdminEmail    string
	AdminPassword string

	// BatchSize is the COPY chunk size for bulk-loading findings.
	BatchSize int
}

// DefaultConfig targets just over 1,000,000 findings: 5 big projects at 100k
// each, 600 small projects at 850 each, across 150 teams in 30 orgs.
func DefaultConfig() Config {
	return Config{
		Orgs:                 30,
		TeamsPerOrg:          5,
		BigProjects:          5,
		BigProjectFindings:   100_000,
		SmallProjects:        600,
		SmallProjectFindings: 850,
		ComponentsPerProject: 200,
		Scanners:             []string{"trivy", "grype", "osv"},
		AdminEmail:           "loadtest-admin@xila.local",
		AdminPassword:        "loadtest-password-CHANGE-ME-123",
		BatchSize:            20_000,
	}
}

// Teams is the total number of teams the config seeds.
func (c Config) Teams() int { return c.Orgs * c.TeamsPerOrg }

// TotalProjects is the total number of projects the config seeds.
func (c Config) TotalProjects() int { return c.BigProjects + c.SmallProjects }

// TotalFindings is the total number of findings the config seeds.
func (c Config) TotalFindings() int {
	return c.BigProjects*c.BigProjectFindings + c.SmallProjects*c.SmallProjectFindings
}

// String summarizes the dataset shape for logging.
func (c Config) String() string {
	return fmt.Sprintf("%d orgs, %d teams, %d projects (%d big x %d, %d small x %d) = %d findings, %d components/project",
		c.Orgs, c.Teams(), c.TotalProjects(), c.BigProjects, c.BigProjectFindings, c.SmallProjects, c.SmallProjectFindings,
		c.TotalFindings(), c.ComponentsPerProject)
}
