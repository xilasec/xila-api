package loadtest

import (
	"fmt"
	"math/rand/v2" // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used -- seeded on purpose: a reproducible load-test dataset, never secrets
	"time"

	"github.com/xilasec/xila-api/internal/domain"
)

// findingColumns is the explicit COPY column list for bulk-loading findings.
// "search" is a generated column (never listed); everything else not listed
// here (first_scan_id, last_scan_id, sla_*, assignee_id, custom, …) is left at
// its table default — this is historical backlog, not a scan's output, so it
// carries no scan association. The findings_sla / findings_0version triggers
// still run on every row exactly as they would on a real insert.
var findingColumns = []string{
	"project_id", "fingerprint", "scanner", "category", "rule_id", "title", "severity",
	"cve", "package_name", "package_version", "purl", "status", "priority",
	"cvss", "epss", "kev", "kev_sources", "exploit_maturity", "version_id",
	"first_seen_at", "last_seen_at", "dep_direct", "dep_scope", "metadata", "tags",
}

var statusPool = []string{"open", "open", "open", "confirmed", "confirmed", "remediated", "false_positive", "risk_accepted", "wont_fix"}
var severityPool = []domain.Severity{domain.SeverityLow, domain.SeverityLow, domain.SeverityMedium, domain.SeverityMedium, domain.SeverityMedium, domain.SeverityHigh, domain.SeverityHigh, domain.SeverityCritical}
var depScopePool = []domain.DepScope{domain.DepScopeUnknown, domain.DepScopeRuntime, domain.DepScopeRuntime, domain.DepScopeRuntime, domain.DepScopeDev, domain.DepScopeOptional}

// findingRows generates n deterministic COPY-ready rows for one project/version,
// round-robined across scanners so roughly 1/len(scanners) collide on
// (cve, package) across tools, and fingerprinted from seed so rows from
// different calls (different projects) never collide. priority is computed
// with the same domain.Priority the application writes on every real upsert.
func findingRows(projectID, versionID string, n, cvePool int, scanners []string, seed uint64) [][]any {
	rng := rand.New(rand.NewPCG(seed, seed^0x9E3779B97F4A7C15))
	now := time.Now()
	rows := make([][]any, n)
	for i := range n {
		pkgIdx := rng.IntN(max(cvePool, 1))
		scanner := scanners[i%len(scanners)]
		cve := fmt.Sprintf("CVE-%04d-%06d", 2015+pkgIdx%10, pkgIdx)
		pkg := fmt.Sprintf("pkg-%07d", pkgIdx)
		sev := severityPool[rng.IntN(len(severityPool))]

		kev := rng.Float64() < 0.03
		var epss *float32
		x := domain.Exploitability{KEV: kev}
		if rng.Float64() < 0.8 { // 20% of findings carry no EPSS score yet
			v := rng.Float64()
			if kev {
				v = 0.7 + 0.3*rng.Float64()
			}
			f := float32(v)
			epss = &f
			x.EPSS = v
		}
		switch {
		case kev:
			x.Maturity = domain.ExploitWeaponized
		case rng.Float64() < 0.05:
			x.Maturity = domain.ExploitWeaponized
		case rng.Float64() < 0.1:
			x.Maturity = domain.ExploitPoC
		}
		kevSources := []string{}
		if kev {
			kevSources = []string{domain.KEVCISA}
		}

		var directPtr *bool
		var direct any
		scope := depScopePool[rng.IntN(len(depScopePool))]
		switch {
		case rng.Float64() < 0.1: // 10% unknown reachability
		case rng.Float64() < 0.65:
			b := true
			directPtr, direct = &b, true
		default:
			b := false
			directPtr, direct = &b, false
		}
		reach := domain.Reachability{Direct: directPtr, Scope: scope}
		priority := domain.Priority(sev, x, reach, domain.ExposureUnknown)

		var cvss *float32
		if rng.Float64() < 0.7 {
			v := float32(2 + rng.Float64()*8)
			cvss = &v
		}

		firstSeen := now.Add(-time.Duration(rng.IntN(400*24)) * time.Hour)
		lastSeen := firstSeen.Add(time.Duration(rng.IntN(60*24)) * time.Hour)
		if lastSeen.After(now) {
			lastSeen = now
		}

		rows[i] = []any{
			projectID,
			fmt.Sprintf("lt-%d-%d", seed, i),
			scanner,
			"sca",
			cve,
			fmt.Sprintf("Vulnerable dependency %s (%s)", pkg, cve),
			string(sev),
			[]string{cve},
			pkg,
			fmt.Sprintf("1.%d.%d", pkgIdx%20, i%10),
			fmt.Sprintf("pkg:generic/%s@1.%d.%d", pkg, pkgIdx%20, i%10),
			statusPool[rng.IntN(len(statusPool))],
			float32(priority),
			cvss, epss, kev, kevSources, nullIfEmpty(string(x.Maturity)), versionID,
			firstSeen, lastSeen, direct, string(scope),
			[]byte("{}"), []string{},
		}
	}
	return rows
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
