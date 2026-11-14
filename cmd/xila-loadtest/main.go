// Command xila-loadtest seeds a large, realistic dataset directly through the
// product's repositories and measures the hot paths at scale: ingest
// throughput through the real scan service, and HTTP latency of the main list
// endpoints. See docs/SCALE.md for how to run it and the numbers it produced.
//
//	xila-loadtest seed         --dsn <postgres dsn> [sizing flags]
//	xila-loadtest http-bench   --base-url <http://host:port> [--requests N]
//	xila-loadtest ingest-bench --base-url <http://host:port> --project <id> [--scans N --findings-per-scan N]
//	xila-loadtest explain      --dsn <postgres dsn> --query <key> [--project <id>]
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/xilasec/xila-api/internal/database"
	"github.com/xilasec/xila-api/internal/loadtest"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "seed":
		err = runSeed(args)
	case "http-bench":
		err = runHTTPBench(args)
	case "ingest-bench":
		err = runIngestBench(args)
	case "explain":
		err = runExplain(args)
	case "-h", "--help", "help":
		fmt.Println(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n%s\n", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

const usage = `xila-loadtest — scale/load-test harness for the Xila API (see docs/SCALE.md)

Commands:
  seed         migrate + seed a dataset directly through the repositories
  http-bench   measure p50/p95/p99 latency of the list/portfolio/component endpoints
  ingest-bench measure ingest throughput through the real scan service (HTTP upload)
  explain      run EXPLAIN (ANALYZE, BUFFERS) for one of the slow-query keys

Run a subcommand with -h for its flags.`

func runSeed(args []string) error {
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	dsn := fs.String("dsn", "", "Postgres DSN to migrate and seed (required)")
	orgs := fs.Int("orgs", loadtest.DefaultConfig().Orgs, "number of organizations")
	teamsPerOrg := fs.Int("teams-per-org", loadtest.DefaultConfig().TeamsPerOrg, "teams per org")
	bigProjects := fs.Int("big-projects", loadtest.DefaultConfig().BigProjects, "number of large 'monorepo' projects")
	bigFindings := fs.Int("big-findings", loadtest.DefaultConfig().BigProjectFindings, "findings per large project")
	smallProjects := fs.Int("small-projects", loadtest.DefaultConfig().SmallProjects, "number of small projects")
	smallFindings := fs.Int("small-findings", loadtest.DefaultConfig().SmallProjectFindings, "findings per small project")
	components := fs.Int("components-per-project", loadtest.DefaultConfig().ComponentsPerProject, "SBOM components per project")
	adminEmail := fs.String("admin-email", loadtest.DefaultConfig().AdminEmail, "bootstrap admin email")
	adminPassword := fs.String("admin-password", loadtest.DefaultConfig().AdminPassword, "bootstrap admin password")
	batch := fs.Int("batch-size", loadtest.DefaultConfig().BatchSize, "COPY chunk size for bulk-loading findings")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dsn == "" {
		return fmt.Errorf("--dsn is required")
	}
	cfg := loadtest.Config{
		Orgs: *orgs, TeamsPerOrg: *teamsPerOrg,
		BigProjects: *bigProjects, BigProjectFindings: *bigFindings,
		SmallProjects: *smallProjects, SmallProjectFindings: *smallFindings,
		ComponentsPerProject: *components,
		Scanners:             loadtest.DefaultConfig().Scanners,
		AdminEmail:           *adminEmail,
		AdminPassword:        *adminPassword,
		BatchSize:            *batch,
	}
	fmt.Println("dataset:", cfg.String())

	fmt.Println("running migrations...")
	if err := database.Migrate(*dsn); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	ctx := context.Background()
	pool, err := database.Connect(ctx, *dsn, database.DefaultPoolConfig())
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer pool.Close()

	res, err := loadtest.Seed(ctx, pool, cfg, func(format string, a ...any) {
		fmt.Printf("["+time.Now().Format(time.TimeOnly)+"] "+format+"\n", a...)
	})
	if err != nil {
		return err
	}
	fmt.Printf("done in %s: %d findings, %d components across %d projects\n",
		res.Elapsed.Round(time.Second), res.TotalFindings, res.TotalComponents, len(res.Projects))
	fmt.Printf("admin login: %s / %s\n", res.AdminEmail, res.AdminPassword)
	for _, p := range res.Projects {
		if p.Big {
			fmt.Printf("big project: id=%s findings=%d\n", p.ID, p.Findings)
		}
	}
	return nil
}
