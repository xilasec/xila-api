package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/access"
	"github.com/xilasec/xila-api/internal/account"
	"github.com/xilasec/xila-api/internal/aitriage"
	"github.com/xilasec/xila-api/internal/apitoken"
	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/asset"
	"github.com/xilasec/xila-api/internal/audit"
	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/badge"
	"github.com/xilasec/xila-api/internal/compliance"
	"github.com/xilasec/xila-api/internal/computed"
	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/connector"
	"github.com/xilasec/xila-api/internal/correlation"
	"github.com/xilasec/xila-api/internal/cra"
	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/customparser"
	"github.com/xilasec/xila-api/internal/database"
	"github.com/xilasec/xila-api/internal/demo"
	"github.com/xilasec/xila-api/internal/engagement"
	"github.com/xilasec/xila-api/internal/enrichment"
	"github.com/xilasec/xila-api/internal/evidence"
	"github.com/xilasec/xila-api/internal/exploitintel"
	"github.com/xilasec/xila-api/internal/feature"
	"github.com/xilasec/xila-api/internal/federation"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/findingtemplate"
	"github.com/xilasec/xila-api/internal/fixplan"
	"github.com/xilasec/xila-api/internal/gate"
	"github.com/xilasec/xila-api/internal/inbox"
	"github.com/xilasec/xila-api/internal/ingesthealth"
	"github.com/xilasec/xila-api/internal/issuetracker"
	"github.com/xilasec/xila-api/internal/ldap"
	"github.com/xilasec/xila-api/internal/leader"
	"github.com/xilasec/xila-api/internal/license"
	"github.com/xilasec/xila-api/internal/mcp"
	"github.com/xilasec/xila-api/internal/membership"
	"github.com/xilasec/xila-api/internal/metrics"
	"github.com/xilasec/xila-api/internal/netguard"
	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/objectstore"
	"github.com/xilasec/xila-api/internal/observability"
	"github.com/xilasec/xila-api/internal/oidc"
	"github.com/xilasec/xila-api/internal/org"
	"github.com/xilasec/xila-api/internal/pkgmeta"
	"github.com/xilasec/xila-api/internal/policy"
	"github.com/xilasec/xila-api/internal/portfolio"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/psirt"
	"github.com/xilasec/xila-api/internal/ratelimit"
	"github.com/xilasec/xila-api/internal/remediation"
	"github.com/xilasec/xila-api/internal/report"
	"github.com/xilasec/xila-api/internal/retention"
	"github.com/xilasec/xila-api/internal/rootcause"
	"github.com/xilasec/xila-api/internal/saml"
	"github.com/xilasec/xila-api/internal/sbom"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/scanner"
	"github.com/xilasec/xila-api/internal/scim"
	"github.com/xilasec/xila-api/internal/secretbox"
	"github.com/xilasec/xila-api/internal/server"
	"github.com/xilasec/xila-api/internal/serviceaccount"
	"github.com/xilasec/xila-api/internal/sla"
	"github.com/xilasec/xila-api/internal/sso"
	"github.com/xilasec/xila-api/internal/team"
	"github.com/xilasec/xila-api/internal/triage"
	"github.com/xilasec/xila-api/internal/user"
	"github.com/xilasec/xila-api/internal/vex"
	"github.com/xilasec/xila-api/internal/vulnmatch"
	"github.com/xilasec/xila-api/internal/vulnpolicy"
	"github.com/xilasec/xila-api/web"
)

// version is set at release build time (-ldflags "-X main.version=v1.2.3").
var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Println(version)
		return
	}
	// healthcheck lets a container probe the server without a shell or curl
	// (the runtime image is distroless): exit 0 when /health answers 200.
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(healthcheck())
	}
	// demo-seed populates a demo org/team/project with real sample findings
	// and an SBOM, for a 5-minute "see a finding" onboarding path.
	if len(os.Args) > 1 && os.Args[1] == "demo-seed" {
		os.Exit(demoSeedCmd(os.Args[2:]))
	}
	if err := run(); err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	// Every server-side request to a configured URL goes through netguard.
	netguard.SetDefault(netguard.Policy{
		AllowPrivate:  cfg.Security.OutboundAllowPrivate,
		AllowLoopback: cfg.Security.OutboundAllowLoopback,
		AllowedHosts:  cfg.Security.OutboundAllowedHosts,
	})

	rootCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Observability (traces, metrics, logs) via OpenTelemetry. Installs the
	// global slog logger, so do this before anything that logs.
	telemetry, err := observability.Setup(rootCtx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := telemetry.Shutdown(ctx); err != nil {
			slog.Error("observability shutdown failed", "error", err)
		}
	}()

	slog.Info("starting xila-api", "version", version, "env", cfg.Env,
		"cors", corsMode(cfg.Security.AllowedOrigins), "cookie_secure", cfg.Security.CookieSecure)
	for _, warn := range cfg.Warnings() {
		slog.Warn("production hardening", "advice", warn)
	}

	// Rotatable secrets (M10 10.2): every node re-reads any secret setting
	// that came from a reference or a NAME_FILE on SECRETS_REFRESH_INTERVAL
	// (0 = off) — not only the leader, since each node holds its own DB
	// connections, SMTP client, HTTP clients, etc.
	go cfg.Secrets.Run(rootCtx)

	// Database.
	db, err := database.Connect(rootCtx, cfg.DB.DSN(), database.PoolConfig{
		MaxConns:          cfg.DB.MaxConns,
		MinConns:          cfg.DB.MinConns,
		MaxConnLifetime:   cfg.DB.MaxConnLifetime,
		MaxConnIdleTime:   cfg.DB.MaxConnIdleTime,
		HealthCheckPeriod: cfg.DB.HealthCheckPeriod,
		StatementTimeout:  cfg.DB.StatementTimeout,
		PasswordGetter:    cfg.SecretGetter("DB_PASSWORD", cfg.DB.Password),
		// Wait out a database that is still starting (fresh install, both
		// restarted together) rather than crash-looping.
		StartupWait: time.Minute,
	})
	if err != nil {
		return err
	}
	defer db.Close()

	if err := database.Migrate(cfg.DB.DSN()); err != nil {
		return err
	}
	slog.Info("database migrations applied")

	// Reporting reads (portfolio, trends, reports): a read replica
	// (DB_READ_URL) and/or a tighter statement cap (DB_READ_STATEMENT_TIMEOUT)
	// in a pool of their own; otherwise the primary pool.
	readDB := db
	if cfg.DB.SeparateReadPool() {
		timeout := cfg.DB.ReadStatementTimeout
		if timeout == 0 {
			timeout = cfg.DB.StatementTimeout
		}
		readDB, err = database.Connect(rootCtx, cfg.DB.ReadDSN(), database.PoolConfig{
			MaxConns:          cfg.DB.ReadMaxConns,
			MinConns:          1,
			MaxConnLifetime:   cfg.DB.MaxConnLifetime,
			MaxConnIdleTime:   cfg.DB.MaxConnIdleTime,
			HealthCheckPeriod: cfg.DB.HealthCheckPeriod,
			StatementTimeout:  timeout,
			StartupWait:       time.Minute,
			// DB_READ_URL carries its own credentials (possibly a different
			// host/user entirely) and is out of scope for rotation; only the
			// primary's password applies here when there is no separate URL.
			PasswordGetter: readPasswordGetter(cfg),
		})
		if err != nil {
			return fmt.Errorf("reporting database: %w", err)
		}
		defer readDB.Close()
		slog.Info("reporting reads use their own pool", "replica", cfg.DB.ReadURL != "", "statement_timeout", timeout)
	}

	// The metric snapshot job makes a full pass over the findings: on a large
	// instance that outlasts DB_STATEMENT_TIMEOUT, so it gets a small pool
	// capped by DB_JOB_STATEMENT_TIMEOUT instead.
	jobDB, err := database.Connect(rootCtx, cfg.DB.DSN(), database.PoolConfig{
		MaxConns:          2,
		MinConns:          0,
		MaxConnLifetime:   cfg.DB.MaxConnLifetime,
		MaxConnIdleTime:   cfg.DB.MaxConnIdleTime,
		HealthCheckPeriod: cfg.DB.HealthCheckPeriod,
		StatementTimeout:  cfg.DB.JobStatementTimeout,
		StartupWait:       time.Minute,
		PasswordGetter:    cfg.SecretGetter("DB_PASSWORD", cfg.DB.Password),
	})
	if err != nil {
		return fmt.Errorf("job database pool: %w", err)
	}
	defer jobDB.Close()

	// Payload storage for queued ingest jobs (INGEST_PAYLOAD_STORE, M11 11.8):
	// postgres (scan_jobs.payload, the default) or s3 (any S3-compatible
	// object storage; scan_jobs keeps only a reference). Built here, with a
	// reachability check (HeadBucket), so a misconfigured bucket fails startup
	// rather than the first upload.
	var payloadStore scan.PayloadStore
	if cfg.Ingest.PayloadStore == "s3" {
		client, err := objectstore.New(rootCtx, objectstore.Config{
			Endpoint:        cfg.S3.Endpoint,
			Region:          cfg.S3.Region,
			Bucket:          cfg.S3.Bucket,
			Prefix:          cfg.S3.Prefix,
			AccessKeyID:     cfg.SecretGetter("S3_ACCESS_KEY_ID", cfg.S3.AccessKeyID),
			SecretAccessKey: cfg.SecretGetter("S3_SECRET_ACCESS_KEY", cfg.S3.SecretAccessKey),
			ForcePathStyle:  cfg.S3.ForcePathStyle,
		})
		if err != nil {
			return fmt.Errorf("S3 payload store: %w", err)
		}
		payloadStore = client
		slog.Info("ingest payload store ready", "backend", "s3", "bucket", cfg.S3.Bucket)
	}

	// Wire dependencies.
	userRepo := user.NewRepository(db)
	teamRepo := team.NewRepository(db)
	projectRepo := project.NewRepository(db)
	retentionSvc := retention.NewService(db, projectRepo, retention.Policy(cfg.Retention), payloadStore)
	auditRepo := audit.NewRepository(db)
	ingestHealth := ingesthealth.NewRepository(db)
	scanRepo := scan.NewRepository(db)
	findingRepo := finding.NewRepository(db)

	sbomRepo := sbom.NewRepository(db)
	pkgmetaRepo := pkgmeta.NewRepository(db)
	assetRepo := asset.NewRepository(db)
	assetSvc := asset.NewService(assetRepo, findingRepo)
	complianceRepo := compliance.NewRepository(db)
	// Reporting reads go to readDB (replica / capped pool); the snapshot job
	// writes through the primary.
	portfolioRepo := portfolio.NewRepository(readDB).WithSnapshots(cfg.PortfolioFromSnapshots)
	metricsRepo := metrics.NewRepository(jobDB)
	metricsReadRepo := metrics.NewRepository(readDB)
	portfolioParts := portfolio.NewRepository(jobDB)
	notifyRepo := notify.NewRepository(db)
	inboxRepo := inbox.NewRepository(db)
	features := feature.NewStore(db, feature.Unavailable(cfg)...)
	notifySvc := notify.NewService(notifyRepo, notify.SMTPConfig(cfg.SMTP)).WithFeatures(features).WithInbox(inboxRepo).
		WithSMTPPassword(cfg.SecretGetter("SMTP_PASSWORD", cfg.SMTP.Password))
	notifySvc.SetDeliveryPolicy(notify.DeliveryPolicy{
		MaxAttempts: cfg.Notify.MaxAttempts, RetryBase: cfg.Notify.RetryBase,
		RetryMax: cfg.Notify.RetryMax, Retention: cfg.Notify.Retention,
	})
	membershipRepo := membership.NewRepository(db)
	orgRepo := org.NewRepository(db)

	triageRepo := triage.NewRepository(db)
	gateRepo := gate.NewRepository(db)
	slaRepo := sla.NewRepository(db)
	slaSvc := sla.NewService(slaRepo, notifySvc)
	integrationKey, err := cfg.IntegrationKey()
	if err != nil {
		return err
	}
	integrationPrevious, err := cfg.IntegrationPreviousKeys()
	if err != nil {
		return err
	}
	trackerCipher, err := secretbox.NewKeyring(integrationKey, integrationPrevious)
	if err != nil {
		return err
	}
	notifySvc.SetSecretCipher(trackerCipher) // webhook signing secrets
	issueSvc := issuetracker.NewService(issuetracker.NewRepository(db), findingRepo, trackerCipher, cfg.PublicURL)
	// Remediation actions: grouped after each ingest's dedup (a follow-up
	// pass), swept on REMEDIATION_SWEEP_INTERVAL; their tickets sync with the
	// issue tracker's run.
	remediationRepo := remediation.NewRepository(db)
	remediationSvc := remediation.NewService(remediationRepo, findingRepo, issueSvc, cfg.RemediationAutoCreate, cfg.PublicURL).WithFeatures(features)
	issueSvc.AddLinkSyncer(remediationSvc)
	// Custom fields: definitions + validated values; triage rules read and
	// set them, component policies read the project's. Computed fields
	// (internal/computed) recompute their own value from a CEL expression.
	customFieldRepo := customfield.NewRepository(db)
	customFieldSvc := customfield.NewService(customFieldRepo, membershipRepo, findingRepo)
	triageSvc := triage.NewService(triageRepo, findingRepo, findingRepo).WithCustomFields(customFieldSvc)
	computedSvc := computed.NewService(customFieldRepo, findingRepo, triageRepo, projectRepo, assetRepo)

	parsers := newParserRegistry()
	// No-code parsers (M12 12.4): admin-defined CSV/JSON/XML mappings the
	// upload path falls back to when ?scanner= names no built-in parser.
	customParserRepo := customparser.NewRepository(db)
	customParserSvc := customparser.NewService(customParserRepo, parsers)
	// Post-ingest passes, in order: reachability first (it sets priority, which the
	// later passes can match on and which dedup uses to elect a primary); then VEX,
	// whose verdicts are authoritative and must win over a generic rule; then
	// vulnerability policies (component+vulnerability-pair CEL rules, with their
	// own priority among themselves) — after VEX so an authoritative VEX verdict
	// always wins, before the generic triage rules so a policy's analysis/rating
	// is in place before a rule conditions on it; then the triage rules, which
	// only see what VEX and the policies left open; last, imported verdicts
	// (connector pulls, reports carrying their own triage), applied only to new
	// findings nothing local has triaged.
	reacher := correlation.NewReacher(findingRepo, findingRepo)
	vexRepo := vex.NewRepository(db)
	vexSvc := vex.NewService(vexRepo, findingRepo, projectRepo)
	vulnPolicyRepo := vulnpolicy.NewRepository(db)
	vulnPolicySvc := vulnpolicy.NewService(vulnPolicyRepo, findingRepo, findingRepo)
	connectorRepo := connector.NewRepository(db)
	// EU CRA Article 14: actively exploited findings (KEV, weaponized exploit)
	// of in-scope products open reporting cases with the 24 h / 72 h / 14 d clock.
	craRepo := cra.NewRepository(db)
	craSvc := cra.NewService(craRepo, notifySvc, cra.Manufacturer{
		Name: cfg.CRA.ManufacturerName, Address: cfg.CRA.ManufacturerAddress,
		Contact: cfg.CRA.ManufacturerContact, MainEstablishment: cfg.CRA.MemberState,
	}).WithFeatures(features)
	// Exploit intel: the feeds sync on the leader's schedule; at ingest a scan's
	// findings get the exploits already known (no network), right after
	// reachability, since both feed priority.
	exploitRepo := exploitintel.NewRepository(db)
	var exploitSvc *exploitintel.Service
	if cfg.Exploit.Enabled {
		feeds, err := exploitintel.Feeds(cfg.Exploit.Sources, cfg.Exploit.URLs)
		if err != nil {
			return fmt.Errorf("EXPLOIT_INTEL_SOURCES: %w", err)
		}
		exploitSvc = exploitintel.NewService(exploitRepo, feeds, netguard.NewClient(10*time.Minute), findingRepo).WithCRA(craSvc)
	}
	appliers := []scan.Applier{reacher}
	if exploitSvc != nil {
		appliers = append(appliers, exploitSvc)
	}
	// Exposure after the triage rules: it infers asset exposure from the scan and
	// recomputes this scan's priorities from every input (a rule's severity
	// reset included) before dedup elects primaries. Computed fields right after
	// the triage rules: a computed finding field reads the severity/status a
	// rule just settled.
	appliers = append(appliers, vexSvc, vulnPolicySvc, triageSvc, computedSvc, assetSvc,
		connector.NewRemoteTriage(connectorRepo, findingRepo).WithApproval(cfg.RiskAcceptanceRequiresApproval))
	// NVD CVSS: stamp cached vectors onto a scan's findings at ingest (no network;
	// the enrichment schedule fetches). Before dedup, after nothing that reads it.
	// One NVD client: CVSS enrichment and CPE matching share its rate limit.
	nvdClient := enrichment.NewNVDClient(cfg.NVD.URL, cfg.SecretGetter("NVD_API_KEY", cfg.NVD.APIKey))
	nvdSvc := enrichment.NewNVD(findingRepo, nvdClient)
	if cfg.NVD.Enabled {
		appliers = append(appliers, nvdSvc)
	}
	ingestSvc := scan.NewService(scanRepo, findingRepo, projectRepo, parsers, notifySvc, appliers, scanRepo).
		WithFollowUps(remediationSvc).
		WithSkipUnchanged(cfg.Ingest.SkipUnchanged).
		WithHostAssets(assetRepo).
		WithPayloadStore(payloadStore).
		WithCustomParsers(customParserSvc)
	// Ingest queue depth: sampled once per interval and shared by the metrics
	// exporter, the upload handler's backpressure check, and (M11 11.7) the
	// live-tuning sample that resizes this node's worker pool.
	workerPool := scan.NewWorkerPool(scanRepo, ingestSvc, cfg.Ingest.PollInterval, cfg.Ingest.MaxAttempts)
	queueMon := scan.NewQueueMonitor(scanRepo, cfg.Ingest.QueueSampleInterval, cfg.Ingest.MaxQueueDepth).
		WithLiveSettings(scanRepo, workerPool, cfg.Ingest.Workers)
	connectorSvc := connector.NewService(connectorRepo, ingestSvc, trackerCipher)
	// Component policies: evaluated on every SBOM upload (the sbom post-ingest
	// hook), after each policy change, and on POLICY_EVAL_INTERVAL.
	licenseGroups := license.NewGroups(db)
	policyRepo := policy.NewRepository(db)
	policySvc := policy.NewService(policyRepo, sbomRepo, pkgmetaRepo, licenseGroups, ingestSvc, notifySvc).
		WithCustomFields(customFieldRepo)
	sbomSvc := sbom.NewService(sbomRepo, projectRepo, policySvc, reacher).
		WithLicenses(license.Resolve).WithStrictValidation(cfg.SBOMStrictValidation)
	correlationSvc := correlation.NewService(findingRepo, sbomRepo)
	authSvc := auth.NewService(userRepo, cfg.JWT, cfg.PasswordLoginEnabled)
	// Shared with the auth middleware and the audit recorder, so rotating
	// JWT_SECRET (Keys.Update) applies to every signer and verifier at once.
	jwtKeys := authSvc.Keys()
	authSvc.WithFeatures(features)
	authSvc.EnableResetMail(notifySvc, cfg.PublicURL)
	// TOTP two-factor: secrets sealed like integration tokens; code attempts
	// capped per account (always, whatever AUTH_RATE_LIMIT_* says).
	authSvc.EnableMFA(trackerCipher, ratelimit.New(db, ratelimit.Limits{}))
	// SSO: providers from the environment (OIDC_*, SAML_*) and from the admin
	// UI, resolved per request by one registry, sharing one linking +
	// group-sync layer (built below, once the registry exists — see
	// ssoSvc.WithSAMLSingleLogout). Declared here so account.NewHandler, which
	// starts a SAML Single Logout on /me/logout, can take it.
	ssoRepo := sso.NewRepository(db)
	ssoSvc := sso.NewService(userRepo, ssoRepo, authSvc, cfg.SSO.AutoCreateUsers)
	// LDAP / Active Directory sign-in through the password form (LDAP_*).
	if cfg.LDAP.Enabled {
		dir, err := ldap.New(cfg.LDAP, ssoSvc)
		if err != nil {
			return err
		}
		authSvc.EnableDirectory(dir.WithBindPassword(cfg.SecretGetter("LDAP_BIND_PASSWORD", cfg.LDAP.BindPassword)))
	}

	tokenRepo := apitoken.NewRepository(db)
	tokenSvc := apitoken.NewService(tokenRepo)
	federationRepo := federation.NewRepository(db)
	federationSvc := federation.NewService(federationRepo, userRepo, authSvc, cfg.ServiceAccounts.TokenTTL)

	// Advisory sources (VULNMATCH_SOURCES), merged into one deduplicated result:
	// OSV.dev, GitHub Advisories, the local OSV mirror, private advisories.
	osvMirrorRepo := vulnmatch.NewOSVRepository(db)
	advisoryRepo := vulnmatch.NewAdvisoryRepository(db, cfg.PublicURL)
	jvnRepo := vulnmatch.NewJVNRepository(db)
	vulnSources, err := vulnmatch.NewSources(cfg.VulnMatch.Sources, vulnmatch.SourceDeps{
		OSVURL: cfg.VulnMatch.OSVURL, GitHubURL: cfg.VulnMatch.GitHubURL, GitHubToken: cfg.SecretGetter("VULNMATCH_GITHUB_TOKEN", cfg.VulnMatch.GitHubToken),
		Mirror: osvMirrorRepo, Private: advisoryRepo, NVD: nvdClient,
		VulnerableCodeURL: cfg.VulnMatch.VulnerableCodeURL, VulnerableCodeAPIKey: cfg.SecretGetter("VULNMATCH_VULNERABLECODE_API_KEY", cfg.VulnMatch.VulnerableCodeAPIKey),
		JVN: jvnRepo,
	})
	if err != nil {
		return err
	}
	osvMirror := vulnmatch.NewMirror(osvMirrorRepo, cfg.VulnMatch.OSVMirrorURL, cfg.VulnMatch.OSVEcosystems)
	// Feed rules (mute / severity / tags) apply inside every match, to every
	// source; add_tags rules tag findings through the finding repository.
	feedRuleRepo := vulnmatch.NewFeedRuleRepository(db)
	vulnSvc := vulnmatch.NewService(sbomRepo, ingestSvc, vulnSources).WithFeedRules(feedRuleRepo, findingRepo)
	var jvnMirror *vulnmatch.JVNMirror
	if slices.Contains(cfg.VulnMatch.Sources, vulnmatch.SourceJVN) {
		jvnMirror = vulnmatch.NewJVNMirror(jvnRepo, cfg.VulnMatch.JVNURL, cfg.VulnMatch.JVNFromYear)
	}
	// A feed-rule edit re-matches in the background: a mute closes its
	// findings (on a healthy run) without waiting for the schedule.
	var onFeedRuleChange func()
	if cfg.VulnMatch.Enabled {
		onFeedRuleChange = func() { vulnSvc.Kick(rootCtx) }
	}
	// PSIRT: CSAF advisories about our own products (admin), optionally
	// published as a CSAF provider directory (PSIRT_PUBLIC).
	psirtRepo := psirt.NewRepository(db)
	psirtSvc := psirt.NewService(psirtRepo, advisoryRepo, psirt.Config{
		Public: cfg.PSIRT.Public, Prefix: cfg.PSIRT.AdvisoryPrefix, BaseURL: cfg.PublicURL,
		Publisher: psirt.Publisher{Name: cfg.PSIRT.PublisherName, Namespace: cfg.PSIRT.PublisherNamespace,
			Contact: cfg.PSIRT.PublisherContact},
	})
	// A private advisory edit re-matches in the background, so its findings
	// appear (or close, once withdrawn) without waiting for the schedule.
	var onAdvisoryChange func()
	if cfg.VulnMatch.Enabled && slices.Contains(cfg.VulnMatch.Sources, vulnmatch.SourcePrivate) {
		onAdvisoryChange = func() { vulnSvc.Kick(rootCtx) }
	}
	if cfg.VulnMatch.Enabled {
		// A fresh SBOM shows its vulnerabilities right away rather than at the
		// next scheduled match. Off with VULNMATCH_ENABLED (e.g. air-gapped).
		// Policies re-evaluate once the upload's advisories are recorded, so
		// security conditions see them immediately too.
		sbomSvc.WithMatcher(policySvc.AfterMatch(vulnSvc))
	}
	// Outdated components: registry metadata for current SBOM inventory. Off
	// with PKGMETA_ENABLED (air-gapped); PKGMETA_<ECO>_URL points at mirrors.
	var pkgmetaSvc *pkgmeta.Service
	if cfg.PkgMeta.Enabled {
		pkgmetaSvc = pkgmeta.NewService(pkgmetaRepo, pkgmeta.NewRegistries(pkgmeta.RegistryConfig{
			UserAgent:         pkgmeta.UserAgent(cfg.PublicURL),
			RequestsPerSecond: cfg.PkgMeta.RequestsPerSecond,
			URLs:              cfg.PkgMeta.URLs,
		}), pkgmeta.Options{TTL: cfg.PkgMeta.TTL, Concurrency: cfg.PkgMeta.Concurrency})
		// A fresh SBOM's new packages are looked up right away; policies then
		// re-evaluate so outdated/age conditions judge them immediately too.
		sbomSvc.WithPackageMeta(policySvc.AfterRefresh(pkgmetaSvc))
	}

	kevCatalogs, err := enrichment.KEVCatalogs(cfg.Enrich.KEVSources, cfg.Enrich.KEVURLs, cfg.SecretGetter("VULNCHECK_API_TOKEN", cfg.Enrich.VulnCheckToken),
		netguard.NewClient(5*time.Minute))
	if err != nil {
		return fmt.Errorf("KEV_SOURCES: %w", err)
	}
	enrichSvc := enrichment.NewService(findingRepo, enrichment.NewHTTPSource(), kevCatalogs,
		enrichment.NewKEVRepository(db), notifySvc).WithCRA(craSvc)

	engagementRepo := engagement.NewRepository(db)
	findingTemplates := findingtemplate.NewRepository(db)
	reportTemplates := report.NewTemplateRepository(db)
	// Opt-in AI triage (AI_TRIAGE_ENABLED): nil provider = off (routes 404).
	var aiProvider aitriage.Provider
	if cfg.AI.Enabled {
		if aiProvider, err = aitriage.NewProvider(cfg.AI, cfg.SecretGetter("AI_API_KEY", cfg.AI.APIKey)); err != nil {
			return err
		}
		slog.InfoContext(rootCtx, "AI triage enabled", "provider", cfg.AI.Provider, "model", cfg.AI.Model)
	}
	handlers := server.Handlers{
		Features:    feature.NewHandler(features, userRepo),
		Auth:        auth.NewHandler(authSvc),
		Account:     account.NewHandler(userRepo, authSvc, ssoSvc),
		Org:         org.NewHandler(orgRepo, userRepo),
		Team:        team.NewHandler(teamRepo, membershipRepo),
		TeamMembers: membership.NewHandler(membershipRepo, userRepo),
		Membership:  membershipRepo,
		Personal:    notify.NewPersonalHandler(notifyRepo, notifySvc),
		Inbox:       inbox.NewHandler(inboxRepo),
		MCP:         mcp.NewHandler(cfg.MCPEnabled, version),
		Access:      access.NewHandler(access.NewRepository(db)),
		Project: project.NewHandler(projectRepo, findingRepo, membershipRepo).WithTagsChanged(func(id string) {
			policySvc.Reevaluate([]string{id}, false) // tag-scoped policies may now (not) apply
		}),
		Scan: scan.NewHandler(scanRepo, ingestSvc, cfg.Ingest.Async, queueMon, workerPool),
		Finding: finding.NewHandler(findingRepo, notifySvc, membershipRepo, cfg.AssessmentRequiresApproval).
			WithRiskAcceptanceApproval(cfg.RiskAcceptanceRequiresApproval).WithCustomFields(customFieldRepo),
		AITriage: aitriage.NewHandler(aitriage.NewService(aitriage.NewRepository(db), findingRepo, aiProvider,
			ratelimit.New(db, ratelimit.Limits{}), notifySvc,
			aitriage.Options{RequireApproval: cfg.AssessmentRequiresApproval, RateLimit: cfg.AI.RateLimit})),
		Sbom:       sbom.NewHandler(sbomRepo, sbomSvc),
		Asset:      asset.NewHandler(assetRepo, assetSvc, membershipRepo),
		Compliance: compliance.NewHandler(complianceRepo),
		Portfolio:  portfolio.NewHandler(portfolioRepo),
		Metrics:    metrics.NewHandler(metricsReadRepo).WithSnapshotter(metricsRepo, portfolioParts.SnapshotParts),
		Report: report.NewHandler(report.NewService(portfolioRepo, finding.NewRepository(readDB), complianceRepo, projectRepo,
			report.NewRepository(db)).WithEngagements(engagementRepo), reportTemplates),
		Engagement:  engagement.NewHandler(engagementRepo, ingestSvc, findingRepo, findingTemplates),
		Badge:       badge.NewHandler(badge.NewRepository(db), portfolioRepo, gateRepo, findingRepo).WithPublicURL(cfg.PublicURL),
		FixPlan:     fixplan.NewHandler(findingRepo),
		Remediation: remediation.NewHandler(remediationRepo, remediationSvc, membershipRepo),
		RootCauses:  rootcause.NewHandler(rootcause.NewService(findingRepo, remediationRepo, remediationSvc, membershipRepo)),
		Exploits:    exploitintel.NewHandler(exploitRepo, exploitSvc, findingRepo),
		Evidence:    evidence.NewHandler(evidence.NewRepository(db), projectRepo, complianceRepo, portfolioRepo, craRepo),
		CRACases:    cra.NewCaseHandler(craSvc),
		FindingTmpl: findingtemplate.NewHandler(findingTemplates),
		ReportTmpl:  report.NewTemplateHandler(reportTemplates),
		CustomFields: customfield.NewHandler(customFieldRepo, customFieldSvc).
			WithComputedValidator(computedSvc).WithComputedChanged(computedSvc.OnDefinitionChanged),
		CustomParser: customparser.NewHandler(customParserSvc),
		Notify:       notify.NewHandler(notifyRepo, notifySvc),
		Retention:    retention.NewHandler(retentionSvc),
		Archive:      archive.NewHandler(archive.NewRepository(db), findingRepo, cfg.Retention.ArchiveAge),
		Audit:        audit.NewHandler(auditRepo),
		AuditLog:     audit.NewRecorder(auditRepo, membershipRepo, jwtKeys),
		IngestHealth: ingesthealth.NewHandler(ingestHealth),
		Triage:       triage.NewHandler(triageRepo, triageSvc, cfg.TriageRulesRequireApproval).WithCustomFields(customFieldRepo),
		Gate:         gate.NewHandler(gateRepo, findingRepo, projectRepo),
		SLA:          sla.NewHandler(slaRepo, slaSvc),
		Vex:          vex.NewHandler(vexRepo, vexSvc).WithPublicURL(cfg.PublicURL),
		IssueTracker: issuetracker.NewHandler(issueSvc),
		Connector:    connector.NewHandler(connectorSvc),
		VulnMatch:    vulnmatch.NewHandler(vulnSvc, vulnSources.Names(), osvMirrorRepo, osvMirror).WithJVN(jvnMirror),
		Advisory:     vulnmatch.NewAdvisoryHandler(advisoryRepo, onAdvisoryChange),
		FeedRules:    vulnmatch.NewFeedRuleHandler(feedRuleRepo, onFeedRuleChange),
		PSIRT:        psirt.NewHandler(psirtSvc, psirtRepo),
		PkgMeta:      pkgmeta.NewHandler(pkgmetaRepo, pkgmetaSvc),
		Correlation:  correlation.NewHandler(correlationSvc),
		ApiToken:     apitoken.NewHandler(tokenRepo, tokenSvc).WithReauthWindow(cfg.JWT.ReauthWindow),
		SvcAccount:   serviceaccount.NewHandler(serviceaccount.NewRepository(db), tokenSvc, tokenRepo, cfg.ServiceAccounts.KeyMaxDays),
		Federation:   federation.NewHandler(federationRepo, federationSvc, !cfg.IsProduction()),
		SCIM:         scim.NewHandler(scim.NewStore(db), auditRepo),
		TokenAuth:    tokenSvc,
		Sessions:     userRepo,
		AuthLimiter: ratelimit.New(db, ratelimit.Limits{
			IPMax: cfg.AuthRateLimit.IPPerMinute, IPWindow: time.Minute,
			AccountMax: cfg.AuthRateLimit.Account, AccountWindow: cfg.AuthRateLimit.AccountWindow,
		}),
		Enrichment: enrichment.NewHandler(enrichSvc),
		License:    license.NewHandler(licenseGroups),
		Policy:     policy.NewHandler(policyRepo, policySvc, findingRepo),
		VulnPolicy: vulnpolicy.NewHandler(vulnPolicyRepo, vulnPolicySvc).WithCustomFields(customFieldRepo),
		Secrets:    secretbox.NewHandler(db, trackerCipher),
		JWTKeys:    jwtKeys,
		Ready:      db.Ping,
	}

	// SSO: providers from the environment (OIDC_*, SAML_*) and from the admin
	// UI, resolved per request by one registry, sharing one linking +
	// group-sync layer. A provider whose setup fails (discovery, metadata
	// fetch) is logged and left off the login page — never fatal, retried.
	// (ssoRepo/ssoSvc themselves were built earlier, above authSvc, so
	// account.NewHandler could take ssoSvc.)
	ssoProviders := sso.NewProviderRepository(db, trackerCipher, cfg.PublicURL)
	ssoRegistry := sso.NewRegistry(ssoProviders, sso.EnvProviders(cfg), map[string]sso.Protocol{
		sso.ProviderOIDC: oidc.Protocol{},
		sso.ProviderSAML: saml.Protocol{Keys: saml.NewKeyStore(db, trackerCipher)},
	})
	wireKeyRotation(cfg, jwtKeys, trackerCipher, ssoRegistry)
	// SAML Single Logout: a login is recorded (NameID/SessionIndex) until the
	// JWT's own TTL, so a later /me/logout can find the IdP to sign out of,
	// and an IdP-initiated LogoutRequest can find the session to end here.
	samlSessions := saml.NewSessionStore(db, userRepo)
	ssoSvc.WithSAMLSingleLogout(samlSessions, ssoRegistry, cfg.JWT.TTL)
	logEnvSSO(rootCtx, ssoRegistry)
	handlers.SSO = sso.NewHandler(ssoRepo, ssoProviders, ssoRegistry, sso.Settings{
		AutoCreateUsers: cfg.SSO.AutoCreateUsers, PasswordLoginEnabled: cfg.PasswordLoginEnabled,
		PublicURL: cfg.PublicURL, Production: cfg.IsProduction(), CookieSecure: cfg.Security.CookieSecure,
	})
	handlers.OIDC = oidc.NewHandler(ssoRegistry, ssoSvc, cfg.Security.CookieSecure)
	handlers.SAML = saml.NewHandler(ssoRegistry, saml.NewReplayStore(db), ssoSvc, samlSessions, cfg.Security.CookieSecure)

	// Scheduled background jobs run on exactly one instance at a time: with
	// several replicas, every one would otherwise send its own summary, expiry
	// notifications, enrichment fetches… One replica wins a Postgres advisory
	// lock; if it dies, another takes over (see internal/leader).
	go leader.Run(rootCtx, db, leader.JobsLockKey, leader.Options{}, func(ctx context.Context) {
		var wg sync.WaitGroup
		job := func(run func()) {
			wg.Add(1)
			go func() { defer wg.Done(); run() }()
		}
		// Resolve the licenses of components stored before license resolution
		// existed (one-off; a no-op once done).
		// Then evaluate component policies now (license data is complete, so
		// nothing is judged on unresolved licenses) and on POLICY_EVAL_INTERVAL,
		// catching KEV/EPSS, outdated and license-data changes.
		job(func() {
			runLicenseBackfill(ctx, sbomRepo)
			runPolicyEval(ctx, policySvc, cfg.Policy.EvalInterval)
		})
		// Vulnerability policies: re-evaluate on VULN_POLICY_EVAL_INTERVAL,
		// catching a validity window's expiry (ingest and policy edits already
		// evaluate immediately). Optionally sync a GitOps bundle URL first, so
		// a fetched update is reflected in the same pass.
		job(func() {
			if cfg.VulnPolicy.BundleURL != "" {
				syncer := vulnpolicy.NewSyncer(vulnPolicySvc, cfg.VulnPolicy.BundleURL, netguard.NewClient(30*time.Second))
				go syncer.RunEvery(ctx, cfg.VulnPolicy.BundleInterval)
			}
			runVulnPolicyEval(ctx, vulnPolicySvc, cfg.VulnPolicy.EvalInterval)
		})
		// Computed custom fields: EPSS/KEV, status and other facts a computed
		// field reads change without a new scan, so a sweep keeps every project,
		// asset and finding fresh within COMPUTED_FIELDS_INTERVAL (0 = off).
		job(func() { runComputedFields(ctx, computedSvc, cfg.ComputedFields.Interval) })
		// Periodically refresh EPSS/KEV and recompute priorities; then, with
		// NVD_ENABLED, CVSS vectors from NVD (slow without a key: rate-limited).
		if cfg.Enrich.Enabled {
			job(func() { runEnrichment(ctx, enrichSvc, cfg.Enrich.Interval) })
		}
		if cfg.NVD.Enabled {
			job(func() { runNVD(ctx, nvdSvc, cfg.Enrich.Interval) })
		}
		// Public exploits (ExploitDB / Metasploit / Nuclei): at start, then daily.
		if exploitSvc != nil {
			job(func() { exploitSvc.RunEvery(ctx, cfg.Exploit.Interval) })
		}
		// Keep stored SBOMs alive: re-match the current inventory against the
		// advisory sources so newly disclosed vulnerabilities surface without a
		// re-scan.
		if cfg.VulnMatch.Enabled {
			job(func() { runVulnMatch(ctx, vulnSvc, cfg.VulnMatch.Interval) })
		}
		// Air-gapped OSV mirror: download VULNMATCH_OSV_ECOSYSTEMS exports from
		// VULNMATCH_OSV_MIRROR_URL (at start, then on the interval).
		if len(cfg.VulnMatch.OSVEcosystems) > 0 {
			job(func() { runOSVMirror(ctx, osvMirror, vulnSvc, cfg.VulnMatch.OSVMirrorInterval, cfg.VulnMatch.Enabled) })
		}
		// JVN iPedia mirror (jvn source): download the feeds at start, then
		// on the interval; the next match picks the aliases up.
		if jvnMirror != nil {
			job(func() { runJVNMirror(ctx, jvnMirror, cfg.VulnMatch.JVNInterval) })
		}
		// Keep package registry metadata fresh: latest versions for the
		// outdated-component view and policies.
		if cfg.PkgMeta.Enabled {
			job(func() { runPackageMeta(ctx, pkgmetaSvc, cfg.PkgMeta.Interval) })
		}
		// Periodically reopen findings whose risk acceptance has expired.
		// Durable notifications: every replica queues, only the leader sends.
		job(func() { notifySvc.RunDispatcher(ctx, cfg.Notify.DispatchInterval) })
		job(func() {
			runExceptionSweep(ctx, findingRepo, cfg.ExceptionSweepInterval, cfg.RiskAcceptanceExpiryWarning, notifySvc)
		})
		// Alert on findings that breached (or are about to breach) their SLA.
		job(func() { runSLASweep(ctx, slaSvc, cfg.SLASweepInterval) })
		// CRA Article 14: open cases for newly exploited findings, start
		// final-report clocks, alert on reporting deadlines (CRA_SWEEP_INTERVAL).
		job(func() { craSvc.RunEvery(ctx, cfg.CRA.SweepInterval) })
		// Two-way issue-tracker sync + auto-create on ISSUE_SYNC_INTERVAL.
		job(func() { runIssueSync(ctx, issueSvc, cfg.IssueSyncInterval) })
		// Group open findings into remediation actions; refresh due dates,
		// owners and auto-close on REMEDIATION_SWEEP_INTERVAL.
		job(func() { runRemediationSweep(ctx, remediationSvc, cfg.RemediationSweepInterval) })
		// Pull Dependency-Track / DefectDojo connectors on CONNECTOR_PULL_INTERVAL.
		job(func() { runConnectorPulls(ctx, connectorSvc, cfg.ConnectorPullInterval) })
		// Housekeeping: stale versions, old SBOM snapshots / scans, logs (*_RETENTION).
		job(func() { retentionSvc.RunEvery(ctx, 24*time.Hour) })
		// Ingestion health: alert once when a project's intake looks broken.
		job(func() { ingestHealth.RunSweep(ctx, notifySvc) })
		// Daily metric snapshots for the trend charts (backfills 90 days on first run).
		job(func() { runMetricsSnapshots(ctx, metricsRepo, portfolioParts, cfg.MetricsSnapshotInterval) })
		// Scheduled per-channel summaries (daily / weekly, set on each channel).
		job(func() { notifySvc.RunSummaries(ctx, findingRepo) })
		// Re-seal rows a previous INTEGRATION_SECRET_KEY still opens under the
		// current primary: once at startup if a previous key is configured,
		// and again whenever a rotation changes the primary (ring.Changed()).
		job(func() { runSecretRekey(ctx, db, trackerCipher) })
		wg.Wait()
	})
	// Async ingestion: a worker pool drains the durable scan-job queue so uploads
	// return immediately and processing scales with worker count, not request rate.
	if cfg.Ingest.Async {
		// INGEST_WORKERS=0 makes a web-only node: it accepts and queues uploads,
		// and dedicated worker nodes drain the queue. The queue monitor's sample
		// (M11 11.7) keeps resizing this to the live-tuned count every interval,
		// so this initial Resize just avoids waiting a full interval at startup.
		workerPool.Resize(rootCtx, cfg.Ingest.Workers)
		// Watch the backlog: the gauges say how far behind we are, and the same
		// sample sheds uploads (429) once the queue is deeper than we can drain.
		if err := queueMon.RegisterMetrics(); err != nil {
			slog.Warn("ingest queue metrics unavailable", "error", err)
		}
		go queueMon.Run(rootCtx)
		slog.Info("async ingestion enabled",
			"workers", cfg.Ingest.Workers, "max_queue_depth", cfg.Ingest.MaxQueueDepth)
	}
	// Serve the embedded UI when built with -tags embedfrontend (single bundle).
	if assets, ok := web.Assets(); ok {
		handlers.Static = assets
		slog.Info("serving embedded web UI")
	}

	// Prometheus scrape endpoint (METRICS_ENABLED): /metrics on the main port,
	// or its own listener on METRICS_ADDR (keep that one cluster-internal).
	var metricsSrv *http.Server
	if telemetry.Metrics != nil {
		guarded := observability.GuardMetrics(telemetry.Metrics, cfg.SecretGetter("METRICS_TOKEN", cfg.Metrics.Token))
		if cfg.Metrics.Addr == "" {
			handlers.PromMetrics = guarded
		} else {
			mux := http.NewServeMux()
			mux.Handle("GET /metrics", guarded)
			metricsSrv = &http.Server{Addr: cfg.Metrics.Addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
			go func() {
				if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					slog.Error("metrics listener failed", "addr", cfg.Metrics.Addr, "error", err)
				}
			}()
		}
		slog.Info("prometheus metrics enabled", "addr", cmp.Or(cfg.Metrics.Addr, "main port"), "token", cfg.Metrics.Token != "")
	}

	srv := server.New(cfg, handlers)

	// Run the server until it errors or a shutdown signal arrives.
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- srv.Start()
	}()

	select {
	case err := <-serverErr:
		return err
	case <-rootCtx.Done():
		slog.Info("shutdown signal received, draining connections")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if metricsSrv != nil {
			_ = metricsSrv.Shutdown(ctx)
		}
		return srv.Shutdown(ctx)
	}
}

// runEnrichment refreshes exploit intel on an interval until the context ends.
// Failures (e.g. offline) are logged, not fatal.
func runEnrichment(ctx context.Context, svc *enrichment.Service, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			res, err := svc.Enrich(ctx)
			observability.RecordJob(ctx, "enrichment", start, err)
			if err != nil {
				slog.WarnContext(ctx, "enrichment run failed", "error", err)
				continue
			}
			slog.InfoContext(ctx, "enrichment run complete", "findings_updated", res.Findings,
				"kev_sources", res.KEV, "kev_failed", len(res.KEVFailed))
		}
	}
}

// runExceptionSweep, on an interval until the context ends: reopens false
// positive / won't fix findings whose exception lapsed; expires risk
// acceptances past their expiry (their findings reopen); and announces approved
// acceptances lapsing within warnAhead.
func runExceptionSweep(ctx context.Context, repo *finding.Repository, interval, warnAhead time.Duration, notifier *notify.Service) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			observability.RecordJob(ctx, "exception_sweep", start, sweepExceptions(ctx, repo, warnAhead, notifier))
		}
	}
}

// sweepExceptions reopens lapsed false positive / won't fix exceptions,
// expires risk acceptances and warns about soon-expiring ones. It returns the
// first failure (for the job metrics); later steps still run.
func sweepExceptions(ctx context.Context, repo *finding.Repository, warnAhead time.Duration, notifier *notify.Service) (failed error) {
	if n, err := repo.ExpireExceptions(ctx); err != nil {
		failed = err
		slog.WarnContext(ctx, "exception sweep failed", "error", err)
	} else if n > 0 {
		slog.InfoContext(ctx, "reopened lapsed exceptions", "count", n)
		notifier.Notify(ctx, notify.Event{
			Type:   notify.EventExceptionExpired,
			Title:  "Exceptions expired",
			Text:   fmt.Sprintf("%d finding(s) had their false positive / won't fix exception lapse and were reopened.", n),
			Fields: map[string]string{"count": fmt.Sprintf("%d", n)},
		})
	}
	expired, err := repo.ExpireAcceptances(ctx)
	if err != nil {
		failed = cmp.Or(failed, err)
		slog.WarnContext(ctx, "risk acceptance expiry failed", "error", err)
	}
	regrouped := map[string]bool{}
	for _, a := range expired {
		slog.InfoContext(ctx, "risk acceptance expired", "acceptance_id", a.ID, "findings", a.FindingCount)
		notifier.Notify(ctx, finding.AcceptanceEvent(notify.EventRiskAcceptanceExpired, "Risk acceptance expired", a))
		if a.FindingCount > 0 && !regrouped[a.ProjectID] {
			regrouped[a.ProjectID] = true
			if _, err := repo.Deduplicate(ctx, a.ProjectID); err != nil {
				slog.WarnContext(ctx, "dedup after risk acceptance expiry failed", "project_id", a.ProjectID, "error", err)
			}
		}
	}
	if warnAhead <= 0 {
		return failed
	}
	expiring, err := repo.WarnExpiringAcceptances(ctx, warnAhead)
	if err != nil {
		failed = cmp.Or(failed, err)
		slog.WarnContext(ctx, "risk acceptance expiry warning failed", "error", err)
	}
	for _, a := range expiring {
		notifier.Notify(ctx, finding.AcceptanceEvent(notify.EventRiskAcceptanceExpiring, "Risk acceptance expiring", a))
	}
	return failed
}

// runLicenseBackfill resolves the licenses of SBOM components stored before
// license resolution existed (license_resolved IS NULL). Idempotent, and a
// single index probe once there's nothing left; a failure is retried at the
// next boot / leadership change.
func runLicenseBackfill(ctx context.Context, sboms *sbom.Repository) {
	n, err := sboms.BackfillLicenses(ctx, license.Resolve)
	if err != nil {
		slog.WarnContext(ctx, "license backfill failed", "error", err, "resolved", n)
		return
	}
	if n > 0 {
		slog.InfoContext(ctx, "resolved licenses of existing components", "count", n)
	}
}

// runSLASweep alerts on findings that newly breached or entered the due-soon
// tail of their SLA, on an interval, until the context ends.
func runSLASweep(ctx context.Context, svc *sla.Service, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			res, err := svc.Sweep(ctx)
			observability.RecordJob(ctx, "sla_sweep", start, err)
			if err != nil {
				slog.WarnContext(ctx, "sla sweep failed", "error", err)
				continue
			}
			if res.Breached > 0 || res.DueSoon > 0 {
				slog.InfoContext(ctx, "sla sweep alerted", "breached", res.Breached, "due_soon", res.DueSoon)
			}
		}
	}
}

// runSecretRekey re-seals, under the ring's current primary, every row still
// sealed with a previous INTEGRATION_SECRET_KEY: once at startup if a
// previous key is configured (a rotation already in progress when this
// replica became leader), and again every time ring.Changed() fires — a live
// refresh or an admin rotating the primary — until the context ends.
func runSecretRekey(ctx context.Context, db *pgxpool.Pool, ring *secretbox.Keyring) {
	rekey := func() {
		start := time.Now()
		statuses, err := secretbox.Rekey(ctx, db, ring)
		observability.RecordJob(ctx, "secret_rekey", start, err)
		if err != nil {
			slog.WarnContext(ctx, "secret rekey failed", "error", err)
			return
		}
		for _, st := range statuses {
			if st.Previous > 0 || st.Unreadable > 0 {
				slog.InfoContext(ctx, "secret rekey", "table", st.Table, "column", st.Column,
					"total", st.Total, "primary", st.Primary, "previous", st.Previous, "unreadable", st.Unreadable)
			}
		}
	}
	if ring.HasPrevious() {
		rekey()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ring.Changed():
			rekey()
		}
	}
}

// runIssueSync reconciles linked issues with their findings (both ways) and
// auto-creates issues over each tracker's threshold, on an interval, until the
// context ends.
func runIssueSync(ctx context.Context, svc *issuetracker.Service, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			res, err := svc.Sync(ctx)
			observability.RecordJob(ctx, "issue_sync", start, err)
			if err != nil {
				slog.WarnContext(ctx, "issue sync failed", "error", err)
				continue
			}
			if res.Created+res.ClosedIssues+res.ReopenedIssues+res.ResolvedFindings+res.ReopenedFindings+
				res.ResolvedActions+res.ReopenedActions+res.Errors > 0 {
				slog.InfoContext(ctx, "issue sync", "created", res.Created,
					"closed_issues", res.ClosedIssues, "reopened_issues", res.ReopenedIssues,
					"resolved_findings", res.ResolvedFindings, "reopened_findings", res.ReopenedFindings,
					"resolved_actions", res.ResolvedActions, "reopened_actions", res.ReopenedActions,
					"errors", res.Errors)
			}
		}
	}
}

// runRemediationSweep groups open findings into remediation actions and
// refreshes the live ones, at start and then on an interval, until the context
// ends.
func runRemediationSweep(ctx context.Context, svc *remediation.Service, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		start := time.Now()
		res, err := svc.Sweep(ctx)
		observability.RecordJob(ctx, "remediation_sweep", start, err)
		if err != nil {
			slog.WarnContext(ctx, "remediation sweep failed", "error", err)
		} else if res.Created+res.Joined+res.Closed > 0 {
			slog.InfoContext(ctx, "remediation sweep", "created", res.Created, "joined", res.Joined,
				"closed", res.Closed, "proposed", res.Proposed)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runConnectorPulls pulls each enabled Dependency-Track / DefectDojo connector
// once per interval, until the context ends. It ticks more often than the
// interval and pulls only the connectors that are due, so a connector added (or
// last pulled) mid-interval isn't held up to a whole extra one, and instances
// share the work: a per-connector advisory lock makes each pull happen once.
func runConnectorPulls(ctx context.Context, svc *connector.Service, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(min(interval, 5*time.Minute))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			res, err := svc.PullDue(ctx, interval)
			observability.RecordJob(ctx, "connector_pull", start, err)
			if err != nil {
				slog.WarnContext(ctx, "connector pulls failed", "error", err)
				continue
			}
			if res.Pulled+res.Failed > 0 {
				slog.InfoContext(ctx, "connector pulls", "pulled", res.Pulled, "failed", res.Failed, "skipped", res.Skipped)
			}
		}
	}
}

// corsMode summarizes the CORS posture for the startup log.
func corsMode(origins []string) string {
	if len(origins) == 0 {
		return "same-origin"
	}
	return strings.Join(origins, ",")
}

// readPasswordGetter is the DB_PASSWORD getter for the reporting read pool:
// nil when DB_READ_URL points reporting reads at a separate connection
// string (its own credentials, rotation out of scope), the primary's
// rotating password otherwise.
func readPasswordGetter(cfg config.Config) func() string {
	if cfg.DB.ReadURL != "" {
		return nil
	}
	return cfg.SecretGetter("DB_PASSWORD", cfg.DB.Password)
}

// runPolicyEval evaluates every project against the component policies once
// now, then on an interval, until the context ends — catching what changed
// without an upload (KEV/EPSS, outdated status, license data). interval 0
// disables it (uploads and policy edits still evaluate).
func runPolicyEval(ctx context.Context, svc *policy.Service, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		start := time.Now()
		_, err := svc.EvaluateAll(ctx)
		observability.RecordJob(ctx, "policy_eval", start, err)
		if err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "policy evaluation failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runVulnPolicyEval evaluates every project against the vulnerability
// policies once now, then on an interval, until the context ends, catching
// a validity window's expiry (ingest and policy edits already evaluate
// immediately). interval 0 disables it.
func runVulnPolicyEval(ctx context.Context, svc *vulnpolicy.Service, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		start := time.Now()
		_, err := svc.EvaluateAll(ctx)
		observability.RecordJob(ctx, "vuln_policy_eval", start, err)
		if err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "vulnerability policy evaluation failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runComputedFields recomputes every project, asset and finding's computed
// custom fields on COMPUTED_FIELDS_INTERVAL (0 = off; ingest and a
// definition change still recompute).
func runComputedFields(ctx context.Context, svc *computed.Service, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		start := time.Now()
		n, err := svc.RunSweep(ctx)
		observability.RecordJob(ctx, "computed_fields", start, err)
		if err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "computed fields sweep failed", "error", err)
		} else {
			slog.InfoContext(ctx, "computed fields sweep complete", "changed", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runVulnMatch re-evaluates stored SBOM inventory against the advisory feed on an
// interval, so a vulnerability disclosed after upload still surfaces. Failures
// (e.g. the feed is unreachable) are logged, not fatal.
func runVulnMatch(ctx context.Context, svc *vulnmatch.Service, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			n, err := svc.Match(ctx)
			observability.RecordJob(ctx, "vulnmatch", start, err)
			if err != nil {
				slog.WarnContext(ctx, "vulnerability match failed", "error", err)
				continue
			}
			slog.InfoContext(ctx, "vulnerability match run complete", "findings", n)
		}
	}
}

// runNVD fetches CVSS vectors from NVD for findings' CVEs on the enrichment
// interval (first run at start, so enabling it shows results the same day).
// NVD's rate limit makes a large first backfill take a while; each run is
// capped and the next one continues.
func runNVD(ctx context.Context, svc *enrichment.NVD, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		start := time.Now()
		n, err := svc.Refresh(ctx)
		observability.RecordJob(ctx, "nvd", start, err)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.WarnContext(ctx, "nvd enrichment failed", "error", err, "findings_updated", n)
		} else {
			slog.InfoContext(ctx, "nvd enrichment complete", "findings_updated", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runOSVMirror keeps the local OSV mirror current: download + import the
// configured ecosystem exports at start and every interval, then re-match so
// new advisories surface (when the matcher is on).
func runOSVMirror(ctx context.Context, mirror *vulnmatch.Mirror, svc *vulnmatch.Service, interval time.Duration, rematch bool) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		start := time.Now()
		res, err := mirror.Sync(ctx)
		observability.RecordJob(ctx, "osv_mirror", start, err)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.WarnContext(ctx, "osv mirror sync failed", "error", err)
		}
		slog.InfoContext(ctx, "osv mirror sync complete", "records", res.Records,
			"inserted", res.Inserted, "updated", res.Updated)
		if rematch && res.Inserted+res.Updated > 0 {
			if _, err := svc.Match(ctx); err != nil && ctx.Err() == nil {
				slog.WarnContext(ctx, "vulnerability match after mirror sync failed", "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runJVNMirror keeps the JVN iPedia mirror current: at start, then every
// interval. A failed feed is logged; the others are still stored.
func runJVNMirror(ctx context.Context, mirror *vulnmatch.JVNMirror, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		start := time.Now()
		res, err := mirror.Sync(ctx)
		observability.RecordJob(ctx, "jvn_mirror", start, err)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			slog.WarnContext(ctx, "jvn mirror sync failed", "error", err)
		}
		slog.InfoContext(ctx, "jvn mirror sync complete", "feeds", res.Feeds, "entries", res.Entries)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runPackageMeta refreshes stale package registry metadata for current SBOM
// inventory: once at startup (a fresh install fills in), then every interval.
// Each sweep only fetches packages whose TTL or backoff has passed, so a short
// interval is cheap. Failures are logged, not fatal.
func runPackageMeta(ctx context.Context, svc *pkgmeta.Service, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		start := time.Now()
		res, err := svc.Sweep(ctx)
		observability.RecordJob(ctx, "pkgmeta", start, err)
		if ctx.Err() != nil {
			return
		}
		pkgmeta.LogSweep(ctx, res, err)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// runMetricsSnapshots records the daily metric snapshots: once at startup — so
// a fresh instance's first run backfills history and the charts aren't empty —
// then every interval, each run rewriting yesterday (closing it out) and today.
// interval 0 disables it.
func runMetricsSnapshots(ctx context.Context, repo *metrics.Repository, parts *portfolio.Repository, interval time.Duration) {
	if interval <= 0 {
		return
	}
	snap := func() {
		start := time.Now()
		res, err := repo.Run(ctx, time.Now())
		if err == nil {
			// The rest of the portfolio (compliance, SLA) for
			// PORTFOLIO_FROM_SNAPSHOTS, taken with the counts.
			err = parts.SnapshotParts(ctx)
		}
		observability.RecordJob(ctx, "metrics_snapshot", start, err)
		if err != nil {
			slog.WarnContext(ctx, "metric snapshot failed", "error", err)
			return
		}
		if res.Backfilled > 0 {
			slog.InfoContext(ctx, "metric history reconstructed", "days", res.Backfilled)
		}
	}
	snap()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap()
		}
	}
}

// logEnvSSO builds the environment-configured SSO providers at boot and logs
// whether each works. A failure is not fatal: the provider stays off the login
// page and its setup is retried on use.
func logEnvSSO(ctx context.Context, registry *sso.Registry) {
	env := registry.Environment()
	for i, st := range registry.Statuses(ctx, env, 30*time.Second) {
		p := env[i]
		if st.Status == sso.StatusOK {
			slog.Info("SSO provider enabled", "kind", p.Kind, "provider", p.Name, "login_url", p.Endpoints.LoginURL)
		} else {
			slog.Error("SSO provider setup failed; retried on use", "kind", p.Kind, "provider", p.Name,
				"status", st.Status, "error", st.LastError)
		}
	}
}

// healthcheck GETs the local /health endpoint on HTTP_PORT (default 8080)
// and returns the process exit code: 0 healthy, 1 not.
func healthcheck() int {
	port := os.Getenv("HTTP_PORT")
	if port == "" {
		port = "8080"
	}
	client := &http.Client{Timeout: 3 * time.Second}
	res, err := client.Get("http://127.0.0.1:" + port + "/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		return 1
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy: status", res.StatusCode)
		return 1
	}
	return 0
}

// newParserRegistry registers every scanner/import-format parser. Shared by
// run() and demoSeedCmd() so the demo fixtures are ingested through the exact
// registry a real upload goes through.
func newParserRegistry() *scanner.Registry {
	return scanner.NewRegistry(
		scanner.NewTrivy(), scanner.NewSarif(),
		scanner.NewGrype(), scanner.NewOSVScanner(), scanner.NewNpmAudit(),
		scanner.NewDependencyCheck(), scanner.NewGoVulnCheck(),
		scanner.NewGitleaks(), scanner.NewTruffleHog(),
		scanner.NewZap(), scanner.NewNuclei(),
		scanner.NewProwler(), scanner.NewKubescape(), scanner.NewKubeaudit(),
		scanner.NewCheckov(), scanner.NewTfsec(), scanner.NewTerrascan(), scanner.NewScoutSuite(),
		scanner.NewClair(), scanner.NewAnchore(), scanner.NewDockerScout(), scanner.NewPolaris(), scanner.NewKubeBench(),
		scanner.NewBurp(), scanner.NewNikto(), scanner.NewNmap(), scanner.NewWapiti(),
		scanner.NewDefectDojoGeneric(), scanner.NewSecObserve(),
		scanner.NewSnyk(), scanner.NewPipAudit(), scanner.NewSafety(), scanner.NewCargoAudit(), scanner.NewRetireJS(), scanner.NewBundlerAudit(),
		scanner.NewSemgrep(), scanner.NewBandit(), scanner.NewGosec(), scanner.NewBrakeman(),
		scanner.NewDetectSecrets(), scanner.NewGGShield(),
		scanner.NewHadolint(), scanner.NewKICS(), scanner.NewESLint(), scanner.NewYarnAudit(), scanner.NewNJSScan(),
		scanner.NewSonarQube(), scanner.NewCheckmarx(), scanner.NewVeracode(), scanner.NewMend(),
		scanner.NewNessus(), scanner.NewOpenVAS(), scanner.NewQualys(), scanner.NewAcunetix(), scanner.NewInvicti(), scanner.NewTestSSL(), scanner.NewCryptoLyzer(), scanner.NewDrHeader(),
		scanner.NewBearer(), scanner.NewMobSF(), scanner.NewJFrogXray(), scanner.NewAWSInspector2(), scanner.NewAWSSecurityHub(),
		scanner.NewNancy(), scanner.NewCloudSploit(), scanner.NewArachni(), scanner.NewSpotBugs(), scanner.NewFortify(), scanner.NewSteampipe(),
	)
}

// demoSeedCmd implements `xila-api demo-seed`: idempotently creates a demo
// org/team/project and ingests bundled sample reports through the real scan
// and SBOM pipeline, for a 5-minute "see a finding" onboarding path. Returns
// the process exit code.
func demoSeedCmd(args []string) int {
	fs := flag.NewFlagSet("demo-seed", flag.ContinueOnError)
	force := fs.Bool("force", false, "seed demo data even when APP_ENV=production")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	if err := demo.CheckEnvironment(cfg.IsProduction(), *force); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	db, err := database.Connect(ctx, cfg.DB.DSN(), database.PoolConfig{StartupWait: 30 * time.Second})
	if err != nil {
		fmt.Fprintln(os.Stderr, "database:", err)
		return 1
	}
	defer db.Close()
	if err := database.Migrate(cfg.DB.DSN()); err != nil {
		fmt.Fprintln(os.Stderr, "migrate:", err)
		return 1
	}

	userRepo := user.NewRepository(db)
	orgRepo := org.NewRepository(db)
	teamRepo := team.NewRepository(db)
	projectRepo := project.NewRepository(db)
	scanRepo := scan.NewRepository(db)
	findingRepo := finding.NewRepository(db)
	sbomRepo := sbom.NewRepository(db)

	ingestSvc := scan.NewService(scanRepo, findingRepo, projectRepo, newParserRegistry(), nil, nil, scanRepo)
	sbomSvc := sbom.NewService(sbomRepo, projectRepo, nil, nil)

	res, err := demo.Seed(ctx, demo.Deps{
		Users: userRepo, Orgs: orgRepo, Teams: teamRepo, Projects: projectRepo,
		Scans: scanRepo, Scan: ingestSvc, Sbom: sbomSvc,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "demo seed:", err)
		return 1
	}

	url := cfg.PublicURL
	if url == "" {
		url = "http://localhost:" + cfg.HTTP.Port
	}
	fmt.Println("Demo project ready.")
	fmt.Println("URL:     ", url)
	if res.AdminPassword != "" {
		fmt.Println("Login:   ", res.AdminEmail)
		fmt.Println("Password:", res.AdminPassword, "(shown once — change it after signing in)")
	} else {
		fmt.Println("Sign in with your existing account.")
	}
	if !res.Ingested {
		fmt.Println("(demo project already had scans; left it untouched)")
	}
	return 0
}
