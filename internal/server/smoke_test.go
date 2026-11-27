package server

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
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
	"github.com/xilasec/xila-api/internal/ingesthealth"
	"github.com/xilasec/xila-api/internal/issuetracker"
	"github.com/xilasec/xila-api/internal/license"
	"github.com/xilasec/xila-api/internal/mcp"
	"github.com/xilasec/xila-api/internal/membership"
	"github.com/xilasec/xila-api/internal/metrics"
	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/observability"
	"github.com/xilasec/xila-api/internal/oidc"
	"github.com/xilasec/xila-api/internal/org"
	"github.com/xilasec/xila-api/internal/pgtest"
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
	"github.com/xilasec/xila-api/internal/serviceaccount"
	"github.com/xilasec/xila-api/internal/sla"
	"github.com/xilasec/xila-api/internal/sso"
	"github.com/xilasec/xila-api/internal/team"
	"github.com/xilasec/xila-api/internal/triage"
	"github.com/xilasec/xila-api/internal/triagecarry"
	"github.com/xilasec/xila-api/internal/user"
	"github.com/xilasec/xila-api/internal/vex"
	"github.com/xilasec/xila-api/internal/vulnmatch"
	"github.com/xilasec/xila-api/internal/vulnpolicy"
)

const smokeTrivyReport = `{"Results":[
  {"Target":"go.mod","Class":"lang-pkgs","Type":"gomod","Vulnerabilities":[
    {"VulnerabilityID":"CVE-2020-1","PkgName":"pkgA","InstalledVersion":"1.0","FixedVersion":"1.1","Severity":"CRITICAL","CweIDs":["CWE-79"]}]},
  {"Target":".env","Class":"secret","Secrets":[
    {"RuleID":"aws-key","Severity":"HIGH","StartLine":2}]}
]}`

const smokeCycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "metadata": { "component": { "type": "application", "name": "web", "version": "1.0.0" } },
  "components": [
    { "type": "library", "name": "log4j-core", "version": "2.14.1", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1" },
    { "type": "library", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2" },
    { "type": "library", "name": "pkgA", "version": "1.0", "purl": "pkg:generic/pkgA@1.0" },
    { "type": "library", "name": "copyleft-lib", "version": "1.0", "purl": "pkg:npm/copyleft-lib@1.0", "licenses": [{ "license": { "id": "GPL-3.0-only" } }] }
  ]
}`

// fakeExploit is a deterministic EPSS source and CISA KEV catalog for the
// smoke test.
type fakeExploit struct{}

func (fakeExploit) Scores(context.Context, []string) (map[string]float64, error) {
	return map[string]float64{"CVE-2020-1": 0.9}, nil
}
func (fakeExploit) Name() string { return "cisa" }
func (fakeExploit) Fetch(context.Context) (enrichment.KEVList, error) {
	return enrichment.KEVList{IDs: []string{"CVE-2020-1"}, Ransomware: map[string]bool{"CVE-2020-1": true}}, nil
}

// fakeNPM is a deterministic npm registry: express has newer releases (and a
// pre-release that must not count); every other package is unknown (404).
type fakeNPM struct{}

func (fakeNPM) Ecosystem() string { return pkgmeta.NPM }
func (fakeNPM) Fetch(_ context.Context, p pkgmeta.PURL) (pkgmeta.Package, error) {
	if p.Name != "express" {
		return pkgmeta.Package{}, pkgmeta.ErrNotFound
	}
	return pkgmeta.Package{Latest: "4.21.2", Versions: []pkgmeta.Version{
		// express 4.18.2's real tarball digest (registry.npmjs.org dist.shasum).
		{Version: "4.18.2", Hashes: map[string][]string{"sha1": {"3fabe08296e930c796c19e3c516979386ba9fd59"}}},
		{Version: "4.19.0"}, {Version: "4.21.2"}, {Version: "5.0.0-beta.1"},
	}}, nil
}

// newTestApp wires the full application against the test database. opts
// adjust the config (e.g. turn on an approval workflow); none = the defaults.
func newTestApp(t *testing.T, opts ...func(*config.Config)) *fiber.App {
	t.Helper()
	return newTestAppOn(t, pgtest.Pool(t), opts...)
}

// newTestAppOn wires the application on an existing pool, so two differently
// configured apps can share one database (e.g. before/after a config change).
func newTestAppOn(t *testing.T, pool *pgxpool.Pool, opts ...func(*config.Config)) *fiber.App {
	t.Helper()

	cfg := config.Config{
		Env:  "test",
		HTTP: config.HTTP{Host: "127.0.0.1", Port: "0"},
		JWT:  config.JWT{Secret: "smoke-secret", TTL: time.Hour},
		Otel: config.Otel{ServiceName: "xila-api-test"},

		PasswordLoginEnabled: true,
		// The same key trackerCipher is built from below (MFA availability
		// follows it, as in main).
		IntegrationSecretKey: "c21va2UtaW50ZWdyYXRpb24ta2V5LTMyLWJ5dGVzISE=", // gitleaks:allow -- fake test key (base64 of the cipher key below)
		SSO:                  config.SSO{AutoCreateUsers: true},
		ServiceAccounts:      config.ServiceAccounts{KeyMaxDays: 90, TokenTTL: 15 * time.Minute},
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	findingRepo := finding.NewRepository(pool)
	scanRepo := scan.NewRepository(pool)
	projectRepo := project.NewRepository(pool)
	retentionSvc := retention.NewService(pool, projectRepo, retention.Policy(cfg.Retention), nil)
	auditRepo := audit.NewRepository(pool)
	sbomRepo := sbom.NewRepository(pool)
	assetRepo := asset.NewRepository(pool)
	assetSvc := asset.NewService(assetRepo, findingRepo)
	complianceRepo := compliance.NewRepository(pool)
	notifyRepo := notify.NewRepository(pool)
	features := feature.NewStore(pool, feature.Unavailable(cfg)...)
	notifySvc := notify.NewService(notifyRepo, notify.SMTPConfig{}).WithFeatures(features)
	tokenRepo := apitoken.NewRepository(pool)
	tokenSvc := apitoken.NewService(tokenRepo)
	userRepo := user.NewRepository(pool)
	authSvc := auth.NewService(userRepo, cfg.JWT, cfg.PasswordLoginEnabled)
	jwtKeys := authSvc.Keys()
	authSvc.WithFeatures(features)
	federationRepo := federation.NewRepository(pool)
	federationSvc := federation.NewService(federationRepo, userRepo, authSvc, cfg.ServiceAccounts.TokenTTL)
	membershipRepo := membership.NewRepository(pool)
	triageRepo := triage.NewRepository(pool)
	gateRepo := gate.NewRepository(pool)
	// Custom fields: definitions + validated values; triage rules read and
	// set them, component policies read the project's. Computed fields
	// (internal/computed) recompute their own value from a CEL expression.
	customFieldRepo := customfield.NewRepository(pool)
	customFieldSvc := customfield.NewService(customFieldRepo, membershipRepo, findingRepo)
	triageSvc := triage.NewService(triageRepo, findingRepo, findingRepo).WithCustomFields(customFieldSvc)
	computedSvc := computed.NewService(customFieldRepo, findingRepo, triageRepo, projectRepo, assetRepo)
	vexRepo := vex.NewRepository(pool)
	vexSvc := vex.NewService(vexRepo, findingRepo, projectRepo)
	vulnPolicyRepo := vulnpolicy.NewRepository(pool)
	vulnPolicySvc := vulnpolicy.NewService(vulnPolicyRepo, findingRepo, findingRepo)
	carryRepo := triagecarry.NewRepository(pool)
	carrySvc := triagecarry.NewService(carryRepo, projectRepo, findingRepo)
	findingRepo.WithCarrier(carrySvc)
	orgRepo := org.NewRepository(pool)
	slaRepo := sla.NewRepository(pool)
	trackerCipher, err := secretbox.NewKeyring([]byte("smoke-integration-key-32-bytes!!"), nil)
	if err != nil {
		t.Fatalf("tracker cipher: %v", err)
	}
	authSvc.EnableMFA(trackerCipher, ratelimit.New(pool, ratelimit.Limits{}))
	// SSO: declared here (not where main wires the rest of it, below) so
	// account.NewHandler, which starts a SAML Single Logout on /me/logout,
	// can take ssoSvc.
	ssoRepo := sso.NewRepository(pool)
	ssoSvc := sso.NewService(userRepo, ssoRepo, authSvc, cfg.SSO.AutoCreateUsers)
	notifySvc.SetSecretCipher(trackerCipher)
	issueSvc := issuetracker.NewService(issuetracker.NewRepository(pool), findingRepo, trackerCipher, "https://xila.test")
	remediationRepo := remediation.NewRepository(pool)
	remediationSvc := remediation.NewService(remediationRepo, findingRepo, issueSvc, cfg.RemediationAutoCreate, "https://xila.test").WithFeatures(features)
	issueSvc.AddLinkSyncer(remediationSvc)
	// Exploit intel without network: refs are seeded by tests; the ingest pass
	// applies what's stored.
	exploitRepo := exploitintel.NewRepository(pool)
	craRepo := cra.NewRepository(pool)
	craSvc := cra.NewService(craRepo, notifySvc, cra.Manufacturer{Name: "Acme GmbH", Contact: "psirt@acme.test", MainEstablishment: "DE"}).WithFeatures(features)
	exploitSvc := exploitintel.NewService(exploitRepo, nil, nil, findingRepo).WithCRA(craSvc)
	parsers := scanner.NewRegistry(
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
	connectorRepo := connector.NewRepository(pool)
	// No-code parsers (M12 12.4): admin-defined CSV/JSON/XML mappings the
	// upload path falls back to when ?scanner= names no built-in parser.
	customParserRepo := customparser.NewRepository(pool)
	customParserSvc := customparser.NewService(customParserRepo, parsers)
	ingestSvc := scan.NewService(scanRepo, findingRepo, projectRepo, parsers, notifySvc,
		[]scan.Applier{correlation.NewReacher(findingRepo, findingRepo), exploitSvc, vexSvc, vulnPolicySvc, carrySvc, triageSvc, computedSvc, assetSvc,
			connector.NewRemoteTriage(connectorRepo, findingRepo).WithApproval(cfg.RiskAcceptanceRequiresApproval),
			enrichment.NewNVD(findingRepo, nil)}, scanRepo).WithFollowUps(remediationSvc).WithSkipUnchanged(true).WithHostAssets(assetRepo).
		WithCustomParsers(customParserSvc)
	// Advisory sources without network: the local OSV mirror + private advisories.
	osvMirrorRepo := vulnmatch.NewOSVRepository(pool)
	advisoryRepo := vulnmatch.NewAdvisoryRepository(pool, "")
	vulnSources, err := vulnmatch.NewSources([]string{vulnmatch.SourceOSVLocal, vulnmatch.SourcePrivate},
		vulnmatch.SourceDeps{Mirror: osvMirrorRepo, Private: advisoryRepo})
	if err != nil {
		t.Fatalf("vuln sources: %v", err)
	}
	feedRuleRepo := vulnmatch.NewFeedRuleRepository(pool)
	vulnSvc := vulnmatch.NewService(sbomRepo, ingestSvc, vulnSources).WithFeedRules(feedRuleRepo, findingRepo)
	psirtRepo := psirt.NewRepository(pool)
	psirtSvc := psirt.NewService(psirtRepo, advisoryRepo, psirt.Config{
		Public: cfg.PSIRT.Public, Prefix: cmp.Or(cfg.PSIRT.AdvisoryPrefix, "XILA-SA"), BaseURL: "https://xila.example.test",
		Publisher: psirt.Publisher{Name: cfg.PSIRT.PublisherName, Namespace: cfg.PSIRT.PublisherNamespace,
			Contact: cfg.PSIRT.PublisherContact},
	})
	licenseGroups := license.NewGroups(pool)
	policyRepo := policy.NewRepository(pool)
	pkgmetaRepo := pkgmeta.NewRepository(pool)
	pkgmetaSvc := pkgmeta.NewService(pkgmetaRepo, map[string]pkgmeta.Registry{pkgmeta.NPM: fakeNPM{}}, pkgmeta.Options{})
	policySvc := policy.NewService(policyRepo, sbomRepo, pkgmetaRepo, licenseGroups, ingestSvc, notifySvc).
		WithCustomFields(customFieldRepo)
	// Policy edits re-evaluate in the background: let that finish before the
	// pool closes and the next test truncates.
	t.Cleanup(policySvc.WaitIdle)

	engagementRepo := engagement.NewRepository(pool)
	findingTemplates := findingtemplate.NewRepository(pool)
	reportTemplates := report.NewTemplateRepository(pool)
	// AI triage as main wires it; tests point AI_BASE_URL at a fake model server.
	var aiProvider aitriage.Provider
	if cfg.AI.Enabled {
		if aiProvider, err = aitriage.NewProvider(cfg.AI, nil); err != nil {
			t.Fatalf("AI provider: %v", err)
		}
	}
	handlers := Handlers{
		Features:    feature.NewHandler(features, userRepo),
		Auth:        auth.NewHandler(authSvc),
		Account:     account.NewHandler(userRepo, authSvc, ssoSvc),
		Org:         org.NewHandler(orgRepo, userRepo),
		Membership:  membershipRepo,
		Team:        team.NewHandler(team.NewRepository(pool), membershipRepo),
		TeamMembers: membership.NewHandler(membershipRepo, userRepo),
		Personal:    notify.NewPersonalHandler(notifyRepo, notifySvc),
		MCP:         mcp.NewHandler(cfg.MCPEnabled, "test"),
		Access:      access.NewHandler(access.NewRepository(pool)),
		Project: project.NewHandler(projectRepo, findingRepo, membershipRepo).WithTagsChanged(func(id string) {
			policySvc.Reevaluate([]string{id}, false) // tag-scoped policies may now (not) apply
		}),
		Scan: scan.NewHandler(scanRepo, ingestSvc, false, nil, nil),
		Finding: finding.NewHandler(findingRepo, notifySvc, membershipRepo, cfg.AssessmentRequiresApproval).
			WithRiskAcceptanceApproval(cfg.RiskAcceptanceRequiresApproval).WithCustomFields(customFieldRepo),
		AITriage: aitriage.NewHandler(aitriage.NewService(aitriage.NewRepository(pool), findingRepo, aiProvider,
			ratelimit.New(pool, ratelimit.Limits{}), notifySvc,
			aitriage.Options{RequireApproval: cfg.AssessmentRequiresApproval, RateLimit: cfg.AI.RateLimit})),
		Sbom: sbom.NewHandler(sbomRepo, sbom.NewService(sbomRepo, projectRepo, policySvc,
			correlation.NewReacher(findingRepo, findingRepo)).WithLicenses(license.Resolve).WithStrictValidation(cfg.SBOMStrictValidation)),
		Asset:      asset.NewHandler(assetRepo, assetSvc, membershipRepo),
		Compliance: compliance.NewHandler(complianceRepo),
		Portfolio:  portfolio.NewHandler(portfolio.NewRepository(pool)),
		Metrics:    metrics.NewHandler(metrics.NewRepository(pool)).WithSnapshotter(metrics.NewRepository(pool), portfolio.NewRepository(pool).SnapshotParts),
		Report: report.NewHandler(report.NewService(portfolio.NewRepository(pool), findingRepo, complianceRepo,
			projectRepo, report.NewRepository(pool)).WithEngagements(engagementRepo), reportTemplates),
		Engagement:  engagement.NewHandler(engagementRepo, ingestSvc, findingRepo, findingTemplates),
		Badge:       badge.NewHandler(badge.NewRepository(pool), portfolio.NewRepository(pool), gateRepo, findingRepo),
		FixPlan:     fixplan.NewHandler(findingRepo),
		Remediation: remediation.NewHandler(remediationRepo, remediationSvc, membershipRepo),
		RootCauses:  rootcause.NewHandler(rootcause.NewService(findingRepo, remediationRepo, remediationSvc, membershipRepo)),
		Exploits:    exploitintel.NewHandler(exploitRepo, exploitSvc, findingRepo),
		Evidence:    evidence.NewHandler(evidence.NewRepository(pool), projectRepo, complianceRepo, portfolio.NewRepository(pool), craRepo),
		CRACases:    cra.NewCaseHandler(craSvc),
		FindingTmpl: findingtemplate.NewHandler(findingTemplates),
		ReportTmpl:  report.NewTemplateHandler(reportTemplates),
		CustomFields: customfield.NewHandler(customFieldRepo, customFieldSvc).
			WithComputedValidator(computedSvc).WithComputedChanged(computedSvc.OnDefinitionChanged),
		CustomParser: customparser.NewHandler(customParserSvc),
		Notify:       notify.NewHandler(notifyRepo, notifySvc),
		Retention:    retention.NewHandler(retentionSvc),
		Archive:      archive.NewHandler(archive.NewRepository(pool), findingRepo, cfg.Retention.ArchiveAge),
		Audit:        audit.NewHandler(auditRepo),
		AuditLog:     audit.NewRecorder(auditRepo, membershipRepo, jwtKeys),
		IngestHealth: ingesthealth.NewHandler(ingesthealth.NewRepository(pool)),
		Triage:       triage.NewHandler(triageRepo, triageSvc, false).WithCustomFields(customFieldRepo),
		Gate:         gate.NewHandler(gateRepo, findingRepo, projectRepo),
		SLA:          sla.NewHandler(slaRepo, sla.NewService(slaRepo, notifySvc)),
		Vex:          vex.NewHandler(vexRepo, vexSvc),
		IssueTracker: issuetracker.NewHandler(issueSvc),
		Connector:    connector.NewHandler(connector.NewService(connectorRepo, ingestSvc, trackerCipher)),
		Correlation:  correlation.NewHandler(correlation.NewService(findingRepo, sbomRepo)),
		ApiToken:     apitoken.NewHandler(tokenRepo, tokenSvc).WithReauthWindow(cfg.JWT.ReauthWindow),
		SvcAccount:   serviceaccount.NewHandler(serviceaccount.NewRepository(pool), tokenSvc, tokenRepo, cfg.ServiceAccounts.KeyMaxDays),
		Federation:   federation.NewHandler(federationRepo, federationSvc, !cfg.IsProduction()),
		SCIM:         scim.NewHandler(scim.NewStore(pool), auditRepo),
		TokenAuth:    tokenSvc,
		Sessions:     userRepo,
		// Throttling only when a test asks for it (cfg.AuthRateLimit): the other
		// tests sign in many users from one address.
		AuthLimiter: authLimiterFor(pool, cfg),
		Enrichment: enrichment.NewHandler(enrichment.NewService(findingRepo, fakeExploit{},
			[]enrichment.KEVCatalog{fakeExploit{}}, enrichment.NewKEVRepository(pool), notifySvc).WithCRA(craSvc)),
		VulnMatch:  vulnmatch.NewHandler(vulnSvc, vulnSources.Names(), osvMirrorRepo, nil),
		Advisory:   vulnmatch.NewAdvisoryHandler(advisoryRepo, nil),
		FeedRules:  vulnmatch.NewFeedRuleHandler(feedRuleRepo, nil),
		PSIRT:      psirt.NewHandler(psirtSvc, psirtRepo),
		PkgMeta:    pkgmeta.NewHandler(pkgmetaRepo, pkgmetaSvc),
		License:    license.NewHandler(licenseGroups),
		Policy:     policy.NewHandler(policyRepo, policySvc, findingRepo),
		VulnPolicy: vulnpolicy.NewHandler(vulnPolicyRepo, vulnPolicySvc).WithCustomFields(customFieldRepo),
		Secrets:    secretbox.NewHandler(pool, trackerCipher),
		JWTKeys:    jwtKeys,
	}
	// SSO exactly as main wires it; protocol clients reach in-process IdPs over
	// loopback, the SP key pair is the shared generated one. (ssoRepo/ssoSvc
	// themselves were built earlier, above, so account.NewHandler could take
	// ssoSvc.)
	ssoProviders := sso.NewProviderRepository(pool, trackerCipher, cfg.PublicURL)
	ssoRegistry := sso.NewRegistry(ssoProviders, sso.EnvProviders(cfg), map[string]sso.Protocol{
		sso.ProviderOIDC: oidc.Protocol{},
		sso.ProviderSAML: saml.Protocol{Keys: saml.NewKeyStore(pool, trackerCipher)},
	})
	samlSessions := saml.NewSessionStore(pool, userRepo)
	ssoSvc.WithSAMLSingleLogout(samlSessions, ssoRegistry, cfg.JWT.TTL)
	handlers.SSO = sso.NewHandler(ssoRepo, ssoProviders, ssoRegistry, sso.Settings{
		AutoCreateUsers: cfg.SSO.AutoCreateUsers, PasswordLoginEnabled: cfg.PasswordLoginEnabled,
		PublicURL: cfg.PublicURL, Production: cfg.IsProduction(), CookieSecure: cfg.Security.CookieSecure,
	})
	handlers.OIDC = oidc.NewHandler(ssoRegistry, ssoSvc, cfg.Security.CookieSecure)
	handlers.SAML = saml.NewHandler(ssoRegistry, saml.NewReplayStore(pool), ssoSvc, samlSessions, cfg.Security.CookieSecure)
	// Prometheus scrape endpoint, wired as main does (METRICS_ENABLED).
	if cfg.Metrics.Enabled {
		tel, err := observability.Setup(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tel.Shutdown(context.Background()) })
		handlers.PromMetrics = observability.GuardMetrics(tel.Metrics, cfg.SecretGetter("METRICS_TOKEN", cfg.Metrics.Token))
	}
	return New(cfg, handlers).App()
}

// req is a tiny helper around app.Test for JSON requests.
func req(t *testing.T, app *fiber.App, method, path, token string, body string) (*http.Response, map[string]any) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = bytes.NewReader([]byte(body))
	}
	// httptest.NewRequest sets Host (example.com) like any real client does;
	// fasthttp rejects a request without one.
	httpReq := httptest.NewRequest(method, path, reader)
	if body != "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := app.Test(httpReq, -1) // -1 = no timeout
	if err != nil {
		t.Fatalf("app.Test %s %s: %v", method, path, err)
	}
	var decoded map[string]any
	if b, _ := io.ReadAll(resp.Body); len(b) > 0 {
		_ = json.Unmarshal(b, &decoded)
	}
	return resp, decoded
}

func TestSmokeFullFlow(t *testing.T) {
	app := newTestApp(t)

	// Health is public.
	if resp, _ := req(t, app, http.MethodGet, "/health", "", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("health = %d", resp.StatusCode)
	}

	// Protected route without a token -> 401.
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/teams", "", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth teams = %d, want 401", resp.StatusCode)
	}

	// Register + login.
	creds := `{"email":"analyst@xila.io","password":"supersecret"}`
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/auth/register", "", creds); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register = %d", resp.StatusCode)
	}
	resp, loginBody := req(t, app, http.MethodPost, "/api/v1/auth/login", "", creds)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login = %d", resp.StatusCode)
	}
	token, _ := loginBody["token"].(string)
	if token == "" {
		t.Fatal("login returned no token")
	}

	// Create org + team + project (high criticality). The first user is an admin,
	// and creating the org makes them its admin too.
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", token, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	if orgID == "" {
		t.Fatal("org creation returned no id")
	}
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", token, `{"slug":"platform","name":"Platform"}`)
	teamID, _ := teamBody["id"].(string)
	if teamID == "" {
		t.Fatal("team creation returned no id")
	}
	_, projBody := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", token,
		`{"slug":"web","name":"Web","business_criticality":"high"}`)
	projectID, _ := projBody["id"].(string)
	if projectID == "" {
		t.Fatal("project creation returned no id")
	}

	// Ingest a Trivy report.
	scanPath := "/api/v1/projects/" + projectID + "/scans?scanner=trivy&branch=main&commit=abc"
	resp, scanBody := req(t, app, http.MethodPost, scanPath, token, smokeTrivyReport)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("ingest = %d", resp.StatusCode)
	}
	if scanBody["status"] != "completed" {
		t.Errorf("scan status = %v, want completed", scanBody["status"])
	}

	// Summary: critical vuln (15) + high secret (7) = 22 weighted, times the
	// high-criticality multiplier (2) = 44.
	_, summary := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/summary", token, "")
	if got := summary["risk_score"]; got != float64(44) {
		t.Errorf("risk_score = %v, want 44", got)
	}
	if got := summary["total_open"]; got != float64(2) {
		t.Errorf("total_open = %v, want 2", got)
	}

	// Re-ingesting the identical report must not create duplicates.
	req(t, app, http.MethodPost, scanPath, token, smokeTrivyReport)
	_, listBody := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings", token, "")
	findings, _ := listBody["findings"].([]any)
	if len(findings) != 2 {
		t.Errorf("after re-ingest got %d findings, want 2 (deduplicated)", len(findings))
	}

	// SLA: the built-in default applies until a policy is set; setting one
	// re-dates the existing findings; filters, summary, sweep and gate see it.
	slaPath := "/api/v1/projects/" + projectID + "/sla/policy"
	_, eff := req(t, app, http.MethodGet, slaPath, token, "")
	if eff["scope"] != "default" || eff["critical_days"] != float64(7) {
		t.Errorf("default sla policy = %v, want scope default / critical 7", eff)
	}
	if resp, _ := req(t, app, http.MethodPut, slaPath, token, `{"critical_days":2,"high_days":0}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("zero-day window = %d, want 400", resp.StatusCode)
	}
	resp, eff = req(t, app, http.MethodPut, slaPath, token, `{"critical_days":2,"high_days":5}`)
	if resp.StatusCode != http.StatusOK || eff["scope"] != "project" {
		t.Fatalf("put sla policy = %d %v", resp.StatusCode, eff)
	}
	_, slaList := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings?sla=on_track&sort=sla_due", token, "")
	onTrack, _ := slaList["findings"].([]any)
	if len(onTrack) != 2 {
		t.Fatalf("?sla=on_track = %d findings, want 2", len(onTrack))
	}
	if first, _ := onTrack[0].(map[string]any); first["sla_days"] != float64(2) || first["sla_status"] != "on_track" || first["sla_due_at"] == nil {
		t.Errorf("soonest-due finding = days %v status %v due %v, want the 2-day critical, on track",
			first["sla_days"], first["sla_status"], first["sla_due_at"])
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/findings?sla=late", token, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid ?sla = %d, want 400", resp.StatusCode)
	}
	_, summary = req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/summary", token, "")
	if s, _ := summary["sla"].(map[string]any); s["on_track"] != float64(2) || s["breached"] != float64(0) {
		t.Errorf("summary sla = %v, want 2 on track / 0 breached", summary["sla"])
	}
	if resp, sweep := req(t, app, http.MethodPost, "/api/v1/sla/sweep", token, ""); resp.StatusCode != http.StatusOK || sweep["breached"] != float64(0) {
		t.Errorf("sla sweep = %d %v, want 200 with nothing breached", resp.StatusCode, sweep)
	}
	if resp, gateRes := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/gate", token,
		`{"policy":{"block_sla_breach":true}}`); resp.StatusCode != http.StatusOK {
		t.Errorf("block_sla_breach gate = %d %v, want pass (nothing overdue)", resp.StatusCode, gateRes)
	}

	// Branches: a PR branch gets its own copy of the findings; the default branch
	// (main, scanned first) is what the summary reports; the gate can target a
	// branch by name and refuses one that was never uploaded.
	resp, featScan := req(t, app, http.MethodPost,
		"/api/v1/projects/"+projectID+"/scans?scanner=trivy&branch=feature%2Fx", token, smokeTrivyReport)
	if resp.StatusCode != http.StatusCreated || featScan["version_id"] == nil {
		t.Fatalf("feature branch scan = %d %v", resp.StatusCode, featScan)
	}
	_, vs := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/versions", token, "")
	versionList, _ := vs["versions"].([]any)
	if len(versionList) != 2 {
		t.Fatalf("versions = %v, want main + feature/x", vs["versions"])
	}
	if first, _ := versionList[0].(map[string]any); first["name"] != "main" || first["is_default"] != true {
		t.Errorf("first version = %v, want main (default)", first)
	}
	_, allBranches := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings?all_versions=true", token, "")
	if fs, _ := allBranches["findings"].([]any); len(fs) != 4 {
		t.Errorf("findings across branches = %d, want 4 (2 per branch)", len(fs))
	}
	_, featOnly := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings?branch=feature%2Fx", token, "")
	if fs, _ := featOnly["findings"].([]any); len(fs) != 2 {
		t.Errorf("feature/x findings = %d, want 2", len(fs))
	}
	_, summary = req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/summary", token, "")
	if got := summary["total_open"]; got != float64(2) {
		t.Errorf("summary total_open = %v, want 2 (default branch only)", got)
	}
	if resp, g := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/gate?branch=feature%2Fx", token,
		`{"policy":{"max_critical":0}}`); resp.StatusCode != http.StatusUnprocessableEntity || g["version_id"] != featScan["version_id"] {
		t.Errorf("gate on feature/x = %d %v, want 422 against feature/x", resp.StatusCode, g["version_id"])
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/gate?branch=never-uploaded", token, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("gate on an unknown branch = %d, want 404", resp.StatusCode)
	}
	defaultID, _ := versionList[0].(map[string]any)["id"].(string)
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/projects/"+projectID+"/versions/"+defaultID, token, ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("deleting the default version = %d, want 409", resp.StatusCode)
	}

	// Baseline gate: "new" means not already live (by fingerprint) on the named
	// baseline branch, not the single-scan heuristic. feature/x was scanned with
	// the exact same report as main (same fingerprints), so nothing is new
	// against it until a finding exists only on the branch.
	if resp, g := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/gate?branch=feature%2Fx&baseline=main", token,
		`{"policy":{"max_critical":0},"new_only":true}`); resp.StatusCode != http.StatusOK || g["baseline"] != "main" {
		t.Errorf("baseline gate on feature/x vs main = %d %v, want 200 (findings mirror main, nothing new)", resp.StatusCode, g)
	}
	featVersionID, _ := featScan["version_id"].(string)
	resp, manual := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/findings", token,
		`{"title":"only on the branch","severity":"critical","category":"sast","version_id":"`+featVersionID+`"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("manual finding on feature/x = %d %v", resp.StatusCode, manual)
	}
	if resp, g := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/gate?branch=feature%2Fx&baseline=main", token,
		`{"policy":{"max_critical":0},"new_only":true}`); resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("baseline gate with a branch-only finding = %d %v, want 422", resp.StatusCode, g)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/gate?branch=feature%2Fx&baseline=never-uploaded", token, ""); resp.StatusCode < 400 {
		t.Errorf("gate against an unknown baseline = %d, want a 4xx", resp.StatusCode)
	}

	// SBOM upload -> history -> global package search.
	resp, sbomBody := req(t, app, http.MethodPost,
		"/api/v1/projects/"+projectID+"/sboms?artifact=web&version=1.0.0", token, smokeCycloneDX)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("sbom upload = %d", resp.StatusCode)
	}
	if got := sbomBody["component_count"]; got != float64(4) {
		t.Errorf("component_count = %v, want 4", got)
	}

	_, history := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/sboms", token, "")
	if sboms, _ := history["sboms"].([]any); len(sboms) != 1 {
		t.Errorf("sbom history = %d, want 1", len(sboms))
	}

	// Global "filter by package" search.
	_, search := req(t, app, http.MethodGet, "/api/v1/components?name=log4j-core", token, "")
	comps, _ := search["components"].([]any)
	if len(comps) != 1 {
		t.Fatalf("component search hits = %d, want 1", len(comps))
	}
	if hit, _ := comps[0].(map[string]any); hit["project_slug"] != "web" {
		t.Errorf("search hit project_slug = %v, want web", hit["project_slug"])
	}

	// Vulnerable-or-not on component rows: Trivy reported CVE-2020-1 on pkgA@1.0.
	_, vuln := req(t, app, http.MethodGet, "/api/v1/components?vulnerable=true", token, "")
	vulnComps, _ := vuln["components"].([]any)
	if len(vulnComps) != 1 {
		t.Fatalf("?vulnerable=true = %d components, want only pkgA", len(vulnComps))
	}
	if hit, _ := vulnComps[0].(map[string]any); hit["name"] != "pkgA" || hit["vuln_count"] != float64(1) || hit["max_severity"] != "critical" {
		t.Errorf("vulnerable component = %v", hit)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/components?vulnerable=maybe", token, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("?vulnerable=maybe = %d, want 400", resp.StatusCode)
	}
	sbomID, _ := sbomBody["id"].(string)

	// Outdated components: before a registry lookup nothing is known — not
	// "up to date"; after a sweep express is 2 releases behind 4.21.2, and the
	// package the registry doesn't know stays unknown.
	_, before := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/components?outdated=false", token, "")
	if cs, _ := before["components"].([]any); len(cs) != 0 {
		t.Errorf("?outdated=false before any lookup = %d components, want 0", len(cs))
	}
	if resp, sweep := req(t, app, http.MethodPost, "/api/v1/pkgmeta/refresh?wait=true", token, ""); resp.StatusCode != http.StatusOK ||
		sweep["fetched"] != float64(1) || sweep["failed"] != float64(1) {
		t.Errorf("pkgmeta refresh = %d %v", resp.StatusCode, sweep)
	}
	_, outdated := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/components?outdated=true", token, "")
	outComps, _ := outdated["components"].([]any)
	if len(outComps) != 1 {
		t.Fatalf("?outdated=true = %v, want express", outdated["components"])
	}
	if hit, _ := outComps[0].(map[string]any); hit["name"] != "express" || hit["latest_version"] != "4.21.2" ||
		hit["outdated"] != true || hit["versions_behind"] != float64(2) {
		t.Errorf("outdated component = %v", hit)
	}
	_, all := req(t, app, http.MethodGet, "/api/v1/components?name=copyleft-lib", token, "")
	if cs, _ := all["components"].([]any); len(cs) != 1 || cs[0].(map[string]any)["outdated"] != nil {
		t.Errorf("a package unknown to the registry = %v, want outdated null", all["components"])
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/components?outdated=maybe", token, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("?outdated=maybe = %d, want 400", resp.StatusCode)
	}
	_, meta := req(t, app, http.MethodGet, "/api/v1/pkgmeta?purl="+url.QueryEscape("pkg:npm/express@4.19.0"), token, "")
	if st, _ := meta["status"].(map[string]any); st == nil || st["versions_behind"] != float64(1) {
		t.Errorf("GET /pkgmeta = %v", meta)
	}
	_, fresh := req(t, app, http.MethodGet, "/api/v1/sboms/"+sbomID+"/freshness", token, "")
	if fresh["outdated"] != float64(1) || fresh["unknown"] != float64(3) || fresh["total"] != float64(4) {
		t.Errorf("sbom freshness = %v", fresh)
	}
	_, snapVulns := req(t, app, http.MethodGet, "/api/v1/sboms/"+sbomID+"/vulnerabilities", token, "")
	if vs, _ := snapVulns["vulnerabilities"].([]any); len(vs) != 1 {
		t.Errorf("snapshot vulnerabilities = %v, want CVE-2020-1", snapVulns["vulnerabilities"])
	}
	// The snapshot exports as CycloneDX 1.6 carrying that vulnerability, and the
	// project's analysis exports as VEX in every format.
	if resp, bom := req(t, app, http.MethodGet, "/api/v1/sboms/"+sbomID+"/export", token, ""); resp.StatusCode != http.StatusOK ||
		bom["specVersion"] != "1.6" || len(bom["components"].([]any)) != 4 || len(bom["vulnerabilities"].([]any)) != 1 {
		t.Errorf("sbom export = %d %v", resp.StatusCode, bom)
	}
	for _, format := range []string{"openvex", "cyclonedx", "csaf"} {
		if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/vex/export?format="+format, token, ""); resp.StatusCode != http.StatusOK {
			t.Errorf("vex export %s = %d, want 200", format, resp.StatusCode)
		}
	}
	_, diff := req(t, app, http.MethodGet, "/api/v1/sboms/"+sbomID+"/diff", token, "")
	if s, _ := diff["summary"].(map[string]any); diff["base"] != nil || s["added"] != float64(4) {
		t.Errorf("first snapshot diff = base %v summary %v, want no base and 4 added", diff["base"], diff["summary"])
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/sboms/"+sbomID+"/diff?base=not-a-uuid", token, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("diff with bad base = %d, want 400", resp.StatusCode)
	}
	_, graph := req(t, app, http.MethodGet, "/api/v1/sboms/"+sbomID+"/graph", token, "")
	if nodes, _ := graph["nodes"].([]any); len(nodes) != 4 {
		t.Errorf("graph nodes = %d, want the 4 components", len(nodes))
	}
	// A BOM without services still answers, with an empty list (never null).
	if resp, svcs := req(t, app, http.MethodGet, "/api/v1/sboms/"+sbomID+"/services", token, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("sbom services = %d", resp.StatusCode)
	} else if list, ok := svcs["services"].([]any); !ok || len(list) != 0 {
		t.Errorf("sbom services = %v, want []", svcs["services"])
	}
	_, timeline := req(t, app, http.MethodGet, "/api/v1/vulnerabilities/CVE-2020-1/sboms", token, "")
	if arts, _ := timeline["artifacts"].([]any); len(arts) != 1 {
		t.Errorf("CVE-2020-1 timeline artifacts = %v, want web", timeline["artifacts"])
	}

	// Flagship: correlate the SCA finding (pkgA@1.0) to the SBOM component that
	// introduced it.
	scaID := ""
	for _, raw := range findings {
		if f, ok := raw.(map[string]any); ok && f["package_name"] == "pkgA" {
			scaID, _ = f["id"].(string)
		}
	}
	if scaID == "" {
		t.Fatal("could not find the pkgA SCA finding")
	}
	_, corr := req(t, app, http.MethodGet, "/api/v1/findings/"+scaID+"/components", token, "")
	linked, _ := corr["components"].([]any)
	if len(linked) != 1 {
		t.Fatalf("finding→components = %d, want 1", len(linked))
	}
	if hit, _ := linked[0].(map[string]any); hit["name"] != "pkgA" {
		t.Errorf("linked component = %v, want pkgA", hit["name"])
	}

	// License policy: uploading the SBOM evaluated the seeded "Strong copyleft
	// licenses" policy, raising a violation finding for the GPL component.
	_, lic := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings?category=license", token, "")
	licFindings, _ := lic["findings"].([]any)
	if len(licFindings) != 1 {
		t.Fatalf("license findings = %d, want 1", len(licFindings))
	}
	if f, _ := licFindings[0].(map[string]any); f["package_name"] != "copyleft-lib" || f["scanner"] != "policy" ||
		f["rule_id"] != pgtest.SeededPolicyID || f["severity"] != "medium" {
		t.Errorf("license finding = %v, want a medium copyleft-lib violation of the seeded policy", f)
	}
	// The project's Policies tab: the seeded policy is in force with 1 violation,
	// and its violations list the finding.
	_, inForce := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/policies", token, "")
	if ps, _ := inForce["policies"].([]any); len(ps) != 1 || ps[0].(map[string]any)["violations"] != float64(1) {
		t.Errorf("policies in force = %v, want the seeded policy with 1 violation", inForce["policies"])
	}
	_, viol := req(t, app, http.MethodGet, "/api/v1/policies/"+pgtest.SeededPolicyID+"/violations", token, "")
	if vs, _ := viol["findings"].([]any); len(vs) != 1 {
		t.Errorf("seeded policy violations = %v, want 1", viol["findings"])
	}

	// API tokens: mint one and use it in place of the JWT (the CI path).
	_, tokBody := req(t, app, http.MethodPost, "/api/v1/tokens", token, `{"name":"ci"}`)
	secret, _ := tokBody["secret"].(string)
	if !strings.HasPrefix(secret, "xila_") {
		t.Fatalf("token secret = %q, want xila_ prefix", secret)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects", secret, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("list projects with API token = %d, want 200", resp.StatusCode)
	}

	// A project-scoped token may only act on its own project.
	_, scopedBody := req(t, app, http.MethodPost, "/api/v1/tokens", token,
		`{"name":"scoped","project_id":"`+projectID+`"}`)
	scoped, _ := scopedBody["secret"].(string)
	other := "00000000-0000-0000-0000-000000000000"
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+other+"/findings", scoped, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("scoped token on other project = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings", scoped, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("scoped token on own project = %d, want 200", resp.StatusCode)
	}

	// Enrichment: EPSS + KEV lift the exploitable CVE finding to the top by priority.
	if resp, ench := req(t, app, http.MethodPost, "/api/v1/enrich", token, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("enrich = %d", resp.StatusCode)
	} else if ench["enriched"] == float64(0) {
		t.Error("expected at least one finding enriched")
	}
	_, pri := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings?sort=priority", token, "")
	priFindings, _ := pri["findings"].([]any)
	if len(priFindings) == 0 {
		t.Fatal("no findings after enrichment")
	}
	top, _ := priFindings[0].(map[string]any)
	if top["kev"] != true {
		t.Errorf("top finding kev = %v, want true", top["kev"])
	}
	if src, _ := top["kev_sources"].([]any); len(src) != 1 || src[0] != "cisa" {
		t.Errorf("top finding kev_sources = %v, want [cisa]", top["kev_sources"])
	}
	if top["kev_ransomware"] != true {
		t.Errorf("top finding kev_ransomware = %v, want true (the catalog marks CVE-2020-1)", top["kev_ransomware"])
	}
	if _, rw := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings?kev_ransomware=true", token, ""); len(rw["findings"].([]any)) != 1 {
		t.Errorf("kev_ransomware filter = %v, want just the CVE-2020-1 finding", rw["findings"])
	}
	if top["priority"] != float64(45) { // critical(15) × KEV(3)
		t.Errorf("top priority = %v, want 45", top["priority"])
	}

	// Assets: register a container image and attribute a scan's findings to it.
	resp, assetBody := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/assets", token,
		`{"type":"container_image","name":"web:1.0","identifier":"registry/web@sha256:abc"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create asset = %d", resp.StatusCode)
	}
	assetID, _ := assetBody["id"].(string)
	if assetID == "" {
		t.Fatal("asset creation returned no id")
	}

	// Re-ingest the Trivy scan attributed to the asset; findings inherit asset_id.
	req(t, app, http.MethodPost, scanPath+"&asset_id="+assetID, token, smokeTrivyReport)
	_, assetFindings := req(t, app, http.MethodGet, "/api/v1/assets/"+assetID+"/findings", token, "")
	af, _ := assetFindings["findings"].([]any)
	if len(af) != 2 {
		t.Fatalf("asset findings = %d, want 2", len(af))
	}
	for _, raw := range af {
		if f, _ := raw.(map[string]any); f["asset_id"] != assetID {
			t.Errorf("finding asset_id = %v, want %s", f["asset_id"], assetID)
		}
	}

	// The asset shows up in the project's asset list.
	_, assetList := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/assets", token, "")
	if list, _ := assetList["assets"].([]any); len(list) != 1 {
		t.Errorf("project assets = %d, want 1", len(list))
	}

	// Compliance: the CVE finding's CWE-79 fails OWASP A03 (Injection); the other
	// 9 controls pass -> 90%.
	_, comp := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/compliance/owasp-top-10-2021", token, "")
	if comp["score"] != float64(90) {
		t.Errorf("compliance score = %v, want 90", comp["score"])
	}
	if comp["failing_controls"] != float64(1) {
		t.Errorf("failing controls = %v, want 1", comp["failing_controls"])
	}
	controls, _ := comp["controls"].([]any)
	var a03Failing bool
	for _, raw := range controls {
		if ctrl, _ := raw.(map[string]any); ctrl["code"] == "A03" && ctrl["passing"] == false {
			a03Failing = true
		}
	}
	if !a03Failing {
		t.Error("expected OWASP A03 (Injection) to be failing")
	}

	// CSPM: ingest a Prowler report -> a cloud-category finding (validates the
	// cloud/kubernetes category migration end-to-end).
	prowler := `[{"Provider":"aws","CheckID":"iam_root_mfa_enabled","CheckTitle":"MFA on root","Severity":"critical","ResourceId":"arn:aws:iam::1:root","Status":"FAIL"},{"CheckID":"ok","Status":"PASS"}]`
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/scans?scanner=prowler", token, prowler); resp.StatusCode != http.StatusCreated {
		t.Fatalf("prowler ingest = %d", resp.StatusCode)
	}
	_, cloudList := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings?category=cloud", token, "")
	cloud, _ := cloudList["findings"].([]any)
	if len(cloud) != 1 {
		t.Fatalf("cloud findings = %d, want 1", len(cloud))
	}
	if f, _ := cloud[0].(map[string]any); f["scanner"] != "prowler" || f["file_path"] != "arn:aws:iam::1:root" {
		t.Errorf("cloud finding = %v", f)
	}

	// The Prowler check (iam_root_mfa_enabled) maps to CIS AWS control 1.5.
	_, cis := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/compliance/cis-aws-3.0", token, "")
	if cis["failing_controls"] != float64(1) {
		t.Errorf("CIS failing controls = %v, want 1", cis["failing_controls"])
	}
	cisControls, _ := cis["controls"].([]any)
	var cis15Failing bool
	for _, raw := range cisControls {
		if c, _ := raw.(map[string]any); c["code"] == "1.5" && c["passing"] == false {
			cis15Failing = true
		}
	}
	if !cis15Failing {
		t.Error("expected CIS 1.5 (root MFA) to be failing")
	}

	// Portfolio: the rollup sees this project, its cloud + appsec findings, and
	// both frameworks' average scores.
	_, pf := req(t, app, http.MethodGet, "/api/v1/portfolio", token, "")
	if pf["projects"] != float64(1) {
		t.Errorf("portfolio projects = %v, want 1", pf["projects"])
	}
	byCat, _ := pf["open_by_category"].(map[string]any)
	if byCat["cloud"] != float64(1) || byCat["sca"] == nil {
		t.Errorf("portfolio open_by_category = %v, want cloud + sca present", byCat)
	}
	if pfComp, _ := pf["compliance"].([]any); len(pfComp) < 2 {
		t.Errorf("portfolio compliance frameworks = %d, want >= 2 (OWASP + CIS)", len(pfComp))
	}
	if top, _ := pf["top_projects"].([]any); len(top) != 1 {
		t.Errorf("portfolio top_projects = %d, want 1", len(top))
	}

	// Exceptions: won't fix on the cloud finding with an already-past expiry,
	// then run the sweep — it must reopen.
	cloudID, _ := cloud[0].(map[string]any)["id"].(string)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	_, accepted := req(t, app, http.MethodPatch, "/api/v1/findings/"+cloudID, token,
		`{"status":"wont_fix","reason":"waiver","expires_at":"`+past+`"}`)
	if accepted["status"] != "wont_fix" || accepted["exception_reason"] != "waiver" {
		t.Errorf("won't-fix finding = %v", accepted)
	}
	_, hist := req(t, app, http.MethodGet, "/api/v1/findings/"+cloudID+"/exceptions", token, "")
	if h, _ := hist["exceptions"].([]any); len(h) != 1 {
		t.Errorf("exception history = %d, want 1", len(h))
	}
	_, swept := req(t, app, http.MethodPost, "/api/v1/findings/expire-exceptions", token, "")
	if swept["expired"] != float64(1) {
		t.Errorf("expired = %v, want 1", swept["expired"])
	}
	_, reopened := req(t, app, http.MethodGet, "/api/v1/findings/"+cloudID, token, "")
	if reopened["status"] != "open" || reopened["exception_expires_at"] != nil {
		t.Errorf("finding not reopened after expiry: status=%v expires=%v", reopened["status"], reopened["exception_expires_at"])
	}

	// Expiring-soon: "accept risk" on the SCA finding with a future expiry
	// requests a risk acceptance; once approved, the finding appears in the
	// expiring queue and the portfolio count.
	fut := time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339)
	resp, ra := req(t, app, http.MethodPatch, "/api/v1/findings/"+scaID, token,
		`{"status":"risk_accepted","reason":"tracked in JIRA","expires_at":"`+fut+`"}`)
	if resp.StatusCode != http.StatusAccepted || ra["state"] != "requested" {
		t.Fatalf("accept risk = %d %v, want 202 + a requested risk acceptance", resp.StatusCode, ra)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/risk-acceptances/"+ra["id"].(string)+"/approve", token, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("approve risk acceptance = %d", resp.StatusCode)
	}
	_, expiring := req(t, app, http.MethodGet, "/api/v1/findings/expiring?days=30", token, "")
	if ef, _ := expiring["findings"].([]any); len(ef) != 1 {
		t.Errorf("expiring findings = %d, want 1", len(ef))
	}
	_, pf2 := req(t, app, http.MethodGet, "/api/v1/portfolio", token, "")
	if pf2["expiring_soon"] != float64(1) {
		t.Errorf("portfolio expiring_soon = %v, want 1", pf2["expiring_soon"])
	}

	// Notifications: a webhook channel receives a synchronous test event.
	var mu sync.Mutex
	var received []string
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		received = append(received, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	_, chBody := req(t, app, http.MethodPost, "/api/v1/notifications/channels", token,
		`{"name":"ci","type":"webhook","url":"`+hook.URL+`","events":["*"]}`)
	chID, _ := chBody["id"].(string)
	if chID == "" {
		t.Fatal("channel creation returned no id")
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/notifications/channels/"+chID+"/test", token, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("channel test = %d", resp.StatusCode)
	}
	mu.Lock()
	got := len(received) == 1 && strings.Contains(received[0], `"type":"test"`)
	mu.Unlock()
	if !got {
		t.Errorf("webhook did not receive the test event: %v", received)
	}

	// Per-type target validation, and the test endpoint on a non-webhook type.
	for _, bad := range []string{
		`{"name":"x","type":"teams","url":"ftp://nope"}`,
		`{"name":"x","type":"pager","url":"https://x.example"}`,
		`{"name":"x","type":"email","url":"not-an-address"}`,
	} {
		if resp, _ := req(t, app, http.MethodPost, "/api/v1/notifications/channels", token, bad); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("create %s = %d, want 400", bad, resp.StatusCode)
		}
	}
	if resp, e := req(t, app, http.MethodPost, "/api/v1/notifications/channels", token,
		`{"name":"mail","type":"email","url":"alice@example.com"}`); resp.StatusCode != http.StatusBadRequest || e["error"] != "SMTP is not configured" {
		t.Errorf("email without SMTP = %d %v, want 400 SMTP is not configured", resp.StatusCode, e)
	}
	_, mmBody := req(t, app, http.MethodPost, "/api/v1/notifications/channels", token,
		`{"name":"mm","type":"mattermost","url":"`+hook.URL+`","events":["finding.critical"]}`)
	mmID, _ := mmBody["id"].(string)
	if resp, sent := req(t, app, http.MethodPost, "/api/v1/notifications/channels/"+mmID+"/test", token, ""); resp.StatusCode != http.StatusOK || sent["sent"] != true {
		t.Fatalf("mattermost test = %d %v", resp.StatusCode, sent)
	}
	mu.Lock()
	got = len(received) == 2 && strings.Contains(received[1], `"username":"Xila"`)
	mu.Unlock()
	if !got {
		t.Errorf("mattermost test payload not received: %v", received)
	}
	// Per-channel rules: a minimum severity and a weekly summary, then bad values.
	resp, edited := req(t, app, http.MethodPatch, "/api/v1/notifications/channels/"+mmID, token,
		`{"min_severity":"high","summary":"weekly","summary_weekday":5,"summary_hour":7}`)
	if resp.StatusCode != http.StatusOK || edited["min_severity"] != "high" || edited["summary"] != "weekly" ||
		edited["summary_weekday"] != float64(5) || edited["summary_hour"] != float64(7) || edited["name"] != "mm" {
		t.Errorf("edit channel = %d %v", resp.StatusCode, edited)
	}
	if resp, again := req(t, app, http.MethodPatch, "/api/v1/notifications/channels/"+mmID, token, `{"enabled":false}`); resp.StatusCode != http.StatusOK ||
		again["min_severity"] != "high" || again["summary"] != "weekly" || again["enabled"] != false {
		t.Errorf("a partial edit must keep the other settings: %d %v", resp.StatusCode, again)
	}
	for _, bad := range []string{`{"min_severity":"urgent"}`, `{"summary":"hourly"}`, `{"summary_hour":24}`, `{"summary_weekday":7}`} {
		if resp, _ := req(t, app, http.MethodPatch, "/api/v1/notifications/channels/"+mmID, token, bad); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("edit %s = %d, want 400", bad, resp.StatusCode)
		}
	}

	// Global triage inbox: cross-project list with pagination + KEV filter.
	_, inbox := req(t, app, http.MethodGet, "/api/v1/findings?limit=100&sort=priority", token, "")
	if inbox["pagination"] == nil {
		t.Error("global findings list missing pagination envelope")
	}
	if inboxF, _ := inbox["findings"].([]any); len(inboxF) < 3 {
		t.Errorf("global findings = %d, want >= 3", len(inboxF))
	}
	_, kevOnly := req(t, app, http.MethodGet, "/api/v1/findings?kev=true", token, "")
	kf, _ := kevOnly["findings"].([]any)
	if len(kf) != 1 {
		t.Fatalf("KEV findings = %d, want 1", len(kf))
	}
	if f, _ := kf[0].(map[string]any); f["kev"] != true {
		t.Errorf("kev filter returned non-KEV finding: %v", f)
	}
}

// TestSmokeIssueTracker drives the issue-tracker flow end to end against a fake
// GitHub: configure (token write-only), test, create an issue (idempotent),
// auto-create over the threshold, and sync a triage decision to the issue.
func TestSmokeIssueTracker(t *testing.T) {
	app := newTestApp(t)

	var (
		mu      sync.Mutex
		created []map[string]any
		patches []map[string]any
		states  = map[string]string{}
	)
	gh := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.Header.Get("Authorization") != "Bearer ghp_smoke_secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/acme/web":
			_, _ = w.Write([]byte(`{"full_name":"acme/web"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/repos/acme/web/issues":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			created = append(created, body)
			n := strconv.Itoa(len(created))
			states[n] = "open"
			_, _ = w.Write([]byte(`{"number":` + n + `,"html_url":"https://github.test/acme/web/issues/` + n + `","state":"open"}`))
		case strings.HasPrefix(r.URL.Path, "/repos/acme/web/issues/"):
			n := strings.TrimPrefix(r.URL.Path, "/repos/acme/web/issues/")
			if r.Method == http.MethodPatch {
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				patches = append(patches, body)
				states[n], _ = body["state"].(string)
			}
			_, _ = w.Write([]byte(`{"number":` + n + `,"state":"` + states[n] + `"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer gh.Close()

	creds := `{"email":"tracker@xila.io","password":"supersecret"}`
	req(t, app, http.MethodPost, "/api/v1/auth/register", "", creds)
	_, login := req(t, app, http.MethodPost, "/api/v1/auth/login", "", creds)
	token, _ := login["token"].(string)
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", token, `{"slug":"acme","name":"Acme"}`)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgBody["id"].(string)+"/teams", token, `{"slug":"platform","name":"Platform"}`)
	_, projBody := req(t, app, http.MethodPost, "/api/v1/teams/"+teamBody["id"].(string)+"/projects", token, `{"slug":"web","name":"Web"}`)
	projectID, _ := projBody["id"].(string)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/scans?scanner=trivy", token, smokeTrivyReport); resp.StatusCode != http.StatusCreated {
		t.Fatalf("ingest = %d", resp.StatusCode)
	}

	trackerPath := "/api/v1/projects/" + projectID + "/issue-tracker"
	if resp, _ := req(t, app, http.MethodGet, trackerPath, token, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unconfigured tracker = %d, want 404", resp.StatusCode)
	}
	cfgBody := `{"kind":"github","base_url":"` + gh.URL + `","target":"acme/web","min_severity":"critical","labels":["security"]`
	if resp, _ := req(t, app, http.MethodPut, trackerPath, token, cfgBody+`}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("tracker without token = %d, want 400", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPut, trackerPath, token, `{"kind":"github","target":"no-slash","token":"x"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("github target without owner/repo = %d, want 400", resp.StatusCode)
	}
	resp, tr := req(t, app, http.MethodPut, trackerPath, token, cfgBody+`,"token":"ghp_smoke_secret"}`)
	if resp.StatusCode != http.StatusOK || tr["has_token"] != true || tr["kind"] != "github" || tr["enabled"] != true {
		t.Fatalf("put tracker = %d %v", resp.StatusCode, tr)
	}
	if raw, _ := json.Marshal(tr); strings.Contains(string(raw), "ghp_smoke_secret") {
		t.Errorf("tracker response leaks the token: %s", raw)
	}
	if resp, ok := req(t, app, http.MethodPost, trackerPath+"/test", token, ""); resp.StatusCode != http.StatusOK || ok["ok"] != true {
		t.Errorf("tracker test = %d %v", resp.StatusCode, ok)
	}

	_, crit := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings?severity=critical", token, "")
	critID, _ := crit["findings"].([]any)[0].(map[string]any)["id"].(string)
	issuePath := "/api/v1/findings/" + critID + "/issue"
	if resp, _ := req(t, app, http.MethodGet, issuePath, token, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unlinked finding issue = %d, want 404", resp.StatusCode)
	}
	resp, link := req(t, app, http.MethodPost, issuePath, token, "")
	if resp.StatusCode != http.StatusCreated || link["external_id"] != "1" || link["state"] != "open" ||
		link["url"] != "https://github.test/acme/web/issues/1" {
		t.Fatalf("create issue = %d %v", resp.StatusCode, link)
	}
	if resp, again := req(t, app, http.MethodPost, issuePath, token, ""); resp.StatusCode != http.StatusOK || again["id"] != link["id"] {
		t.Errorf("second create = %d %v, want 200 with the same link", resp.StatusCode, again)
	}
	mu.Lock()
	if len(created) != 1 {
		t.Fatalf("issues created = %d, want 1 (idempotent)", len(created))
	}
	if title, _ := created[0]["title"].(string); !strings.HasPrefix(title, "[critical] ") {
		t.Errorf("issue title = %q", title)
	}
	if body, _ := created[0]["body"].(string); !strings.Contains(body, "https://xila.test/findings/"+critID) ||
		!strings.Contains(body, "Package: pkgA@1.0") || !strings.Contains(body, "CVE-2020-1") {
		t.Errorf("issue body = %q", body)
	}
	mu.Unlock()

	// Lowering the threshold with auto-create on files the high secret finding;
	// the token is kept when omitted.
	if resp, tr := req(t, app, http.MethodPut, trackerPath, token,
		`{"kind":"github","base_url":"`+gh.URL+`","target":"acme/web","min_severity":"high","auto_create":true}`); resp.StatusCode != http.StatusOK || tr["has_token"] != true {
		t.Fatalf("update tracker = %d %v", resp.StatusCode, tr)
	}
	_, res := req(t, app, http.MethodPost, "/api/v1/issue-trackers/sync", token, "")
	if res["created"] != float64(1) || res["errors"] != float64(0) {
		t.Errorf("auto-create sync = %v, want 1 created, no errors", res)
	}

	// A triage decision in Xila closes the issue.
	req(t, app, http.MethodPatch, "/api/v1/findings/"+critID, token, `{"status":"false_positive","reason":"test fixture"}`)
	_, res = req(t, app, http.MethodPost, "/api/v1/issue-trackers/sync", token, "")
	if res["closed_issues"] != float64(1) || res["created"] != float64(0) {
		t.Errorf("sync after triage = %v, want 1 closed issue", res)
	}
	if _, l := req(t, app, http.MethodGet, issuePath, token, ""); l["state"] != "closed" {
		t.Errorf("link after sync = %v, want closed", l)
	}

	if resp, _ := req(t, app, http.MethodDelete, trackerPath, token, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete tracker = %d, want 204", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, issuePath, token, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("link after tracker delete = %d, want 404", resp.StatusCode)
	}
}

// TestSmokeCustomParser exercises the no-code parser management + upload
// path end to end (M12 12.4): an instance admin defines a CSV mapping, a
// dry-run previews it against a pasted sample, a name colliding with a
// built-in scanner is refused, a non-admin is refused management, an upload
// through ?scanner=<custom> creates findings with the mapped fields, and
// re-uploading the identical report keeps the same fingerprints (no
// duplicates).
func TestSmokeCustomParser(t *testing.T) {
	app := newTestApp(t)

	// First user bootstraps as the instance admin.
	adminCreds := `{"email":"admin@xila.io","password":"supersecret"}`
	req(t, app, http.MethodPost, "/api/v1/auth/register", "", adminCreds)
	_, loginBody := req(t, app, http.MethodPost, "/api/v1/auth/login", "", adminCreds)
	adminToken, _ := loginBody["token"].(string)
	if adminToken == "" {
		t.Fatal("admin login returned no token")
	}

	// A second account is a regular (non-admin) user.
	userCreds := `{"email":"analyst@xila.io","password":"supersecret"}`
	req(t, app, http.MethodPost, "/api/v1/auth/register", "", userCreds)
	_, userLogin := req(t, app, http.MethodPost, "/api/v1/auth/login", "", userCreds)
	userToken, _ := userLogin["token"].(string)
	if userToken == "" {
		t.Fatal("analyst login returned no token")
	}

	def := `{"name":"acme-scanner","category":"sca","format":"csv",
		"fields":{"title":{"path":"Name"},"severity":{"path":"Sev","value_map":{"4":"critical"}},"cve":{"path":"Notes"}}}`
	sample := "Name,Sev,Notes\nOutdated libfoo,4,see CVE-2021-44228\n"

	// Management is instance-admin only.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/custom-parsers", userToken, def); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("non-admin create = %d, want 403", resp.StatusCode)
	}

	// A name colliding with a built-in parser is refused.
	collide := `{"name":"trivy","category":"sca","format":"csv","fields":{"title":{"path":"Name"}}}`
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/custom-parsers", adminToken, collide); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("collide with built-in = %d, want 400", resp.StatusCode)
	}

	// Dry-run previews the mapping against a pasted sample without persisting.
	dryRunBody := `{"name":"acme-scanner","category":"sca","format":"csv",
		"fields":{"title":{"path":"Name"},"severity":{"path":"Sev","value_map":{"4":"critical"}},"cve":{"path":"Notes"}},
		"sample":"Name,Sev,Notes\nOutdated libfoo,4,see CVE-2021-44228\n"}`
	resp, dryRun := req(t, app, http.MethodPost, "/api/v1/custom-parsers/dry-run", adminToken, dryRunBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("dry-run = %d", resp.StatusCode)
	}
	dryFindings, _ := dryRun["findings"].([]any)
	if len(dryFindings) != 1 {
		t.Fatalf("dry-run findings = %d, want 1: %v", len(dryFindings), dryRun)
	}
	first, _ := dryFindings[0].(map[string]any)
	if first["title"] != "Outdated libfoo" || first["severity"] != "critical" {
		t.Errorf("dry-run finding = %v, want title/severity mapped", first)
	}
	if _, listNoParsers := req(t, app, http.MethodGet, "/api/v1/custom-parsers", adminToken, ""); listNoParsers["custom_parsers"] == nil {
		t.Fatal("list custom parsers returned no body")
	}

	// Create the parser for real.
	resp, created := req(t, app, http.MethodPost, "/api/v1/custom-parsers", adminToken, def)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create custom parser = %d: %v", resp.StatusCode, created)
	}
	parserID, _ := created["id"].(string)
	if parserID == "" {
		t.Fatal("create custom parser returned no id")
	}

	// A second attempt at the same name is refused (unique constraint).
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/custom-parsers", adminToken, def); resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate name = %d, want 409", resp.StatusCode)
	}

	// Set up a project to upload against.
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", adminToken, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", adminToken, `{"slug":"platform","name":"Platform"}`)
	teamID, _ := teamBody["id"].(string)
	_, projBody := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", adminToken, `{"slug":"web","name":"Web"}`)
	projectID, _ := projBody["id"].(string)
	if projectID == "" {
		t.Fatal("project creation returned no id")
	}

	// Upload through the custom parser's scanner name.
	scanPath := "/api/v1/projects/" + projectID + "/scans?scanner=acme-scanner"
	resp, scanBody := req(t, app, http.MethodPost, scanPath, adminToken, sample)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("custom parser upload = %d: %v", resp.StatusCode, scanBody)
	}
	if scanBody["status"] != "completed" {
		t.Errorf("scan status = %v, want completed", scanBody["status"])
	}

	_, listBody := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings", adminToken, "")
	findings, _ := listBody["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(findings))
	}
	f, _ := findings[0].(map[string]any)
	if f["title"] != "Outdated libfoo" || f["severity"] != "critical" {
		t.Errorf("finding = %v, want mapped title/severity", f)
	}
	if cves, _ := f["cve"].([]any); len(cves) != 1 || cves[0] != "CVE-2021-44228" {
		t.Errorf("finding cve = %v, want [CVE-2021-44228]", f["cve"])
	}

	// Re-uploading the identical report keeps the same fingerprint: no
	// duplicate finding.
	req(t, app, http.MethodPost, scanPath, adminToken, sample)
	_, listAgain := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings", adminToken, "")
	findingsAgain, _ := listAgain["findings"].([]any)
	if len(findingsAgain) != 1 {
		t.Errorf("after re-upload got %d findings, want 1 (deduplicated)", len(findingsAgain))
	}

	// Deleting the definition keeps its findings (they stay under the
	// "acme-scanner" scanner name as history), but the upload path no longer
	// accepts it.
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/custom-parsers/"+parserID, adminToken, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete custom parser = %d", resp.StatusCode)
	}
	_, listAfterDelete := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings", adminToken, "")
	findingsAfterDelete, _ := listAfterDelete["findings"].([]any)
	if len(findingsAfterDelete) != 1 {
		t.Errorf("after deleting the parser, findings = %d, want 1 (history kept)", len(findingsAfterDelete))
	}
	if resp, _ := req(t, app, http.MethodPost, scanPath, adminToken, sample); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("upload after deleting the parser = %d, want 400 (unknown scanner)", resp.StatusCode)
	}
}
