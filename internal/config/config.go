// Package config loads runtime configuration from environment variables.
package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/netguard"
)

// Recognized deployment environments (APP_ENV).
const (
	EnvDevelopment = "development"
	EnvProduction  = "production"
	EnvTest        = "test"
)

const insecureDevSecret = "insecure-development-secret-change-me"

// Config is the fully resolved application configuration.
type Config struct {
	Env      string
	HTTP     HTTP
	DB       DB
	JWT      JWT
	OIDC     OIDC
	SAML     SAML
	LDAP     LDAP
	SSO      SSO
	SMTP     SMTP
	Otel     Otel
	Metrics  Metrics
	Security Security
	Policy   Policy
	Enrich   Enrich
	Exploit  ExploitIntel
	CRA      CRA
	NVD      NVD
	AI       AI
	Notify   Notify
	Ingest   Ingest
	// S3 is the object-storage connection used when Ingest.PayloadStore is
	// "s3" (M11 11.8).
	S3        S3
	VulnMatch VulnMatch
	// PSIRT publishes CSAF security advisories about the instance's own
	// products.
	PSIRT   PSIRT
	PkgMeta PkgMeta
	// AuthRateLimit throttles password sign-in/registration/reset attempts
	// (Postgres-backed, shared across replicas).
	AuthRateLimit AuthRateLimit
	// ServiceAccounts bounds service-account keys and federated sessions.
	ServiceAccounts ServiceAccounts

	// ExceptionSweepInterval is how often lapsed risk acceptances are reopened.
	ExceptionSweepInterval time.Duration
	// SLASweepInterval is how often breached / due-soon SLAs are alerted on (0 = off).
	SLASweepInterval time.Duration
	// Retention is what housekeeping deletes (0 = keep forever).
	Retention Retention
	// TriageRulesRequireApproval turns on the four-eyes workflow for triage
	// rules: created/edited rules stay pending (and never apply) until a
	// different admin approves them.
	TriageRulesRequireApproval bool
	// AssessmentRequiresApproval turns on the four-eyes workflow for manual
	// assessments: an analyst's status / severity change on a finding becomes a
	// pending request until a different project owner (or instance admin)
	// approves it.
	AssessmentRequiresApproval bool
	// RiskAcceptanceRequiresApproval turns on four-eyes for risk acceptances:
	// a request must be approved (or rejected) by a project owner other than
	// its requester, and imported risk acceptances wait as requests. Default
	// on in production.
	RiskAcceptanceRequiresApproval bool
	// RiskAcceptanceExpiryWarning is how far ahead of its expiry an approved
	// risk acceptance is announced as expiring (0 = never).
	RiskAcceptanceExpiryWarning time.Duration
	// IntegrationSecretKey (INTEGRATION_SECRET_KEY) is the base64-encoded
	// 32-byte AES-256 key that encrypts integration credentials (issue-tracker
	// and connector tokens) at rest. Empty means trackers and connectors can't be
	// configured. A malformed key fails boot; read the decoded bytes with
	// IntegrationKey.
	IntegrationSecretKey string
	// PublicURL is the externally reachable UI origin (e.g. https://xila.example.com),
	// used for links back to Xila in outbound content such as issue bodies.
	// Empty omits the links.
	PublicURL string
	// SourceURL (SOURCE_URL) is where users get this instance's source code,
	// linked from every page of the UI. Xila is AGPL-3.0: whoever runs a
	// modified version for users over a network must offer them its source
	// (section 13), so point this at your fork.
	SourceURL string
	// IssueSyncInterval is how often issue-tracker state is synced both ways and
	// auto-create runs (0 = off).
	IssueSyncInterval time.Duration
	// RemediationSweepInterval is how often open findings are grouped into
	// remediation actions and live actions are refreshed (due date, owner,
	// auto-close) (0 = off; ingest still runs it per scan).
	RemediationSweepInterval time.Duration
	// RemediationAutoCreate turns every proposed remediation action into an
	// action automatically instead of waiting for a user to accept it.
	RemediationAutoCreate bool
	// ConnectorPullInterval is how often each enabled Dependency-Track /
	// DefectDojo connector is pulled (0 = off; "pull now" still works).
	ConnectorPullInterval time.Duration
	// MetricsSnapshotInterval is how often today's and yesterday's metric
	// snapshots are (re)computed for the trend charts (0 = off).
	MetricsSnapshotInterval time.Duration
	// PortfolioFromSnapshots (PORTFOLIO_FROM_SNAPSHOTS) serves /portfolio's
	// finding counts from the latest metric snapshots instead of scanning
	// findings per request (as of the last snapshot run).
	PortfolioFromSnapshots bool
	// PasswordLoginEnabled (PASSWORD_LOGIN_ENABLED, default true) allows email +
	// password sign-in. When false, registration is closed once the instance has
	// a user and POST /auth/login only admits the instance owner (break-glass,
	// logged); everyone else signs in via SSO. API tokens are unaffected.
	PasswordLoginEnabled bool
	// MCPEnabled (MCP_ENABLED, default false) serves the MCP server for AI
	// agents at POST /api/v1/mcp, under the caller's token and permissions.
	MCPEnabled bool
	// LegacyLicenseDenylist records that the removed LICENSE_DENYLIST is still
	// set, so Warnings can say it is ignored.
	LegacyLicenseDenylist bool
}

// IsProduction reports whether the app runs in the production environment.
func (c Config) IsProduction() bool { return c.Env == EnvProduction }

// IsDevelopment reports whether the app runs in the development environment.
func (c Config) IsDevelopment() bool { return c.Env == EnvDevelopment }

// Security holds hardening settings whose safe defaults follow the environment.
type Security struct {
	// AllowedOrigins is the CORS allow-list. Empty means same-origin only (the
	// embedded SPA); ["*"] allows any origin (dev default).
	AllowedOrigins []string
	// TrustedProxies, when set, makes the server trust X-Forwarded-* headers from
	// these addresses (correct client IP + scheme behind a load balancer).
	TrustedProxies []string
	// CookieSecure sets the Secure flag on auth cookies (default: production).
	CookieSecure bool
	// Outbound limits where server-side requests to configured URLs (issue
	// trackers, connectors, SSO issuers, webhooks, mirrors) may go. Link-local
	// and cloud-metadata addresses are always refused.
	OutboundAllowPrivate  bool     // OUTBOUND_ALLOW_PRIVATE (default true: self-hosted trackers live there)
	OutboundAllowLoopback bool     // OUTBOUND_ALLOW_LOOPBACK (default: development only)
	OutboundAllowedHosts  []string // OUTBOUND_ALLOWED_HOSTS: exempt from the private/loopback rules
}

// Retention is housekeeping (internal/retention). Rules that delete analysis
// data default off; the delivery log / failed-job sweep and branch pruning are
// on. Never touches a version's current SBOMs, a finding's last scan, the
// latest scan of a target, or a project's default version.
type Retention struct {
	BranchAge  time.Duration // BRANCH_RETENTION: stale non-default branches (default 90 days)
	ReleaseAge time.Duration // RELEASE_RETENTION: stale non-default releases (default off)
	SBOMKeep   int           // SBOM_RETENTION_KEEP: newest snapshots kept per artifact and version (default off)
	SBOMAge    time.Duration // SBOM_RETENTION_AGE: older snapshots deleted only past this age (default off)
	ScanAge    time.Duration // SCAN_RETENTION: old scan records (default off)
	LogAge     time.Duration // LOG_RETENTION: delivery log + failed ingest jobs (default 90 days)
	AuditAge   time.Duration // AUDIT_RETENTION: audit log entries (default 365 days)
	ArchiveAge time.Duration // ARCHIVE_RETENTION: archived records stay restorable this long, then are purged (default 30 days)
	// FindingArchiveAfter (FINDING_ARCHIVE_AFTER) archives remediated findings
	// fixed longer ago than this (default off), so live queries stop carrying
	// them; ARCHIVE_RETENTION then purges them. A fixed finding that comes back
	// is unarchived by the next upsert.
	FindingArchiveAfter time.Duration
}

// Notify governs durable notification delivery (the outbox). The leader's
// dispatcher retries a failed send with exponential backoff (RetryBase,
// doubling, capped at RetryMax) until MaxAttempts, across restarts.
type Notify struct {
	MaxAttempts      int           // NOTIFY_MAX_ATTEMPTS
	RetryBase        time.Duration // NOTIFY_RETRY_BASE
	RetryMax         time.Duration // NOTIFY_RETRY_MAX
	Retention        time.Duration // NOTIFY_RETENTION: keep finished outbox rows
	DispatchInterval time.Duration // NOTIFY_DISPATCH_INTERVAL: how often the leader polls the outbox
}

// Policy holds the component policy engine's schedule.
type Policy struct {
	// EvalInterval is how often every project is re-evaluated against the
	// policies (0 = off; uploads and policy edits still evaluate), catching
	// KEV/EPSS, outdated and license-data changes.
	EvalInterval time.Duration
}

// Enrich holds the exploit-intel enrichment schedule and its KEV catalogs.
type Enrich struct {
	Enabled  bool
	Interval time.Duration
	// KEVSources are the KEV catalogs to download: cisa, enisa (default) and
	// vulncheck (added by default when VulnCheckToken is set).
	KEVSources []string
	// KEVURLs overrides a catalog's URL (a mirror), keyed by catalog name.
	KEVURLs        map[string]string
	VulnCheckToken string
}

// defaultKEVSources: CISA and ENISA, plus VulnCheck once a token is set.
func defaultKEVSources(vulnCheckToken string) []string {
	if vulnCheckToken != "" {
		return []string{"cisa", "enisa", "vulncheck"}
	}
	return []string{"cisa", "enisa"}
}

// ExploitIntel syncs public-exploit feeds (ExploitDB, Metasploit, Nuclei) and
// marks findings with the strongest exploit known for their CVEs.
type ExploitIntel struct {
	Enabled  bool
	Interval time.Duration
	Sources  []string
	// URLs overrides a source's feed URL (a mirror), keyed by source name.
	URLs map[string]string
}

// CRA is the EU Cyber Resilience Act Article 14 reporting setup: the
// manufacturer every report names, and how often case deadlines are checked.
type CRA struct {
	ManufacturerName    string
	ManufacturerAddress string
	ManufacturerContact string // reporting contact (e-mail)
	// MemberState is the main establishment in the Union (ISO 3166-1
	// alpha-2): its CSIRT designated as coordinator receives the reports.
	MemberState   string
	SweepInterval time.Duration
}

// NVD enriches findings with CVSS vectors/scores from the NVD CVE API 2.0 on
// the enrichment schedule. Off by default: without an API key NVD allows 5
// requests per 30 s, so a large backlog takes a while.
type NVD struct {
	Enabled bool
	APIKey  string
	URL     string // override (tests, proxies); empty = services.nvd.nist.gov
}

// AI is opt-in AI-assisted triage (internal/aitriage): a bring-your-own
// model proposes a verdict, an exploitability assessment or a fix for one
// finding; a person accepts or rejects it. Off by default.
type AI struct {
	Enabled bool // AI_TRIAGE_ENABLED
	// Provider is the wire protocol: openai-compatible (OpenAI, Azure OpenAI
	// compatible gateways, vLLM, Ollama, LM Studio…) or anthropic.
	Provider string
	// BaseURL is the API root: e.g. https://api.openai.com/v1 (…/chat/completions
	// is appended) or https://api.anthropic.com (the default for anthropic;
	// …/v1/messages is appended).
	BaseURL string
	Model   string
	// APIKey (AI_API_KEY) is a secret: only ever sent to the provider, never
	// logged or returned.
	APIKey string
	// RateLimit is how many AI requests one project may make per hour.
	RateLimit int
	Timeout   time.Duration
}

// AI providers (AI_PROVIDER).
const (
	AIProviderOpenAI    = "openai-compatible"
	AIProviderAnthropic = "anthropic"
)

// VulnMatch keeps stored SBOMs alive: on an interval it re-evaluates the current
// component inventory against the configured advisory sources, so
// vulnerabilities disclosed after an SBOM was uploaded still surface without a
// re-scan.
type VulnMatch struct {
	Enabled  bool
	Interval time.Duration
	// Sources are the advisory sources merged into one result: osv (OSV.dev
	// API), github (GitHub Advisory Database), osv-local (the imported OSV
	// mirror — air-gapped), private (internal advisories), nvd (CPE matching
	// for components without a purl; uses NVD_URL / NVD_API_KEY).
	Sources     []string
	OSVURL      string // override for testing; empty = public OSV.dev
	GitHubURL   string // empty = api.github.com (GHES: https://host/api/v3)
	GitHubToken string // optional; lifts GitHub's anonymous 60 requests/hour
	// OSVMirrorURL + OSVEcosystems schedule downloads of OSV ecosystem exports
	// (<url>/<Ecosystem>/all.zip) into the local mirror every
	// OSVMirrorInterval. No ecosystems = no download (import by upload only).
	OSVMirrorURL      string
	OSVEcosystems     []string
	OSVMirrorInterval time.Duration
	// VulnerableCode (vulnerablecode source): instance base URL (empty =
	// public.vulnerablecode.io) and API key (the public instance requires one).
	VulnerableCodeURL    string
	VulnerableCodeAPIKey string
	// JVN iPedia (jvn source, alias enrichment): feed base URL, the first
	// year downloaded into an empty mirror, and the refresh interval.
	JVNURL      string
	JVNFromYear int
	JVNInterval time.Duration
}

// PSIRT configures CSAF advisory publishing. Public serves released
// advisories unauthenticated as a CSAF provider directory
// (/.well-known/csaf/provider-metadata.json); otherwise only admins can
// download them.
type PSIRT struct {
	Public             bool
	AdvisoryPrefix     string // tracking ids are <prefix>-<year>-<NNNN>
	PublisherName      string
	PublisherNamespace string // the publisher's URL (CSAF publisher.namespace)
	PublisherContact   string
}

// AuthRateLimit throttles password sign-in attempts. A zero max disables that
// bucket.
type AuthRateLimit struct {
	IPPerMinute   int           // per client IP, per minute (offices share an IP: keep it generous)
	Account       int           // per account (email) per AccountWindow
	AccountWindow time.Duration //
}

// ServiceAccounts bounds the credentials of non-human principals.
type ServiceAccounts struct {
	// KeyMaxDays caps an API key's lifetime (the default is 30 days, or this
	// when lower).
	KeyMaxDays int
	// TokenTTL is the lifetime of a session minted by the workload-identity
	// token exchange (POST /auth/token); at most an hour.
	TokenTTL time.Duration
}

// PkgMeta keeps package registry metadata (latest versions) fresh for current
// SBOM inventory, so components show whether they're outdated. Air-gapped
// installs disable it; internal mirrors (Artifactory, Nexus) replace the
// public registries per ecosystem.
type PkgMeta struct {
	Enabled  bool
	Interval time.Duration // how often a sweep refreshes stale packages
	TTL      time.Duration // how long fetched metadata stays fresh
	// Concurrency is the packages fetched in parallel per registry;
	// RequestsPerSecond caps each registry's request rate.
	Concurrency       int
	RequestsPerSecond int
	// URLs maps a purl type (npm, pypi, maven, golang, cargo, nuget, gem,
	// composer) to its registry base URL; unset = the public registry.
	URLs map[string]string
}

// Ingest configures scan ingestion. When Async, uploads are queued (202) and a
// pool of Workers drains them via the durable Postgres queue — the scaling path
// for high upload volume.
type Ingest struct {
	Async        bool
	Workers      int
	PollInterval time.Duration // how often idle workers poll the queue
	MaxAttempts  int           // retries before a job is parked as failed

	// MaxQueueDepth is the number of pending jobs at which uploads start being
	// rejected with 429 instead of being queued. 0 accepts unboundedly.
	MaxQueueDepth int
	// QueueSampleInterval is how often the queue depth is measured (for metrics
	// and the backpressure decision).
	QueueSampleInterval time.Duration
	// SkipUnchanged short-circuits a scan whose parsed content hash matches its
	// target's previous completed scan: no re-upsert, auto-close, appliers,
	// dedup or alert, just a cheap record of the repeat (M11 11.4). A per-upload
	// force=true always processes in full.
	SkipUnchanged bool
	// PayloadStore (INGEST_PAYLOAD_STORE) is where a queued job's raw upload
	// lives between Enqueue and the worker's ProcessJob: "postgres"
	// (scan_jobs.payload, the default) or "s3" (any S3-compatible object
	// storage; scan_jobs keeps only payload_ref). See internal/objectstore
	// and M11 11.8.
	PayloadStore string
}

// S3 is the object-storage connection for Ingest.PayloadStore=s3
// (internal/objectstore.Config). Any S3-compatible service works: AWS S3,
// MinIO, Ceph, Cloudflare R2, GCS's S3 interop.
type S3 struct {
	// Endpoint overrides AWS's regional endpoint. Required for everything but
	// AWS S3 itself.
	Endpoint string
	Region   string
	Bucket   string
	// Prefix is joined under every object key ("" = bucket root).
	Prefix string
	// AccessKeyID / SecretAccessKey are static credentials. Leave both unset
	// to use the standard AWS credential chain instead (environment,
	// ~/.aws/credentials, EC2/ECS instance credentials, EKS IRSA).
	AccessKeyID     string
	SecretAccessKey string
	// ForcePathStyle addresses buckets as /bucket/key — required by most
	// non-AWS S3-compatible services.
	ForcePathStyle bool
}

// HTTP holds the listener configuration and server timeouts.
type HTTP struct {
	Host         string
	Port         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	BodyLimit    int // max request body in bytes (scan/SBOM uploads can be large)
}

// DB holds PostgreSQL connection + pool settings.
type DB struct {
	Host     string
	Port     string
	User     string
	Password string
	Name     string
	SSLMode  string

	// Pool tuning (applied by database.Connect).
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	ConnectTimeout    time.Duration

	// StatementTimeout caps how long any single query may run, so one pathological
	// statement can't pin a connection (and its locks) forever. Applied per pooled
	// connection — never via the DSN, which the migration driver also uses and
	// where a long CREATE INDEX would be killed. Zero disables it.
	StatementTimeout time.Duration

	// ReadURL (DB_READ_URL, a postgres:// URL; secret, so _FILE works) points
	// reporting reads (portfolio, trends, reports) at a read replica; empty =
	// the primary. ReadStatementTimeout (DB_READ_STATEMENT_TIMEOUT) caps those
	// reads separately (zero = StatementTimeout); setting either gives
	// reporting its own pool of ReadMaxConns (DB_READ_MAX_CONNS) connections,
	// so a heavy report can't starve ingest of connections.
	ReadURL              string
	ReadStatementTimeout time.Duration
	ReadMaxConns         int32
	// JobStatementTimeout (DB_JOB_STATEMENT_TIMEOUT) caps the metric snapshot
	// job's queries, which make a full pass over the findings and on a large
	// instance outlast StatementTimeout. They run on a small pool of their own.
	JobStatementTimeout time.Duration
}

// ReadDSN is the reporting pool's DSN: the replica, else the primary.
func (d DB) ReadDSN() string {
	if d.ReadURL != "" {
		return d.ReadURL
	}
	return d.DSN()
}

// SeparateReadPool reports whether reporting reads get their own pool.
func (d DB) SeparateReadPool() bool { return d.ReadURL != "" || d.ReadStatementTimeout > 0 }

// DSN builds a libpq-style connection URL with every part escaped, so a
// password containing "/", "@", "#" or "?" (as `openssl rand -base64` output
// does) still parses. connect_timeout is libpq-standard (safe for both the pool
// and the migration driver); pool_* tuning is applied programmatically, not
// here, so it doesn't reach the database/sql migrator.
func (d DB) DSN() string {
	q := url.Values{"sslmode": {d.SSLMode}}
	if secs := int(d.ConnectTimeout.Seconds()); secs > 0 {
		q.Set("connect_timeout", strconv.Itoa(secs))
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(d.User, d.Password),
		Host:     net.JoinHostPort(d.Host, d.Port),
		Path:     "/" + d.Name,
		RawQuery: q.Encode(),
	}
	return u.String()
}

// JWT holds token signing settings.
type JWT struct {
	Secret string
	TTL    time.Duration
	// ReauthWindow is how recently a session must have authenticated to
	// create an API token (REAUTH_WINDOW; 0 turns the check off).
	ReauthWindow time.Duration
}

// OIDC configures optional Single Sign-On via an OpenID Connect provider
// (Google, Okta, Azure AD, Auth0, Keycloak, …). Disabled unless Enabled + the
// issuer/client fields are set.
type OIDC struct {
	Enabled      bool
	Issuer       string // e.g. https://accounts.google.com
	ClientID     string
	ClientSecret string
	RedirectURL  string // must match the provider's registered callback
	ProviderName string // label shown on the login button
	// Scopes requested (OIDC_SCOPES, default "openid email profile"; openid is
	// always included). Add "groups" only if the IdP needs it to emit groups.
	Scopes []string
	// GroupsClaim is the ID-token claim holding the user's groups; a dotted path
	// reaches nested claims (Keycloak realm roles: realm_access.roles).
	GroupsClaim string
	// TrustUnverifiedEmail treats an ID token *without* an email_verified claim
	// as verified, so it may link to an existing account by email (Entra ID
	// omits the claim). An explicit email_verified=false is never trusted.
	TrustUnverifiedEmail bool
}

// SAML configures optional Single Sign-On via a SAML 2.0 identity provider
// LDAP signs people in against an LDAP / Active Directory directory through the
// normal password form: search the user with a service account, bind as them
// with their password, then link and sync groups like any SSO login.
type LDAP struct {
	Enabled      bool
	URL          string // ldaps://dc.example.com:636 or ldap://… (with StartTLS)
	StartTLS     bool   // upgrade an ldap:// connection (default true for ldap://)
	CACert       string // PEM CA bundle for the directory's certificate (empty = system roots)
	BindDN       string // service account that may search users (empty = anonymous search)
	BindPassword string
	BaseDN       string
	// UserFilter finds the account; {login} is replaced by the (escaped) name
	// typed into the login form.
	UserFilter     string
	EmailAttribute string // mail
	GroupAttribute string // memberOf (group DNs; groups are offered to mappings as DN and as CN)
	UIDAttribute   string // stable id: entryUUID / objectGUID; empty = try both, then the DN
	LinkByEmail    bool   // a first login may attach to an existing account with the directory's email
}

// (Entra ID, Okta, Keycloak, ADFS, …). Xila is the service provider.
type SAML struct {
	Enabled bool
	// IDPMetadataURL is fetched at boot; IDPMetadata is the XML itself (wins
	// when both are set).
	IDPMetadataURL string
	IDPMetadata    string
	// EntityID is the SP entity id (default <PUBLIC_URL>/api/v1/auth/saml/metadata).
	EntityID string
	// SPCert/SPKey (PEM) sign AuthnRequests and decrypt encrypted assertions.
	// Unset: a key pair is generated once and stored in the database, sealed
	// with INTEGRATION_SECRET_KEY, so every replica shares it.
	SPCert string
	SPKey  string
	// ProviderName is the login button label.
	ProviderName string
	// EmailAttribute names the attribute carrying the email; empty tries the
	// common ones, then an emailAddress-format NameID.
	EmailAttribute string
	// GroupsAttributes are the attribute names carrying groups (all are read).
	GroupsAttributes []string
	// AllowIDPInitiated accepts unsolicited responses (IdP dashboard tiles).
	AllowIDPInitiated bool
	// SignRequests signs AuthnRequests (RSA-SHA256).
	SignRequests bool
	// LinkByEmail trusts the IdP's email enough to attach a first login to an
	// existing account with the same email.
	LinkByEmail bool
}

// SSO holds settings shared by every SSO protocol.
type SSO struct {
	// AutoCreateUsers provisions an account on the first SSO login of someone
	// who has none (just-in-time). Off: they get an error until an admin
	// creates their account.
	AutoCreateUsers bool
}

// SMTP configures outbound email for "email" notification channels. Email
// channels can only be created when Host and From are set.
type SMTP struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLS      string // "starttls" (default) | "tls" (implicit) | "none"
}

// Configured reports whether email delivery is possible.
func (s SMTP) Configured() bool { return s.Host != "" && s.From != "" }

// Otel holds OpenTelemetry exporter settings.
type Otel struct {
	Enabled     bool
	Endpoint    string
	ServiceName string
	Insecure    bool
}

// Metrics is the Prometheus scrape endpoint. It exposes the same OpenTelemetry
// instruments the OTLP exporter sends, so it works with or without OTEL_ENABLED.
type Metrics struct {
	Enabled bool   // METRICS_ENABLED
	Addr    string // METRICS_ADDR: a separate listener (e.g. ":9090"); empty = /metrics on the main port
	Token   string // METRICS_TOKEN: bearer token a scraper must send; empty = none
}

// Load reads configuration from the environment, applying sane defaults that
// tighten automatically in production, and validates the result.
func Load() (Config, error) {
	if err := loadDotEnv(); err != nil {
		return Config{}, err
	}
	var sec secretReader
	env := normalizeEnv(getenv("APP_ENV", EnvDevelopment))
	prod := env == EnvProduction

	// CORS defaults: permissive in dev (so a local SPA on :5173 works), locked to
	// same-origin in production unless origins are explicitly listed.
	corsDefault := []string{"*"}
	if prod {
		corsDefault = nil
	}

	cfg := Config{
		Env: env,
		Security: Security{
			AllowedOrigins:        getlist("CORS_ALLOWED_ORIGINS", corsDefault),
			TrustedProxies:        getlist("TRUSTED_PROXIES", nil),
			CookieSecure:          getbool("COOKIE_SECURE", prod),
			OutboundAllowPrivate:  getbool("OUTBOUND_ALLOW_PRIVATE", true),
			OutboundAllowLoopback: getbool("OUTBOUND_ALLOW_LOOPBACK", !prod),
			OutboundAllowedHosts:  getlist("OUTBOUND_ALLOWED_HOSTS", nil),
		},
		HTTP: HTTP{
			Host:         getenv("HTTP_HOST", "0.0.0.0"),
			Port:         getenv("HTTP_PORT", "8080"),
			ReadTimeout:  getdur("HTTP_READ_TIMEOUT", 15*time.Second),
			WriteTimeout: getdur("HTTP_WRITE_TIMEOUT", 30*time.Second),
			IdleTimeout:  getdur("HTTP_IDLE_TIMEOUT", 60*time.Second),
			BodyLimit:    getint("HTTP_BODY_LIMIT_MB", 32) * 1024 * 1024,
		},
		DB: DB{
			Host:                 getenv("DB_HOST", "localhost"),
			Port:                 getenv("DB_PORT", "5432"),
			User:                 getenv("DB_USER", "xila"),
			Password:             sec.get("DB_PASSWORD", "xila"),
			Name:                 getenv("DB_NAME", "xila"),
			SSLMode:              getenv("DB_SSLMODE", "disable"),
			MaxConns:             int32(getint("DB_MAX_CONNS", 20)),
			MinConns:             int32(getint("DB_MIN_CONNS", 2)),
			MaxConnLifetime:      getdur("DB_MAX_CONN_LIFETIME", time.Hour),
			MaxConnIdleTime:      getdur("DB_MAX_CONN_IDLE_TIME", 30*time.Minute),
			HealthCheckPeriod:    getdur("DB_HEALTH_CHECK_PERIOD", time.Minute),
			ConnectTimeout:       getdur("DB_CONNECT_TIMEOUT", 10*time.Second),
			StatementTimeout:     getdur("DB_STATEMENT_TIMEOUT", 30*time.Second),
			ReadURL:              sec.get("DB_READ_URL", ""),
			ReadStatementTimeout: getdur("DB_READ_STATEMENT_TIMEOUT", 0),
			ReadMaxConns:         int32(getint("DB_READ_MAX_CONNS", 10)),
			JobStatementTimeout:  getdur("DB_JOB_STATEMENT_TIMEOUT", 15*time.Minute),
		},
		JWT: JWT{
			Secret:       sec.get("JWT_SECRET", ""),
			TTL:          getdur("JWT_TTL", 24*time.Hour),
			ReauthWindow: getdur("REAUTH_WINDOW", 10*time.Minute),
		},
		OIDC: OIDC{
			Enabled:      getbool("OIDC_ENABLED", false),
			Issuer:       getenv("OIDC_ISSUER", ""),
			ClientID:     getenv("OIDC_CLIENT_ID", ""),
			ClientSecret: sec.get("OIDC_CLIENT_SECRET", ""),
			RedirectURL:  getenv("OIDC_REDIRECT_URL", ""),
			ProviderName: getenv("OIDC_PROVIDER_NAME", "SSO"),
			Scopes:       oidcScopes(getenv("OIDC_SCOPES", "openid email profile")),
			GroupsClaim:  strings.TrimSpace(getenv("OIDC_GROUPS_CLAIM", "groups")),

			TrustUnverifiedEmail: getbool("OIDC_TRUST_UNVERIFIED_EMAIL", false),
		},
		LDAP: LDAP{
			Enabled:        getbool("LDAP_ENABLED", false),
			URL:            getenv("LDAP_URL", ""),
			StartTLS:       getbool("LDAP_STARTTLS", true),
			CACert:         pemValue(getenv("LDAP_CA_CERT", "")),
			BindDN:         getenv("LDAP_BIND_DN", ""),
			BindPassword:   sec.get("LDAP_BIND_PASSWORD", ""),
			BaseDN:         getenv("LDAP_BASE_DN", ""),
			UserFilter:     getenv("LDAP_USER_FILTER", "(&(objectClass=person)(|(mail={login})(uid={login})(sAMAccountName={login})(userPrincipalName={login})))"),
			EmailAttribute: getenv("LDAP_EMAIL_ATTRIBUTE", "mail"),
			GroupAttribute: getenv("LDAP_GROUP_ATTRIBUTE", "memberOf"),
			UIDAttribute:   getenv("LDAP_UID_ATTRIBUTE", ""),
			LinkByEmail:    getbool("LDAP_LINK_BY_EMAIL", true),
		},
		SAML: SAML{
			Enabled:           getbool("SAML_ENABLED", false),
			IDPMetadataURL:    strings.TrimSpace(getenv("SAML_IDP_METADATA_URL", "")),
			IDPMetadata:       strings.TrimSpace(getenv("SAML_IDP_METADATA", "")),
			EntityID:          strings.TrimSpace(getenv("SAML_ENTITY_ID", "")),
			SPCert:            pemValue(getenv("SAML_SP_CERT", "")),
			SPKey:             pemValue(sec.get("SAML_SP_KEY", "")),
			ProviderName:      getenv("SAML_PROVIDER_NAME", "SAML SSO"),
			EmailAttribute:    strings.TrimSpace(getenv("SAML_EMAIL_ATTRIBUTE", "")),
			GroupsAttributes:  getlist("SAML_GROUPS_ATTRIBUTE", []string{"groups"}),
			AllowIDPInitiated: getbool("SAML_ALLOW_IDP_INITIATED", false),
			SignRequests:      getbool("SAML_SIGN_REQUESTS", true),
			LinkByEmail:       getbool("SAML_LINK_BY_EMAIL", true),
		},
		SSO: SSO{
			AutoCreateUsers: getbool("SSO_AUTO_CREATE_USERS", true),
		},
		PasswordLoginEnabled: getbool("PASSWORD_LOGIN_ENABLED", true),
		MCPEnabled:           getbool("MCP_ENABLED", false),
		SMTP: SMTP{
			Host:     getenv("SMTP_HOST", ""),
			Port:     getint("SMTP_PORT", 587),
			Username: getenv("SMTP_USERNAME", ""),
			Password: sec.get("SMTP_PASSWORD", ""),
			From:     getenv("SMTP_FROM", ""),
			TLS:      strings.ToLower(strings.TrimSpace(getenv("SMTP_TLS", "starttls"))),
		},
		Otel: Otel{
			Enabled:     getbool("OTEL_ENABLED", true),
			Endpoint:    getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"),
			ServiceName: getenv("OTEL_SERVICE_NAME", "xila-api"),
			Insecure:    getbool("OTEL_EXPORTER_OTLP_INSECURE", true),
		},
		Metrics: Metrics{
			Enabled: getbool("METRICS_ENABLED", false),
			Addr:    getenv("METRICS_ADDR", ""),
			Token:   sec.get("METRICS_TOKEN", ""),
		},
		Policy: Policy{
			EvalInterval: getdur("POLICY_EVAL_INTERVAL", 6*time.Hour),
		},
		Enrich: Enrich{
			Enabled:    getbool("ENRICH_ENABLED", true),
			Interval:   getdur("ENRICH_INTERVAL", 6*time.Hour),
			KEVSources: getlist("KEV_SOURCES", defaultKEVSources(sec.get("VULNCHECK_API_TOKEN", ""))),
			KEVURLs: map[string]string{
				"cisa":      getenv("KEV_CISA_URL", ""),
				"enisa":     getenv("KEV_ENISA_URL", ""),
				"vulncheck": getenv("KEV_VULNCHECK_URL", ""),
			},
			VulnCheckToken: sec.get("VULNCHECK_API_TOKEN", ""),
		},
		Exploit: ExploitIntel{
			Enabled:  getbool("EXPLOIT_INTEL_ENABLED", true),
			Interval: getdur("EXPLOIT_INTEL_INTERVAL", 24*time.Hour),
			Sources:  getlist("EXPLOIT_INTEL_SOURCES", []string{"exploitdb", "metasploit", "nuclei"}),
			URLs: map[string]string{
				"exploitdb":  getenv("EXPLOIT_INTEL_EXPLOITDB_URL", ""),
				"metasploit": getenv("EXPLOIT_INTEL_METASPLOIT_URL", ""),
				"nuclei":     getenv("EXPLOIT_INTEL_NUCLEI_URL", ""),
			},
		},
		CRA: CRA{
			ManufacturerName:    getenv("CRA_MANUFACTURER_NAME", ""),
			ManufacturerAddress: getenv("CRA_MANUFACTURER_ADDRESS", ""),
			ManufacturerContact: getenv("CRA_MANUFACTURER_CONTACT", ""),
			MemberState:         strings.ToUpper(getenv("CRA_MANUFACTURER_MEMBER_STATE", "")),
			SweepInterval:       getdur("CRA_SWEEP_INTERVAL", 15*time.Minute),
		},
		Notify: Notify{
			MaxAttempts:      getint("NOTIFY_MAX_ATTEMPTS", 8),
			RetryBase:        getdur("NOTIFY_RETRY_BASE", 30*time.Second),
			RetryMax:         getdur("NOTIFY_RETRY_MAX", time.Hour),
			Retention:        getdur("NOTIFY_RETENTION", 7*24*time.Hour),
			DispatchInterval: getdur("NOTIFY_DISPATCH_INTERVAL", 2*time.Second),
		},
		NVD: NVD{
			Enabled: getbool("NVD_ENABLED", false),
			APIKey:  sec.get("NVD_API_KEY", ""),
			URL:     getenv("NVD_URL", ""),
		},
		AI: AI{
			Enabled:   getbool("AI_TRIAGE_ENABLED", false),
			Provider:  strings.ToLower(strings.TrimSpace(getenv("AI_PROVIDER", AIProviderOpenAI))),
			BaseURL:   strings.TrimRight(strings.TrimSpace(getenv("AI_BASE_URL", "")), "/"),
			Model:     strings.TrimSpace(getenv("AI_MODEL", "")),
			APIKey:    strings.TrimSpace(sec.get("AI_API_KEY", "")),
			RateLimit: getint("AI_RATE_LIMIT", 30),
			Timeout:   getdur("AI_TIMEOUT", 90*time.Second),
		},
		VulnMatch: VulnMatch{
			Enabled:              getbool("VULNMATCH_ENABLED", true),
			Interval:             getdur("VULNMATCH_INTERVAL", 12*time.Hour),
			Sources:              getlist("VULNMATCH_SOURCES", []string{"osv"}),
			OSVURL:               getenv("VULNMATCH_OSV_URL", ""),
			GitHubURL:            getenv("VULNMATCH_GITHUB_URL", ""),
			GitHubToken:          sec.get("VULNMATCH_GITHUB_TOKEN", ""),
			OSVMirrorURL:         getenv("VULNMATCH_OSV_MIRROR_URL", ""),
			OSVEcosystems:        getlist("VULNMATCH_OSV_ECOSYSTEMS", nil),
			OSVMirrorInterval:    getdur("VULNMATCH_OSV_MIRROR_INTERVAL", 24*time.Hour),
			VulnerableCodeURL:    getenv("VULNMATCH_VULNERABLECODE_URL", ""),
			VulnerableCodeAPIKey: sec.get("VULNMATCH_VULNERABLECODE_API_KEY", ""),
			JVNURL:               getenv("VULNMATCH_JVN_URL", ""),
			JVNFromYear:          getint("VULNMATCH_JVN_FROM_YEAR", 2015),
			JVNInterval:          getdur("VULNMATCH_JVN_INTERVAL", 24*time.Hour),
		},
		PSIRT: PSIRT{
			Public:             getbool("PSIRT_PUBLIC", false),
			AdvisoryPrefix:     getenv("PSIRT_ADVISORY_PREFIX", "XILA-SA"),
			PublisherName:      getenv("PSIRT_PUBLISHER_NAME", ""),
			PublisherNamespace: strings.TrimRight(getenv("PSIRT_PUBLISHER_NAMESPACE", ""), "/"),
			PublisherContact:   getenv("PSIRT_PUBLISHER_CONTACT", ""),
		},
		AuthRateLimit: AuthRateLimit{
			IPPerMinute:   getint("AUTH_RATE_LIMIT_IP_PER_MIN", 60),
			Account:       getint("AUTH_RATE_LIMIT_ACCOUNT", 10),
			AccountWindow: getdur("AUTH_RATE_LIMIT_ACCOUNT_WINDOW", 15*time.Minute),
		},
		ServiceAccounts: ServiceAccounts{
			KeyMaxDays: getint("SERVICE_ACCOUNT_KEY_MAX_DAYS", 90),
			TokenTTL:   getdur("FEDERATION_TOKEN_TTL", 15*time.Minute),
		},
		PkgMeta: PkgMeta{
			Enabled:           getbool("PKGMETA_ENABLED", true),
			Interval:          getdur("PKGMETA_INTERVAL", time.Hour),
			TTL:               getdur("PKGMETA_TTL", 24*time.Hour),
			Concurrency:       getint("PKGMETA_CONCURRENCY", 4),
			RequestsPerSecond: getint("PKGMETA_REQUESTS_PER_SECOND", 5),
			URLs: map[string]string{
				"npm":      strings.TrimSpace(getenv("PKGMETA_NPM_URL", "")),
				"pypi":     strings.TrimSpace(getenv("PKGMETA_PYPI_URL", "")),
				"maven":    strings.TrimSpace(getenv("PKGMETA_MAVEN_URL", "")),
				"golang":   strings.TrimSpace(getenv("PKGMETA_GO_URL", "")),
				"cargo":    strings.TrimSpace(getenv("PKGMETA_CARGO_URL", "")),
				"nuget":    strings.TrimSpace(getenv("PKGMETA_NUGET_URL", "")),
				"gem":      strings.TrimSpace(getenv("PKGMETA_GEM_URL", "")),
				"composer": strings.TrimSpace(getenv("PKGMETA_COMPOSER_URL", "")),
			},
		},
		Ingest: Ingest{
			Async:               getbool("INGEST_ASYNC", false),
			Workers:             getint("INGEST_WORKERS", 4),
			PollInterval:        getdur("INGEST_POLL_INTERVAL", 2*time.Second),
			MaxAttempts:         getint("INGEST_MAX_ATTEMPTS", 3),
			MaxQueueDepth:       getint("INGEST_MAX_QUEUE_DEPTH", 10000),
			QueueSampleInterval: getdur("INGEST_QUEUE_SAMPLE_INTERVAL", 5*time.Second),
			SkipUnchanged:       getbool("INGEST_SKIP_UNCHANGED", true),
			PayloadStore:        strings.ToLower(strings.TrimSpace(getenv("INGEST_PAYLOAD_STORE", "postgres"))),
		},
		S3: S3{
			Endpoint:        strings.TrimSpace(getenv("S3_ENDPOINT", "")),
			Region:          strings.TrimSpace(getenv("S3_REGION", "us-east-1")),
			Bucket:          strings.TrimSpace(getenv("S3_BUCKET", "")),
			Prefix:          strings.Trim(strings.TrimSpace(getenv("S3_PREFIX", "")), "/"),
			AccessKeyID:     strings.TrimSpace(sec.get("S3_ACCESS_KEY_ID", "")),
			SecretAccessKey: strings.TrimSpace(sec.get("S3_SECRET_ACCESS_KEY", "")),
			ForcePathStyle:  getbool("S3_FORCE_PATH_STYLE", false),
		},
		ExceptionSweepInterval: getdur("EXCEPTION_SWEEP_INTERVAL", time.Hour),
		SLASweepInterval:       getdur("SLA_SWEEP_INTERVAL", time.Hour),
		Retention: Retention{
			BranchAge:           getdur("BRANCH_RETENTION", 90*24*time.Hour),
			ReleaseAge:          getdur("RELEASE_RETENTION", 0),
			SBOMKeep:            getint("SBOM_RETENTION_KEEP", 0),
			SBOMAge:             getdur("SBOM_RETENTION_AGE", 0),
			ScanAge:             getdur("SCAN_RETENTION", 0),
			LogAge:              getdur("LOG_RETENTION", 90*24*time.Hour),
			AuditAge:            getdur("AUDIT_RETENTION", 365*24*time.Hour),
			ArchiveAge:          getdur("ARCHIVE_RETENTION", 30*24*time.Hour),
			FindingArchiveAfter: getdur("FINDING_ARCHIVE_AFTER", 0),
		},
		TriageRulesRequireApproval:     getbool("TRIAGE_RULES_REQUIRE_APPROVAL", false),
		AssessmentRequiresApproval:     getbool("ASSESSMENT_REQUIRES_APPROVAL", false),
		RiskAcceptanceRequiresApproval: getbool("RISK_ACCEPTANCE_REQUIRES_APPROVAL", prod),
		RiskAcceptanceExpiryWarning:    getdur("RISK_ACCEPTANCE_EXPIRY_WARNING", 7*24*time.Hour),
		IntegrationSecretKey:           strings.TrimSpace(sec.get("INTEGRATION_SECRET_KEY", "")),
		PublicURL:                      strings.TrimRight(strings.TrimSpace(getenv("PUBLIC_URL", "")), "/"),
		SourceURL:                      strings.TrimSpace(getenv("SOURCE_URL", DefaultSourceURL)),
		IssueSyncInterval:              getdur("ISSUE_SYNC_INTERVAL", 15*time.Minute),
		RemediationSweepInterval:       getdur("REMEDIATION_SWEEP_INTERVAL", 15*time.Minute),
		RemediationAutoCreate:          getbool("REMEDIATION_AUTO_CREATE", false),
		ConnectorPullInterval:          getdur("CONNECTOR_PULL_INTERVAL", 6*time.Hour),
		MetricsSnapshotInterval:        getdur("METRICS_SNAPSHOT_INTERVAL", time.Hour),
		PortfolioFromSnapshots:         getbool("PORTFOLIO_FROM_SNAPSHOTS", false),
	}
	if cfg.SAML.EntityID == "" && cfg.PublicURL != "" {
		cfg.SAML.EntityID = cfg.PublicURL + "/api/v1/auth/saml/metadata"
	}
	if _, set := os.LookupEnv("LICENSE_DENYLIST"); set {
		cfg.LegacyLicenseDenylist = true // replaced by component policies
	}

	// A throwaway signing secret is fine in development; anywhere else it must be
	// supplied (enforced by validate below).
	if cfg.JWT.Secret == "" && cfg.IsDevelopment() {
		cfg.JWT.Secret = insecureDevSecret
	}

	if sec.err != nil {
		return Config{}, sec.err
	}
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// normalizeEnv maps common aliases to the canonical environment names.
func normalizeEnv(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "dev", "develop", "development", "local":
		return EnvDevelopment
	case "prod", "production":
		return EnvProduction
	case "test", "testing", "ci":
		return EnvTest
	default:
		return v // left as-is so validate can reject it with the real value
	}
}

// validate rejects configurations that are unsafe to boot, especially in
// production. Hard failures only — softer concerns surface via Warnings.
// DefaultSourceURL is the upstream repository: the right SOURCE_URL for an
// unmodified build.
const DefaultSourceURL = "https://github.com/xilasec/xila-api"

func (c Config) validate() error {
	if c.Env != EnvDevelopment && c.Env != EnvProduction && c.Env != EnvTest {
		return fmt.Errorf("invalid APP_ENV %q (want development, production or test)", c.Env)
	}
	if err := c.validateIngest(); err != nil {
		return err
	}
	if c.DB.ReadURL != "" {
		if u, err := url.Parse(c.DB.ReadURL); err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
			return fmt.Errorf("DB_READ_URL must be a postgres:// URL")
		}
	}
	if c.DB.ReadStatementTimeout < 0 || c.DB.ReadMaxConns < 1 || c.DB.JobStatementTimeout < 0 {
		return fmt.Errorf("DB_READ_STATEMENT_TIMEOUT and DB_JOB_STATEMENT_TIMEOUT must be 0 or more and DB_READ_MAX_CONNS at least 1")
	}
	if c.JWT.ReauthWindow < 0 {
		return fmt.Errorf("REAUTH_WINDOW must be 0 or more, got %s", c.JWT.ReauthWindow)
	}
	if u, err := url.Parse(c.SourceURL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return fmt.Errorf("SOURCE_URL must be an absolute http(s) URL, got %q", c.SourceURL)
	}
	if c.IsProduction() {
		if c.JWT.Secret == "" || c.JWT.Secret == insecureDevSecret {
			return errors.New("JWT_SECRET must be set to a strong, unique value in production")
		}
		// On the public listener, /metrics would hand anyone the instance's
		// internals (routes, queue depths, feed health): require a token, or
		// serve it on a separate (cluster-internal) METRICS_ADDR.
		if c.Metrics.Enabled && c.Metrics.Addr == "" && c.Metrics.Token == "" {
			return errors.New("METRICS_ENABLED on the main port needs METRICS_TOKEN in production (or set METRICS_ADDR to serve /metrics on a separate, internal listener)")
		}
	}
	if c.ServiceAccounts.KeyMaxDays < 1 {
		return errors.New("SERVICE_ACCOUNT_KEY_MAX_DAYS must be ≥ 1")
	}
	if c.ServiceAccounts.TokenTTL <= 0 || c.ServiceAccounts.TokenTTL > time.Hour {
		return errors.New("FEDERATION_TOKEN_TTL must be > 0 and at most 1h")
	}
	if c.Retention.SBOMKeep < 0 {
		return errors.New("SBOM_RETENTION_KEEP must be ≥ 0")
	}
	if c.Notify.MaxAttempts < 1 || c.Notify.RetryBase <= 0 || c.Notify.RetryMax < c.Notify.RetryBase || c.Notify.DispatchInterval <= 0 {
		return errors.New("NOTIFY_MAX_ATTEMPTS must be ≥ 1, NOTIFY_RETRY_BASE and NOTIFY_DISPATCH_INTERVAL > 0, NOTIFY_RETRY_MAX ≥ NOTIFY_RETRY_BASE")
	}
	switch c.SMTP.TLS {
	case "starttls", "tls", "none":
	default:
		return fmt.Errorf("invalid SMTP_TLS %q (want starttls, tls or none)", c.SMTP.TLS)
	}
	if _, err := c.IntegrationKey(); err != nil {
		return err
	}
	if c.CRA.MemberState != "" && !domain.EUMemberState(c.CRA.MemberState) {
		return fmt.Errorf("invalid CRA_MANUFACTURER_MEMBER_STATE %q (want an EU Member State's ISO 3166-1 alpha-2 code, e.g. DE)", c.CRA.MemberState)
	}
	if c.LDAP.Enabled {
		if !strings.HasPrefix(c.LDAP.URL, "ldaps://") && !strings.HasPrefix(c.LDAP.URL, "ldap://") {
			return errors.New("LDAP_URL must be an ldaps:// or ldap:// URL")
		}
		if c.LDAP.BaseDN == "" || !strings.Contains(c.LDAP.UserFilter, "{login}") {
			return errors.New("LDAP_BASE_DN is required and LDAP_USER_FILTER must contain {login}")
		}
		if c.IsProduction() && strings.HasPrefix(c.LDAP.URL, "ldap://") && !c.LDAP.StartTLS {
			return errors.New("LDAP over plain ldap:// without LDAP_STARTTLS sends passwords in cleartext; refusing in production")
		}
	}
	if err := c.validateSAML(); err != nil {
		return err
	}
	if err := c.validateAI(); err != nil {
		return err
	}
	for _, s := range c.VulnMatch.Sources {
		switch s {
		case "osv", "github", "osv-local", "private", "nvd", "vulnerablecode", "jvn":
		default:
			return fmt.Errorf("invalid VULNMATCH_SOURCES entry %q (want osv, github, osv-local, private, nvd, vulnerablecode, jvn)", s)
		}
	}
	if err := c.validatePSIRT(); err != nil {
		return err
	}
	return nil
}

// validatePSIRT fails boot on a publishing setup that can't produce valid
// CSAF: a prefix that isn't a plain id stem, a namespace that isn't a URL, or
// a public directory without the publisher or the URL it is served from.
func (c Config) validatePSIRT() error {
	p := c.PSIRT
	if !psirtPrefixRe.MatchString(p.AdvisoryPrefix) {
		return errors.New("PSIRT_ADVISORY_PREFIX must be letters, digits and dashes, starting with a letter (e.g. ACME-SA)")
	}
	if p.PublisherNamespace != "" && !strings.HasPrefix(p.PublisherNamespace, "https://") && !strings.HasPrefix(p.PublisherNamespace, "http://") {
		return errors.New("PSIRT_PUBLISHER_NAMESPACE must be the publisher's http(s) URL")
	}
	if p.Public && (p.PublisherName == "" || p.PublisherNamespace == "" || c.PublicURL == "") {
		return errors.New("PSIRT_PUBLIC needs PSIRT_PUBLISHER_NAME, PSIRT_PUBLISHER_NAMESPACE and PUBLIC_URL")
	}
	return nil
}

var psirtPrefixRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{0,30}$`)

// validateIngest fails boot on an ingest configuration that cannot run: a
// negative worker count, an unknown payload store, or
// INGEST_PAYLOAD_STORE=s3 without the bucket/region it needs. It never
// reaches the network — main's objectstore.New HeadBucket call is the one
// place that does, so a wrong bucket name or missing credentials is reported
// there, at startup, not here.
func (c Config) validateIngest() error {
	if c.Ingest.Workers < 0 {
		return fmt.Errorf("INGEST_WORKERS must be 0 or more, got %d", c.Ingest.Workers)
	}
	switch c.Ingest.PayloadStore {
	case "postgres", "s3":
	default:
		return fmt.Errorf("invalid INGEST_PAYLOAD_STORE %q (want postgres or s3)", c.Ingest.PayloadStore)
	}
	if c.Ingest.PayloadStore != "s3" {
		return nil
	}
	if c.S3.Bucket == "" {
		return errors.New("INGEST_PAYLOAD_STORE=s3 requires S3_BUCKET")
	}
	if c.S3.Region == "" {
		return errors.New("INGEST_PAYLOAD_STORE=s3 requires S3_REGION")
	}
	if c.S3.Endpoint != "" {
		if err := netguard.CheckURL(c.S3.Endpoint); err != nil {
			return fmt.Errorf("S3_ENDPOINT: %w", err)
		}
	}
	return nil
}

// validateSAML fails boot on a SAML setup that cannot work or would be unsafe.
// (An unreachable metadata URL is not a config error: main logs it and runs
// without SAML, like OIDC discovery.)
func (c Config) validateSAML() error {
	if !c.SAML.Enabled {
		return nil
	}
	if c.PublicURL == "" {
		return errors.New("SAML_ENABLED requires PUBLIC_URL (the ACS and metadata URLs are built from it)")
	}
	if c.IsProduction() && !strings.HasPrefix(c.PublicURL, "https://") {
		return errors.New("SAML_ENABLED in production requires an https:// PUBLIC_URL")
	}
	if c.SAML.IDPMetadataURL == "" && c.SAML.IDPMetadata == "" {
		return errors.New("SAML_ENABLED requires SAML_IDP_METADATA_URL or SAML_IDP_METADATA")
	}
	if (c.SAML.SPCert == "") != (c.SAML.SPKey == "") {
		return errors.New("set both SAML_SP_CERT and SAML_SP_KEY, or neither (a key pair is then generated)")
	}
	if c.SAML.SPKey == "" && c.IntegrationSecretKey == "" {
		return errors.New("SAML without SAML_SP_CERT/SAML_SP_KEY needs INTEGRATION_SECRET_KEY to store the generated SP key")
	}
	return nil
}

// validateAI fails boot on an AI triage setup that cannot work.
func (c Config) validateAI() error {
	if !c.AI.Enabled {
		return nil
	}
	switch c.AI.Provider {
	case AIProviderOpenAI:
		if c.AI.BaseURL == "" {
			return errors.New("AI_BASE_URL is required for AI_PROVIDER=openai-compatible (e.g. https://api.openai.com/v1)")
		}
	case AIProviderAnthropic:
		if c.AI.APIKey == "" {
			return errors.New("AI_API_KEY is required for AI_PROVIDER=anthropic")
		}
	default:
		return fmt.Errorf("invalid AI_PROVIDER %q (want openai-compatible or anthropic)", c.AI.Provider)
	}
	if c.AI.BaseURL != "" {
		u, err := url.Parse(c.AI.BaseURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			return errors.New("AI_BASE_URL must be an http(s) URL without credentials")
		}
	}
	if c.AI.Model == "" {
		return errors.New("AI_MODEL is required when AI_TRIAGE_ENABLED=true")
	}
	if c.AI.RateLimit < 1 || c.AI.Timeout <= 0 {
		return errors.New("AI_RATE_LIMIT must be ≥ 1 and AI_TIMEOUT > 0")
	}
	return nil
}

// IntegrationKey decodes INTEGRATION_SECRET_KEY. nil (no error) when unset.
func (c Config) IntegrationKey() ([]byte, error) {
	if c.IntegrationSecretKey == "" {
		return nil, nil
	}
	key, err := base64.StdEncoding.DecodeString(c.IntegrationSecretKey)
	if err != nil {
		key, err = base64.RawURLEncoding.DecodeString(strings.TrimRight(c.IntegrationSecretKey, "="))
	}
	if err != nil || len(key) != 32 {
		return nil, errors.New("INTEGRATION_SECRET_KEY must be 32 random bytes, base64-encoded (openssl rand -base64 32)")
	}
	return key, nil
}

// Warnings returns non-fatal advice: removed settings that are still set (any
// environment), and production hardening. main logs each at startup.
func (c Config) Warnings() []string {
	var w []string
	if c.Ingest.Async && c.Ingest.Workers == 0 {
		w = append(w, "INGEST_ASYNC=true with INGEST_WORKERS=0: this node only queues uploads; run worker nodes (INGEST_WORKERS > 0) against the same database or the queue never drains")
	}
	if c.LegacyLicenseDenylist {
		w = append(w, `LICENSE_DENYLIST is no longer supported and is ignored — license rules are component policies now (/policies; the seeded "Strong copyleft licenses" policy replaces its default)`)
	}
	if !c.PasswordLoginEnabled && !c.OIDC.Enabled && !c.SAML.Enabled {
		w = append(w, "PASSWORD_LOGIN_ENABLED=false but no SSO provider is configured by environment — unless an admin has added one on the SSO page, only the instance owner can sign in")
	}
	if c.SAML.Enabled && !c.Security.CookieSecure {
		w = append(w, "SAML is enabled with COOKIE_SECURE=false — the login-tracking cookie is SameSite=Lax, which the IdP's POST to the ACS only carries when the IdP is on the same site (e.g. both on localhost); serve Xila over https with COOKIE_SECURE=true for any real IdP")
	}
	if !c.IsProduction() {
		return w
	}
	if c.DB.Password == "" || c.DB.Password == "xila" {
		w = append(w, "DB_PASSWORD is empty or the insecure default — set a strong database password")
	}
	if c.DB.SSLMode == "disable" {
		w = append(w, "DB_SSLMODE=disable — enable TLS to the database (e.g. require)")
	}
	if slices.Contains(c.Security.AllowedOrigins, "*") {
		w = append(w, "CORS_ALLOWED_ORIGINS is '*' — restrict it to your known UI origins")
	}
	if !c.Security.CookieSecure {
		w = append(w, "COOKIE_SECURE=false — auth cookies should be Secure behind TLS")
	}
	if !c.RiskAcceptanceRequiresApproval {
		w = append(w, "RISK_ACCEPTANCE_REQUIRES_APPROVAL=false — a project owner can approve their own risk acceptance requests, and imported risk acceptances apply without review")
	}
	if c.Security.OutboundAllowLoopback {
		w = append(w, "OUTBOUND_ALLOW_LOOPBACK=true — users who can configure an integration URL (project owners: issue trackers, connectors) can make the server call services on its own host; list the hosts you need in OUTBOUND_ALLOWED_HOSTS instead")
	}
	if c.OIDC.Enabled && !strings.HasPrefix(c.OIDC.RedirectURL, "https://") {
		w = append(w, "OIDC_REDIRECT_URL is not https — SSO redirects should use TLS")
	}
	if c.OIDC.Enabled && c.OIDC.TrustUnverifiedEmail {
		w = append(w, "OIDC_TRUST_UNVERIFIED_EMAIL=true — SSO logins without email_verified are linked to existing accounts by email; only safe if your IdP controls every address")
	}
	if c.SAML.Enabled && c.SAML.AllowIDPInitiated {
		w = append(w, "SAML_ALLOW_IDP_INITIATED=true — unsolicited SAML responses are accepted, which allows login CSRF; prefer SP-initiated login")
	}
	if c.SAML.Enabled && !c.SAML.SignRequests {
		w = append(w, "SAML_SIGN_REQUESTS=false — AuthnRequests are unsigned")
	}
	if c.SMTP.Configured() && c.SMTP.TLS == "none" {
		w = append(w, "SMTP_TLS=none — email (and SMTP credentials) are sent in cleartext")
	}
	if c.Otel.Enabled && c.Otel.Insecure {
		w = append(w, "OTEL_EXPORTER_OTLP_INSECURE=true — use TLS to the telemetry collector")
	}
	if c.AI.Enabled && strings.HasPrefix(c.AI.BaseURL, "http://") {
		w = append(w, "AI_BASE_URL is not https — finding details (and AI_API_KEY) are sent to the model in cleartext")
	}
	if c.IntegrationSecretKey == "" {
		w = append(w, "INTEGRATION_SECRET_KEY is unset — two-factor sign-in, issue trackers and connectors can't be configured (their secrets are encrypted with it)")
	}
	if c.Ingest.PayloadStore == "s3" && strings.HasPrefix(c.S3.Endpoint, "http://") {
		w = append(w, "S3_ENDPOINT is not https — queued scan reports are uploaded to object storage in cleartext")
	}
	return w
}

// loadDotEnv reads ENV_FILE, or ./.env when ENV_FILE is unset and the file
// exists, into the process environment. Variables already set in the real
// environment win, so a deployment can always override the file. ENV_FILE must
// exist; a missing ./.env is not an error.
func loadDotEnv() error {
	path, explicit := os.LookupEnv("ENV_FILE")
	if !explicit {
		path = ".env"
	}
	err := godotenv.Load(filepath.Clean(path))
	if err != nil && !explicit && errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}
	return nil
}

// secretReader reads a secret setting from NAME, or from the file named by
// NAME_FILE: the convention Docker and Kubernetes secrets, Vault Agent, the
// Secrets Store CSI driver and External Secrets Operator all write to. One
// trailing newline is trimmed. Setting both, or naming a file that can't be
// read, is an error (kept in err) rather than a silent fallback.
type secretReader struct{ err error }

func (r *secretReader) get(key, fallback string) string {
	path, fromFile := os.LookupEnv(key + "_FILE")
	if !fromFile {
		return getenv(key, fallback)
	}
	if _, both := os.LookupEnv(key); both {
		r.fail(fmt.Errorf("set %s or %s_FILE, not both", key, key))
		return fallback
	}
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		r.fail(fmt.Errorf("%s_FILE: %w", key, err))
		return fallback
	}
	return strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
}

func (r *secretReader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

// getlist reads a comma-separated env var, trimming blanks.
func getlist(key string, fallback []string) []string {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// oidcScopes splits OIDC_SCOPES (space- or comma-separated) and makes sure
// openid is requested — without it there is no ID token.
func oidcScopes(v string) []string {
	scopes := strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' })
	if !slices.Contains(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}
	return scopes
}

// pemValue accepts a PEM block with real newlines or with literal "\n" (a
// one-line .env value).
func pemValue(v string) string {
	return strings.TrimSpace(strings.ReplaceAll(v, `\n`, "\n"))
}

func getint(key string, fallback int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return fallback
}

func getbool(key string, fallback bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

func getdur(key string, fallback time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
