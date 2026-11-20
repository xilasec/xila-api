// Package server builds and runs the HTTP layer.
package server

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/contrib/otelfiber/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/adaptor"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	"go.opentelemetry.io/otel/trace"

	"github.com/xilasec/xila-api/internal/access"
	"github.com/xilasec/xila-api/internal/account"
	"github.com/xilasec/xila-api/internal/aitriage"
	"github.com/xilasec/xila-api/internal/apidoc"
	"github.com/xilasec/xila-api/internal/apitoken"
	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/asset"
	"github.com/xilasec/xila-api/internal/audit"
	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/badge"
	"github.com/xilasec/xila-api/internal/compliance"
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
	"github.com/xilasec/xila-api/internal/inbox"
	"github.com/xilasec/xila-api/internal/ingesthealth"
	"github.com/xilasec/xila-api/internal/issuetracker"
	"github.com/xilasec/xila-api/internal/license"
	"github.com/xilasec/xila-api/internal/mcp"
	"github.com/xilasec/xila-api/internal/membership"
	"github.com/xilasec/xila-api/internal/metrics"
	"github.com/xilasec/xila-api/internal/notify"
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
	"github.com/xilasec/xila-api/internal/scim"
	"github.com/xilasec/xila-api/internal/secretbox"
	"github.com/xilasec/xila-api/internal/serviceaccount"
	"github.com/xilasec/xila-api/internal/sla"
	"github.com/xilasec/xila-api/internal/sso"
	"github.com/xilasec/xila-api/internal/team"
	"github.com/xilasec/xila-api/internal/triage"
	"github.com/xilasec/xila-api/internal/vex"
	"github.com/xilasec/xila-api/internal/vulnmatch"
	"github.com/xilasec/xila-api/internal/vulnpolicy"
)

// Handlers bundles the HTTP handlers the server mounts.
type Handlers struct {
	Features     *feature.Handler
	Access       *access.Handler
	MCP          *mcp.Handler
	Personal     *notify.PersonalHandler
	Inbox        *inbox.Handler
	Auth         *auth.Handler
	Account      *account.Handler
	Org          *org.Handler
	Team         *team.Handler
	TeamMembers  *membership.Handler
	Project      *project.Handler
	Scan         *scan.Handler
	Finding      *finding.Handler
	AITriage     *aitriage.Handler
	Sbom         *sbom.Handler
	Asset        *asset.Handler
	Compliance   *compliance.Handler
	Portfolio    *portfolio.Handler
	Metrics      *metrics.Handler
	Report       *report.Handler
	Correlation  *correlation.Handler
	ApiToken     *apitoken.Handler
	SvcAccount   *serviceaccount.Handler
	Federation   *federation.Handler
	SCIM         *scim.Handler
	Enrichment   *enrichment.Handler
	Notify       *notify.Handler
	Retention    *retention.Handler
	Archive      *archive.Handler
	Audit        *audit.Handler
	IngestHealth *ingesthealth.Handler
	Engagement   *engagement.Handler
	Badge        *badge.Handler
	FixPlan      *fixplan.Handler
	Remediation  *remediation.Handler
	RootCauses   *rootcause.Handler
	Exploits     *exploitintel.Handler
	Evidence     *evidence.Handler
	CRACases     *cra.CaseHandler
	FindingTmpl  *findingtemplate.Handler
	ReportTmpl   *report.TemplateHandler
	CustomFields *customfield.Handler
	CustomParser *customparser.Handler
	Triage       *triage.Handler
	Gate         *gate.Handler
	SLA          *sla.Handler
	Vex          *vex.Handler
	IssueTracker *issuetracker.Handler
	Connector    *connector.Handler
	VulnMatch    *vulnmatch.Handler
	Advisory     *vulnmatch.AdvisoryHandler
	FeedRules    *vulnmatch.FeedRuleHandler
	// PSIRT serves CSAF advisory publishing (admin) and the public CSAF
	// provider directory (404 unless PSIRT_PUBLIC).
	PSIRT      *psirt.Handler
	PkgMeta    *pkgmeta.Handler
	License    *license.Handler
	Policy     *policy.Handler
	VulnPolicy *vulnpolicy.Handler
	SSO        *sso.Handler
	// OIDC and SAML serve every provider's public login routes under
	// /api/v1/auth (environment ones at the bare paths, admin-managed ones by
	// slug); always mounted, 404 for an unknown or disabled provider.
	OIDC *oidc.Handler
	SAML *saml.Handler

	// AuditLog records every mutating API request and every sign-in event.
	AuditLog *audit.Recorder

	// Membership backs the RBAC authorization middleware.
	Membership *membership.Repository

	// JWTKeys signs and verifies session JWTs (and MFA challenge tokens);
	// shared with AuditLog and auth.Service so a rotation (Keys.Update)
	// applies to every signer and verifier at once.
	JWTKeys *auth.Keys

	// Secrets serves the INTEGRATION_SECRET_KEY ring's rotation status
	// (GET /admin/secrets/status).
	Secrets *secretbox.Handler

	// TokenAuth, if set, lets the auth middleware accept API tokens (CI) in
	// addition to JWTs. Nil means JWT-only.
	TokenAuth auth.TokenValidator
	// Sessions, if set, rejects JWTs revoked by a password change, "sign out
	// everywhere" or deactivation (user.Repository).
	Sessions auth.SessionValidator

	// Ready, if set, backs the /ready probe (e.g. a database ping). A nil Ready
	// reports ready unconditionally.
	Ready func(context.Context) error
	// AuthLimiter, if set, throttles the password endpoints (login, register,
	// password reset).
	AuthLimiter *ratelimit.Limiter

	// Static, if set, is the built web UI served for all non-API routes, making
	// the binary a single bundle (UI + API on one port). Nil serves API only.
	Static fs.FS
	// PromMetrics is the Prometheus scrape handler (METRICS_ENABLED, already
	// token-guarded), mounted at /metrics; nil when off or when METRICS_ADDR
	// serves it on its own listener.
	PromMetrics http.Handler
}

// Server wraps the Fiber application and its listen address.
type Server struct {
	app  *fiber.App
	addr string
}

// New assembles the Fiber app, middleware chain and routes.
func New(cfg config.Config, h Handlers) *Server {
	fiberCfg := fiber.Config{
		AppName:               cfg.Otel.ServiceName,
		DisableStartupMessage: true,
		ErrorHandler:          errorHandler,
		// SBOM/scan uploads can be large; the body limit is configurable.
		BodyLimit:    orInt(cfg.HTTP.BodyLimit, 32*1024*1024),
		ReadTimeout:  orDur(cfg.HTTP.ReadTimeout, 15*time.Second),
		WriteTimeout: orDur(cfg.HTTP.WriteTimeout, 30*time.Second),
		IdleTimeout:  orDur(cfg.HTTP.IdleTimeout, 60*time.Second),
	}
	// Behind a load balancer, trust X-Forwarded-* only from the configured proxies
	// so client IP + scheme are accurate (and not spoofable by clients).
	if len(cfg.Security.TrustedProxies) > 0 {
		fiberCfg.EnableTrustedProxyCheck = true
		fiberCfg.TrustedProxies = cfg.Security.TrustedProxies
		fiberCfg.ProxyHeader = fiber.HeaderXForwardedFor
	}
	app := fiber.New(fiberCfg)

	// Order matters: request id -> panic recovery -> CORS -> tracing -> logging.
	app.Use(requestid.New())
	app.Use(recover.New())
	// CORS: skip entirely when same-origin only (empty allow-list); the embedded
	// SPA needs no cross-origin headers.
	if origins := cfg.Security.AllowedOrigins; len(origins) > 0 {
		app.Use(cors.New(cors.Config{AllowOrigins: strings.Join(origins, ",")}))
	}
	app.Use(otelfiber.Middleware())
	app.Use(requestLogger())
	// A switched-off feature's public routes (CSAF, badges, the MFA sign-in
	// step) answer 404; its API routes are gated on `secured` below.
	app.Use(h.Features.PublicMiddleware())

	// Serve the embedded SPA for everything that isn't an API/probe route.
	// Registered before the routes with a Next guard so API paths pass through;
	// unknown UI paths fall back to index.html for client-side routing.
	if h.Static != nil {
		app.Use(filesystem.New(filesystem.Config{
			Root:         http.FS(h.Static),
			Index:        "index.html",
			NotFoundFile: "index.html",
			Next: func(c *fiber.Ctx) bool {
				p := c.Path()
				return strings.HasPrefix(p, "/api") || p == "/health" || p == "/ready" || p == "/metrics" ||
					strings.HasPrefix(p, "/.well-known/csaf/") || strings.HasPrefix(p, "/csaf/")
			},
		}))
	}

	// The API describes itself. Public — an API description is not a secret, and a
	// token requirement would defeat the point of publishing one.
	if docs, err := apidoc.NewHandler(); err != nil {
		slog.Error("openapi spec is invalid; not serving it", "error", err)
	} else {
		docs.Register(app)
	}

	if h.PromMetrics != nil {
		app.Get("/metrics", adaptor.HTTPHandler(h.PromMetrics))
	}

	// Liveness: process is up. Readiness: dependencies (DB) are reachable.
	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok"})
	})
	app.Get("/ready", func(c *fiber.Ctx) error {
		if h.Ready != nil {
			if err := h.Ready(c.UserContext()); err != nil {
				return fiber.NewError(fiber.StatusServiceUnavailable, "not ready")
			}
		}
		return c.JSON(fiber.Map{"status": "ready"})
	})

	// Public auth routes. Only the password endpoints are throttled (shared,
	// Postgres-backed buckets per IP and per account): /auth/config is fetched on
	// every page load and the SSO redirects are throttled by the IdP — limiting
	// them used to lock whole offices behind one NAT out of SSO.
	v1 := app.Group("/api/v1")
	authGroup := v1.Group("/auth")
	// Sign-ins, registrations, resets and SSO logins land in the audit log,
	// success or failure — throttled attempts too.
	authGroup.Use(h.AuditLog.Auth())
	throttle := func(c *fiber.Ctx) error { return c.Next() }
	throttleReset := throttle
	if h.AuthLimiter != nil {
		throttle = h.AuthLimiter.Middleware()
		throttleReset = h.AuthLimiter.ResetMiddleware()
	}
	authGroup.Post("/register", throttle, h.Auth.Register)
	authGroup.Post("/login", throttle, h.Auth.Login)
	authGroup.Post("/password-reset/request", throttleReset, h.Auth.RequestPasswordReset)
	authGroup.Post("/password-reset/confirm", throttle, h.Auth.ConfirmPasswordReset)
	authGroup.Post("/mfa", throttle, h.Auth.VerifyMFA)
	authGroup.Post("/token", throttle, h.Federation.Exchange) // RFC 8693 workload identity exchange
	authGroup.Get("/config", authConfig(cfg, h))
	h.OIDC.Register(authGroup)
	h.SAML.Register(authGroup)
	// README badges: public, resolved by an unguessable per-project token.
	h.Badge.RegisterPublic(v1)
	// SCIM provisioning: its own bearer tokens, never a session or API token,
	// so it is mounted before the secured group. Changes are audited by the
	// handler (actor kind scim).
	h.SCIM.RegisterSCIM(v1)
	// CSAF provider directory at the site root (PSIRT_PUBLIC; 404 otherwise).
	h.PSIRT.RegisterPublic(app)

	// Everything else requires a valid access token (JWT or API token). Every
	// mutation is audited — before authorization, so a refused one is too.
	secured := v1.Group("", auth.Middleware(h.JWTKeys, h.TokenAuth, h.Sessions),
		h.AuditLog.Middleware(), h.Features.Middleware(), authz.Middleware(h.Membership))
	h.Account.Register(secured)
	h.Features.Register(secured)
	h.Org.Register(secured)
	h.Team.Register(secured)
	h.TeamMembers.Register(secured)
	h.Project.Register(secured)
	h.Access.Register(secured)
	h.MCP.Register(secured)
	h.Personal.Register(secured)
	h.Inbox.Register(secured)
	h.MCP.Attach(app)      // its tools are sub-requests through this app
	h.AuditLog.Attach(app) // describes requests refused before a route matched
	h.Scan.Register(secured)
	h.Finding.Register(secured)
	h.AITriage.Register(secured)
	h.Sbom.Register(secured)
	h.Asset.Register(secured)
	h.Compliance.Register(secured)
	h.Portfolio.Register(secured)
	h.Metrics.Register(secured)
	h.Correlation.Register(secured)
	h.ApiToken.Register(secured)
	h.SvcAccount.Register(secured)
	h.SCIM.RegisterAdmin(secured)
	h.Federation.Register(secured)
	h.Notify.Register(secured)
	h.Retention.Register(secured)
	h.Archive.Register(secured)
	h.Audit.Register(secured)
	h.IngestHealth.Register(secured)
	h.Engagement.Register(secured)
	h.Badge.Register(secured)
	h.FixPlan.Register(secured)
	h.Remediation.Register(secured)
	h.RootCauses.Register(secured)
	h.Exploits.Register(secured)
	h.Evidence.Register(secured)
	h.CRACases.Register(secured)
	h.FindingTmpl.Register(secured)
	h.ReportTmpl.Register(secured)
	h.CustomFields.Register(secured)
	h.CustomParser.Register(secured)
	h.Triage.Register(secured)
	h.Gate.Register(secured)
	h.SLA.Register(secured)
	h.Vex.Register(secured)
	h.IssueTracker.Register(secured)
	h.Connector.Register(secured)
	h.Report.Register(secured)
	h.License.Register(secured)
	h.Policy.Register(secured)
	h.VulnPolicy.Register(secured)
	h.PkgMeta.Register(secured)
	h.SSO.Register(secured)
	if h.Enrichment != nil {
		h.Enrichment.Register(secured)
	}
	if h.VulnMatch != nil {
		h.VulnMatch.Register(secured)
	}
	if h.Advisory != nil {
		h.Advisory.Register(secured)
	}
	h.FeedRules.Register(secured)
	h.PSIRT.Register(secured)
	h.Secrets.Register(secured)

	return &Server{
		app:  app,
		addr: cfg.HTTP.Host + ":" + cfg.HTTP.Port,
	}
}

// App exposes the underlying Fiber app for in-process testing via app.Test.
func (s *Server) App() *fiber.App { return s.app }

// Start begins listening and blocks until the server stops.
func (s *Server) Start() error {
	slog.Info("http server listening", "addr", s.addr)
	return s.app.Listen(s.addr)
}

// Shutdown gracefully drains in-flight requests.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.app.ShutdownWithContext(ctx)
}

func orInt(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

func orDur(v, fallback time.Duration) time.Duration {
	if v > 0 {
		return v
	}
	return fallback
}

// authConfig tells the login page how people sign in: whether the password form
// is offered, and one button per enabled, working SSO provider — read per
// request, so a provider added or disabled on any replica shows up at once.
// development lets the home page's empty-state point admins at `xila-api
// demo-seed` only outside production. Public (no auth required), so it
// carries only kind/name/login URL — never the provider settings.
func authConfig(cfg config.Config, h Handlers) fiber.Handler {
	return func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"password_login_enabled": h.Auth.PasswordLoginEnabled(),
			"password_reset_email":   h.Auth.PasswordResetByEmail(),
			"directory_login":        h.Auth.DirectoryLogin(),
			"providers":              h.SSO.LoginOptions(c.UserContext()),
			"development":            cfg.IsDevelopment(),
			"source_url":             cfg.SourceURL,
		})
	}
}

// errorHandler renders a consistent JSON error envelope.
func errorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	msg := "internal server error"

	var fe *fiber.Error
	if errors.As(err, &fe) {
		code = fe.Code
		msg = fe.Message
	} else {
		// Unexpected error: log with full detail but don't leak it to clients.
		slog.ErrorContext(c.UserContext(), "unhandled error",
			"error", err, "method", c.Method(), "path", c.Path())
	}

	return c.Status(code).JSON(fiber.Map{"error": msg})
}

// requestLogger emits one structured, trace-correlated log line per request.
func requestLogger() fiber.Handler {
	return func(c *fiber.Ctx) error {
		start := time.Now()
		// Render an error here, not after this middleware returns: otherwise the
		// status is written later and every 4xx/5xx would be logged as 200.
		if err := c.Next(); err != nil {
			if herr := c.App().ErrorHandler(c, err); herr != nil {
				_ = c.SendStatus(fiber.StatusInternalServerError)
			}
		}

		attrs := []any{
			"method", c.Method(),
			"path", c.Path(),
			"status", c.Response().StatusCode(),
			"latency_ms", time.Since(start).Milliseconds(),
			"request_id", c.Locals(requestid.ConfigDefault.ContextKey),
			"ip", c.IP(),
		}
		if span := trace.SpanFromContext(c.UserContext()); span.SpanContext().HasTraceID() {
			attrs = append(attrs, "trace_id", span.SpanContext().TraceID().String())
		}

		slog.InfoContext(c.UserContext(), "http request", attrs...)
		return nil
	}
}
