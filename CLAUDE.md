# CLAUDE.md

Guidance for working in this repo. Read this first, then skim `README.md`
(API + domain reference) and `docs/ROADMAP.md` (what to build next).

## What this is

Xila is a security platform API that ingests scanner/SBOM output and unifies
it into deduplicated findings with lifecycle, exploit-aware priority,
compliance posture, cross-project portfolio rollups, and notifications.
It combines DefectDojo, Dependency-Track, and CSPM/KSPM in one Go service, with an
embedded SvelteKit UI.

- Go 1.27 (Node 26 builds the UI), module `github.com/xilasec/xila-api`.
- Fiber (HTTP) · pgx/v5 + golang-migrate (Postgres) · OpenTelemetry · JWT/bcrypt.
- UI in `web/` (SvelteKit + daisyUI), compiled and embedded into the binary.

## Daily commands

Security gates: `make security` (grype + opengrep + KICS + gitleaks, same as CI) and
`make hooks` (pre-commit). Fix findings rather than suppressing them. A
suppression needs an inline reason (`nosemgrep: <rule> -- why`,
`kics-scan ignore-line`, `gitleaks:allow -- why` for a fake test secret, or a
`.grype.yaml` ignore). See
docs/SECURITY_SCANNING.md.

```bash
make up              # docker compose: api (all features on) + postgres + otel-collector + jaeger + mailpit (localhost:8080, mail on :8025)
make down            # stop, keep data   |   make purge = stop + drop the DB volume
make run             # go run ./cmd/api  (API only, no UI; see the "UI" gotcha)
make bundle          # build SPA + one binary that serves UI+API (-tags embedfrontend)
make test            # unit tests only (DB-backed tests self-skip)
gofmt -w . && go vet ./...
```

Run `gofmt -w`, `go vet ./...`, and the tests before declaring a change done.

## Running the tests (they need a real Postgres)

Integration and smoke tests are gated on `TEST_DATABASE_URL` and skip without it.
They **TRUNCATE tables between tests (see `internal/pgtest`), so point them at a
disposable database, not one with data you care about.**

```bash
make up   # or: docker compose up postgres -d   (gives Postgres on :5432, user/pass/db = xila)
export TEST_DATABASE_URL="postgres://xila:xila@localhost:5432/xila?sslmode=disable"
go test -p 1 ./...          # -p 1 is REQUIRED: tests share one DB and truncate; parallel packages deadlock
go test -p 1 -race -timeout 30m ./...    # before finishing a change (internal/server alone is ~9 min under -race)
make test-integration       # convenience wrapper for the two lines above
```

Migrations (`internal/database/migrations/`) run automatically on app start and
on `pgtest.Pool`. There is no manual migration step.

No Docker? Any Postgres works. Run `initdb` to create a throwaway cluster and point
`TEST_DATABASE_URL` at it.

## Architecture & conventions

Each domain is its own package under `internal/`, with the same layering:

- `<domain>.go`: the model struct and a `Repository` (all SQL lives here).
- `service.go`: orchestration and business logic, when there is more than CRUD
  (e.g. `scan` ingestion, `sbom`, `enrichment`, `license`, `notify`,
  `correlation`). Services depend on interfaces they define themselves, not
  concrete repos, so they can be unit-tested with fakes.
- `handler.go`: a thin Fiber HTTP layer. It validates input, maps domain errors
  to status codes, and calls the repo or service. It has a `Register(r fiber.Router)`.

Shared packages:
- `internal/domain`: enums (severity, category, status, criticality, asset
  type) with `Valid()` and weight/multiplier helpers. Add new enum values here.
- `internal/httpx`: `ID()`, `Parse()`, and pagination (`ParsePage`, `Meta`).
- `internal/config`: all env config. Add new settings here with `getenv`/
  `getbool`/`getdur`/`getlist` and a default. `APP_ENV` (`development`/
  `production`/`test`) drives hardening: `Load()` applies env-specific defaults
  (CORS, `CookieSecure`, dev JWT secret), `validate()` fails fast on unsafe prod
  config, and `Warnings()` returns non-fatal prod advice that `main` logs. Use
  a hard error in `validate()` for anything unsafe to boot, and a `Warnings()` entry
  otherwise.
- `cmd/api/main.go`: wires every repo, service, and handler together and starts
  background crons (`runEnrichment`, `runExceptionSweep`, `RunSummaries`, …) inside
  the `leader.Run` block, so with several replicas they run on one elected
  instance. **A new scheduled job goes in that block** (`job(func(){…})`, and it
  must return when its ctx is done). Per-request work that is safe on every instance
  (ingest workers, the queue monitor) stays outside it.
- `internal/server`: the `Handlers` struct (one field per handler), middleware,
  and route registration. It also holds `smoke_test.go`, the full-stack HTTP test.

### List endpoints
Return `{ "<items>": [...], "pagination": {limit, offset, count, has_more} }`.
Use `httpx.ParsePage` and fetch `limit+1` to compute `has_more` (see
`finding.Handler.respondList`).

### Errors
Repos return sentinel errors (`ErrNotFound`, `ErrDuplicate`, …). Handlers use
`errors.Is` to map them to `fiber.NewError(status, msg)`. Detect Postgres constraint
violations via `*pgconn.PgError` codes (`23505` unique, `23503` FK).

## Playbooks (the common changes)

Add a scanner: implement `scanner.Parser` (`Scanner()`,
`PrimaryCategory()`, `Parse(io.Reader) ([]ParsedFinding, error)`) in
`internal/scanner/<tool>.go`, and register it in `scanner.NewRegistry(...)` in
both `main.go` and `smoke_test.go`. Map only failing or relevant results. Put the
rule id in `RuleID` (it becomes the finding `rule_id`, which feeds compliance).
Add a unit test with a real sample report. Add a UI preset in
`web/src/lib/scanners.js`. Use the shared helpers (`normalizeSeverity`,
`cvesFrom`, `cweFrom`, `severityFromCVSS`, `decodeJSONLines`) instead of
re-deriving them. Lift the CVE even when it isn't the tool's primary id
(Grype reports a GHSA with the CVE under `relatedVulnerabilities`). Cross-tool dedup
and EPSS/KEV enrichment key on the CVE. Full guide and wanted list:
`docs/PARSERS.md`. Also add the fixture to the table in
`internal/server/{appsec,infra}_scanners_test.go`. That test uploads every sample over
HTTP and catches fingerprint collisions (fold them with `mergeSameLocation`).
Triage carried by an import format (DefectDojo `false_p`, SecObserve status,
`#nosec`…) goes in `Metadata` as `remote_triage` / `remote_triage_reason` /
`remote_triage_expires`. The `connector.RemoteTriage` applier (last in the list)
applies it only to findings this scan created that are still open. Do not write a
status from a parser, and do not let an import overturn local triage.

Add an advisory source: `internal/vulnmatch` matches every SBOM snapshot
(`sbom.ListSnapshotInventory`) against OSV.dev, records each snapshot's matches in
`sbom_vulns`, and turns the current snapshots' hits into a
synthetic `"osv"` scan per project via `scan.Service.ApplyFindings`. This reuses
the whole pipeline (upsert → auto-close what's no longer affected → auto-triage
→ dedup → priority → gates → alerts). To add another feed, implement
`vulnmatch.Source` (`Query(ctx, purls) map[purl][]Vuln`) and register it for `VULNMATCH_SOURCES`. See `osv.go`,
`github.go`, and `osvlocal.go` (the local mirror and private advisories share the OSV range
evaluator in `osvrange.go`). Keep
`Match` applying every project that has inventory, including ones with zero
vulns. That is what closes findings after a dependency upgrade. All sources share
the `osv` scanner name (per-source provenance lives in metadata), and
`MultiSource` merges by id and aliases (GHSA wins as the identity). A new scanner
name would close and recreate every existing finding.

**A failed source must not close findings: on partial failure, send the healthy results through `scan.Service.AddFindings` (no auto-close), not `ApplyFindings`.**

Component policies: `internal/policy` evaluates every current snapshot's
components (`sbom.CurrentInventory`: license, vulnerability, KEV/EPSS facts) plus
`pkgmeta.Info` against admin-defined policies. It applies the complete violation
set as scanner `policy` via `ApplyFindings` (fingerprint = policy id + purl, so a
fixed component auto-closes). To add a condition, add a subject in `condition.go`
(validate, match, and a table test). Two invariants apply. Unknown facts do not match
(a component with no license or registry data is neither compliant nor violating). Policy
findings do not feed component vulnerability state (`findingOnComponentSQL`
excludes `scanner='policy'`; otherwise a policy would keep itself violated). Evaluation re-runs on
SBOM upload (after that upload's OSV match and registry fetch), on policy edits, and
on `POLICY_EVAL_INTERVAL`.

License data: `internal/license` embeds the SPDX list and ScanCode categories
(`make licenses` refreshes `data/catalog.json`; this is the only networked code).
Components carry `license_expression` / `license_ids` / `license_categories` /
`license_resolved`, computed at ingest by `license.Resolve`. Do not match licenses
by substring. Use `Expr.Satisfies` (`MIT OR GPL-3.0` satisfies "no GPL").

Package freshness: `internal/pkgmeta` caches registry metadata per base purl
(leader cron `PKGMETA_*`, per-ecosystem mirror URLs) and writes `package_status`
per exact purl on fetch. Component queries join it. "Latest" means the newest stable,
non-yanked release. Unknown is null, not "up to date".

Reachability (SBOM-derived): `domain.Reachability` + `domain.Priority`.
The SBOM parsers recover the dependency graph (CycloneDX `dependencies` + `scope`,
SPDX relationships) into `Component.Direct/Depth/Scope`. `correlation.Reacher`
matches each package finding to the project's current inventory and writes
`dep_direct`/`dep_depth`/`dep_scope` + the rescaled `priority`. Two invariants are
tested. Unknown does not discount: with no SBOM graph, the finding keeps full priority.
Reachability discounts but does not suppress: a KEV critical in a dev dep still outranks a
quiet shipped medium. `Reacher` runs as a `scan.Applier` on ingest and
project-wide on SBOM upload, since a new SBOM can move a package from direct to
transitive. Weights live in `domain`. Change them there; the tests assert exact
numbers.

Add a post-ingest pass: implement `scan.Applier` (`Name()`,
`ApplyToScan(ctx, projectID, scanID)`) and add it to the `appliers` slice in
both `main.go` and `smoke_test.go`. Appliers run in order, scoped to the scan's
findings, *before* dedup (priority elects a group's primary) and before the alert.
`correlation.Reacher` and `triage.Service` are the worked examples. A pass that
also has a project-wide form should expose `ApplyToProject` and regroup
(`Deduplicate`) when it changes priorities in bulk.

VEX: `internal/vex` ingests OpenVEX + CycloneDX VEX (sniffed in `Parse`) into
`vex_statements` and applies them as a `scan.Applier` on every ingest.
`not_affected`/`fixed` → `false_positive`. This is a *triage* state, deliberately not
`remediated`, which the next scan would reopen. `affected` → `confirmed`. VEX runs
before the triage rules in the applier list, because a VEX verdict is
authoritative and must win over a generic rule. **Unknown statuses are dropped, not
guessed: a misread verdict silently suppresses a real finding.**

Add an SBOM format: write a parser in `internal/sbom/` that returns a `Document`
(components with `BomRef`, plus `RootRef` + `Edges` for the dependency graph),
and wire it into `sbom.Parse` (content sniffing). See `spdx.go`.

AI inventory (ML-BOM): `internal/sbom/ml.go`. Every component row has a
`kind` (`software`/`model`/`dataset`/`ai-service`), and AI rows have an `ml` jsonb
(`MLFacts`, model-card essentials). An `ai-service` row is *derived* from a
service in the same snapshot (model-linked or a known provider API). The graph
and the BOM export skip it, because the service is already exported as a service and a round
trip would otherwise duplicate it. The `model.*` / `dataset.name` policy subjects judge
AI kinds only. A software component is unknown to them and does not match.

SBOM history: "is this component vulnerable" has one definition,
`sbom.VulnState`, implemented once in SQL as `componentVulnsJoin`. It is the union of advisory rows in
`sbom_vulns` for that snapshot and scanner findings on that exact package version in
any status except `false_positive`, keyed by min CVE, else advisory/rule id.
`SnapshotVulnerabilities` and `VulnerabilityTimeline` repeat the same rule, so change
all three together. A component's advisory match key is its purl, else its CPE
(`SnapshotComponent.MatchKey` / `componentKeySQL`). `sbom_vulns.purl` holds that key,
so join advisories on `componentKeySQL`, not on `c.purl`. CPE-only components are
looked up through `CPESource` (the `nvd` source). A CPE failure is partial and does not
auto-close anything. Do not mutate a map a source returned. `sbom_vulns` is written only by `vulnmatch` (every snapshot,
replaced per run). Findings come only from current snapshots, applied via
`applyIfCurrent` under a per-project advisory lock (namespace 2). Do not hold that
lock across the OSV call. Diff (`DiffComponents`), graph (`BuildGraph`, `Paths`), and
timeline (`settle`) logic are pure Go with unit tests; keep SQL to loading.
API lists must serialize as `[]`, not `null`, because the UI iterates them.

Compliance rule, twice: `compliance.Evaluate` and the portfolio rollup
(`portfolio.aggregateCompliance`, and `ControlFindings`) must apply the same rule.
All of them read `compliance.FindingMatchesSQL` (the (finding, project, control) pairs)
and `ProjectFactFailingSQL`, and skip manual controls unless attested. A new
match type is one more equi-join branch there (plus the `control_mappings`
CHECK), not a condition in one query only. Do not use an OR-ed join; it
cost seconds per project at 100k findings. `TestFindingMatchesIsTheRule` pins
the rule against the original formulation.

Add a compliance framework: this is pure data. `INSERT` rows into `frameworks` /
`controls` / `control_mappings` in a new migration. Map by CWE
(`match_type='cwe'`, tool-agnostic) or by scanner rule (`match_type='rule'`,
`scanner`+`rule_id`). See `000008_compliance` (OWASP) and `000011_cis_aws`
(Prowler). No code changes are needed. The framework shows up in `/compliance` and the portfolio.

RBAC / authorization: tenancy is Organization → Team → Project. Users
have a global `is_admin` flag plus `is_owner` (the single instance owner). The first
user bootstraps as owner. The owner cannot be demoted or removed by anyone. One-owner
and owner-is-admin are schema constraints, and ownership moves only via `user.TransferOwnership`.
Users also have a per-org role
in `org_members` (`admin`/`member`, `domain.OrgRole`), a per-team role in
`team_members`, and a per-project role in `project_members`, using the same
`owner`>`editor`>`viewer` vocabulary (`domain.TeamRole`). The effective project role is
`domain.MaxTeamRole` of (direct project grant, team role, org-admin owner), i.e. the
highest, computed in `membership.RoleOnProject`. Its grant rows are one SQL constant,
`membership.ProjectGrantsSQL`, which the permission audit (`internal/access`) and
`UsersWithProjectAccess` also read. A new kind of grant goes there, or the audit
and authorization disagree (`TestAuditAgreesWithAuthorization` checks a random matrix). Roles only add access. A lower grant does not
demote a higher one. `is_admin` is read from the DB on every request
(`membership.AdminStatus`), not from the JWT claim. Trusting the claim would
mean a demotion takes effect only when the token expires. Any new portfolio-wide list
must scope by `Scope.ProjectIDs` (which unions direct project grants), not
`Scope.TeamIDs`. Otherwise a directly granted project is openable but invisible. Project hierarchy (`projects.parent_id`, migration 000073): project and
team grants inherit down the tree through the `parent_project` branch of
`ProjectGrantsSQL` (`project_ancestors()`), and `ProjectIDsForUser` reads the
same rows. Tree rules (same org, no cycle, depth 5, a collection holds no
scans/SBOMs) live in the `projects_hierarchy` / `*_collection_guard` triggers.
A rollup (`?include_children=`) widens the project-id set with
`projecttree.Rollup` and reuses the existing `= ANY($ids)` queries. Do not add a
second query style. Enforcement is
centralized in `internal/authz.Middleware` on the `secured` group. It parses the
path, resolves the owning org/team (via `membership.Repository`), and denies by
default. Team routes: GET needs `viewer`, mutations need `editor`, team/member management needs
`owner`. Org routes: GET needs org membership; mutations, member management, and `.../teams`
need org `admin`. `/users`, `/enrich`, `/notifications` are admin-only.
Org admins are treated as `owner` of every team in their org. This lives in
`membership.RoleOnTeam` (COALESCE of the team role and an org-admin fallback) and
`TeamIDsForUser`/`ProjectIDsForUser` (which UNION org-admin teams). Portfolio-wide
list endpoints (`/orgs`, `/teams`, `/projects`, `/findings`, `/components`,
`/portfolio`, `/assets`) have no id in the path. For these, the middleware stores an
`authz.Scope` (visible org/team/project ids) that the handlers read to filter.
So **a new cross-tenant list endpoint must call `authz.VisibleScope(c)` and
filter**. A new per-resource route is covered automatically if its path carries an
`orgID`/`teamID`/`projectID` or a `findings|scans|sboms|assets` id (extend
`membership.resourceTables` + `parseScope` for a new resource type). Instance
admin (`IsAdmin`) bypasses all of these checks.

Uploader role: `domain.TeamRole` is `viewer < uploader < editor < owner`
(`TeamRole.rank`). `uploader` is "viewer plus uploads", for CI tokens: it
passes `AtLeast(viewer)` (reads the project, its findings, scans, SBOMs, VEX
like any viewer) but not `AtLeast(editor)`. `authz.Middleware` has a per-route
`allowUploader` opt-in (`parseScope` in `authz.go`, checked as
`role.AtLeast(domain.TeamUploader)`) for exactly the routes that would
otherwise need `editor`: `POST /projects/{id}/scans|sboms|vex|gate`. Every
other read (`GET /scans/{id}`, `GET /projects/{id}/findings`, the global
`GET /findings?project_id=&scan_id=&new=true`) needs no carve-out: `uploader`
already clears the `viewer` bar those routes set. Because roles only add
access, `MaxTeamRole` picks the single highest-ranked role when a user holds
more than one, so `uploader` + `viewer` is still `uploader` (keeps the upload
grant, not demoted to read-only) and `uploader` + `editor` is `editor` (which
already includes upload). The combination is never weaker than its strongest
grant. Any hand-rolled SQL that ranks roles by a `CASE ... WHEN 'owner' ...
WHEN 'editor' ... ELSE` (the permission audit's `accessSQL`,
`membership.UsersWithProjectAccess`) must bucket `uploader` between `editor`
and `viewer` explicitly, or it silently reports an uploader grant as `viewer`.

SSO (OIDC + SAML): `internal/oidc` and `internal/saml` only handle the protocol.
Both hand a verified identity to the shared layer in `internal/sso`, which calls
`user.LinkIdentity` (identity → user by (provider, issuer, subject) in
`user_identities`; else link by a *verified* email; else JIT-create when
`SSO_AUTO_CREATE_USERS`; the first user bootstraps the owner). It then syncs IdP
groups to roles through admin-managed `sso_group_mappings` and mints the normal
JWT. RBAC itself is untouched. Grants carry `source manual|sso` (and
`users.admin_source`). The sync only adds, changes, or removes `sso` rows. It does not touch manual
grants or the owner. Keep it that way in any new membership write path
(manual paths must leave `source` at its `manual` default). SAML specifics:
crewjam/saml does all signature/audience/time/InResponseTo checks (do not hand-roll
XML-DSig). Consumed assertion ids live in `saml_seen_assertions` (replay protection across
replicas). The SP key is generated once into `saml_sp_keys` (secretbox) unless
`SAML_SP_CERT/KEY` are set. The request-tracking cookie must survive the IdP's
cross-site POST, so it is `SameSite=None; Secure`. Over plain http it only
works with the IdP on the same site (there is a startup warning). `PASSWORD_LOGIN_ENABLED=false`
leaves only the owner's password login (break-glass). Providers are runtime
data: admins manage any number of OIDC/SAML providers in `sso_providers`
(secrets encrypted with secretbox, write-only in the API) through the SSO page.
The `OIDC_*`/`SAML_*` env config adds one read-only provider each at the legacy
URLs (`/auth/oidc/login`, `/auth/saml/acs`…). DB providers live under
`/auth/{oidc,saml}/{slug}/…`. These routes are always mounted and return 404 for unknown or disabled slugs (the
drift test's `optional` set is empty; keep it that way). The registry re-reads the
provider row on every login request, so edits and disables apply on all replicas
immediately. It caches the expensive discovery/metadata per `updated_at`. All
per-flow cookies are scoped and keyed per provider slug. Do not share flow state
between providers. Tests use in-process IdPs; the flows were also verified
against a real Keycloak. Single Logout (`internal/saml/slo.go`): signing out
of Xila stays local. Only an IdP's verified `LogoutRequest` bumps
`token_version`. HTTP-Redirect messages are signed in the query (build them with
`Service.redirectURL`, because crewjam's `LogoutRequest.Redirect` doesn't query-sign).
A parsed request is decoded from the element goxmldsig verified, not re-read.

LDAP and two-factor: `internal/ldap` is a third identity protocol next to
OIDC/SAML (kind `ldap`, env-configured, one directory). It searches with the service
account, binds as the user (not with an empty password), then hands an
`sso.Assertion` to `sso.Service.Login`. It has no linking or role logic of its own.
`auth.Service.Login` sends accounts without a local password to the directory.
Two-factor (`auth/mfa.go`) gates every *password* sign-in. A first-factor
success goes through `signedIn`, which returns an `MFARequiredError` challenge
(JWT `purpose: "mfa"`, which `auth.Middleware` refuses as a session) instead of a
token. **Any new way to finish a password sign-in (like the reset link) must go
through `signedIn` / `challenge`, not `TokenFor` directly.**

CEL expressions: `internal/expr` is the single expression language (policy
subject `expression`, triage `Rule.Expression`). Each consumer builds its own
fact document (`policy.componentDoc`, `triage.findingDoc`) and derives its
`expr.Schema` sample from that same function, so save-time validation can't
drift from evaluation. Unknown facts are `null`. `Program.Match` treats every
evaluation error as false, not as a match. To add a fact, add it to the doc
builder (and the README/OpenAPI field lists). Do not add a second language.

**Custom fields**: `internal/customfield` holds admin definitions
(`custom_field_definitions`) and values in a jsonb `custom` column on projects,
assets and findings. Every value write goes through `customfield.Service.Prepare`
(type, enum, org scope, a user who can see the project). A finding's value then goes
through `finding.Repository.SetCustom` (`withActor`; the `findings_events_custom` trigger
logs one `custom_field` event per changed key). `?cf.<key>` filters use
`customfield.ParseFilters` + `AppendSQL` on every list (findings via `listQuery`, so
exports match). CEL sees `custom` through the doc builders. Save-time schemas come
from `FindingSchemaFor` / `ComponentSchemaFor` with the current definitions, while
stored triage rules load with `expr.Load` (no dry run). A deleted field therefore makes a
rule not match (a policy that no longer compiles is skipped, as before).

**Service accounts + workload identity federation**: a service account is a
`users` row with `kind='service'` (+ `service_accounts` metadata), so membership,
authz, scopes, `token_version` and `disabled_at` apply unchanged. The schema
forbids it a password, admin or ownership. Keep it out of people flows: the
users list, SSO linking and password reset skip it, and `account.sessionOnly`
refuses it. Suspending deletes its keys *and* bumps `token_version`. Any new
credential type for it must be revoked by one of those. `internal/federation`
verifies identity tokens with go-oidc (JWKS via discovery through netguard,
verifier cached per issuer `updated_at`). A binding must pin an identity claim
(`identityClaims`) without a leading wildcard. Matches that disagree on the
account or project are refused, never resolved by order. Exchanged sessions are
JWTs with `svc`/`prj` claims; `prj` confines them like a project-scoped token.

**Risk acceptances**: `internal/finding/acceptance.go`. A finding is
`risk_accepted` only while an approved `risk_acceptances` row covers it
(live membership in `risk_acceptance_findings`, `removed_at IS NULL`, at most one
per finding). `SetStatus`/`Apply` refuse `risk_accepted`
(`ErrRiskAcceptanceRequired`). Every other status they set also takes the finding
out of its acceptance (`leaveAcceptances`). Never delete ledger rows; stamp
`removed_at` + `reason` instead. System writers (triage rules, imported verdicts) go
through `AcceptBySystem` with a `source_key`. The finding's `exception_*` fields
now describe false_positive / wont_fix only. Readers of "why / until when" use
`Finding.Exception()` or `ExceptionExpirySQL`.

**AI-assisted triage**: `internal/aitriage` (opt-in, `AI_TRIAGE_*`). A model's
answer is only recorded as an `ai_proposals` row. Only a
person's accept applies it, through the finding package's own paths
(`finding.Repository.ApplyProposed` → `setStatusTx`/`applyChange` under
`withActor`, `RequestAssessment` with `ASSESSMENT_REQUIRES_APPROVAL`,
`RequestAcceptances` for `risk_accepted`). Never write findings from the
package. Everything sent is built by `BuildPrompt` (finding fields only, a
snippet only if the scanner gave one, secrets scrubbed; the preview endpoint
returns the same prompt). A new field goes there and into its redaction test.
Answers are parsed strictly (`ParseAnswer`: exact keys, enums per kind). An
out-of-set value makes the proposal `invalid`; there is no "best effort" parsing.
Provider calls use netguard; provider error text is admin-only (`RemoteError`).

**Add a triage-rule action / condition**: `internal/triage` is the auto-triage
engine. Rules (conditions → action) run on every ingest (`scan.Service`
calls `triage.Service.ApplyToProject` before the new-critical alert) and via
`POST /triage-rules/apply`. To add a match condition, extend `Rule` + the
`triage_rules` migration + `Rule.Matches` (pure, unit-tested) + `ruleColumns`/
`scanRule`. To add an action, extend the `Action` enum + the migration CHECK +
`Service.apply` (and add the finding-repo mutation it needs, like `SetSeverity`).
Rules are admin-managed (`/triage-rules` is in `authz` `adminOnly`). Keep `apply`
idempotent. It re-runs on every ingest, so skip findings already in the target
state.

CRA Article 14 cases: `internal/cra` (`cases.go`, `service.go`). "Actively
exploited" has one definition, `exploitedSQL` (open/confirmed, default version,
`duplicate_of IS NULL`, `kev OR exploit_maturity='weaponized'`, project
`cra_in_scope`). A new exploitation signal goes there, not into a caller. It is
reached from every place that flags exploitation (`enrichment.Service.WithCRA`,
`exploitintel.Service.WithCRA`, the leader sweep, `SetProduct`), so a new
KEV/exploit source must call `OpenExploited` too. One case per (project, lowest
CVE else rule id): `ON CONFLICT DO NOTHING`, not reopened. Deadlines are
`time.Add` of absolute hours (no `interval 'N days'`). Deadline alerts fire once
per case and stage via the `alerted_due_soon`/`alerted_missed` arrays, guarded
in the `UPDATE` itself so concurrent sweeps can't double-send. State changes go
through `Repository.transition` (row lock + event row with actor and payload).
The rules are the pure `submit`/`dismiss`/`closeCase` functions.

Add a notification event: add a constant in `internal/notify/notify.go`
(`EventXxx`), emit `notify.Event{Type: EventXxx, ProjectID: …}` at the right
spot via `go notifier.Notify(context.Background(), …)`, and add it to the UI
event dropdowns (`web/src/routes/notifications/+page.svelte` and the project
Alerts tab). Events with a `ProjectID` route to global and that project's channels.

SLA: `internal/sla` owns policies (`sla_policies`: global / org / project;
the most specific wins as a whole; the built-in 7/30/90/120 lives in the SQL function
`sla_policy_for`) and the breach / due-soon sweep. The per-finding clock
(`sla_days`, `sla_due_at`, pause bookkeeping) is a database trigger
(`findings_sla_maintain`, migration 000027). This is deliberate: status and
severity are written from a dozen places, and each must move the
clock. So **don't compute SLA fields in Go write paths**. A new status that
should pause the clock must be added to both `FindingStatus.PausesSLA` and the
trigger. `domain.SLAStatusAt` is the read-side classification and
`finding.slaCondition` its SQL twin. Change them together (`SLADueSoonFraction`
is the shared constant). SLA time is absolute (24-hour days, paused time as
seconds). Adding a `days` interval to a `timestamptz` is calendar arithmetic and
drifts an hour across DST. A policy change must re-date existing findings
(`sla.reapply`, per project, inside the policy transaction).

Exploit intel / priority inputs: `domain.Priority(sev, Exploitability{EPSS,
KEV, Maturity}, reach, exposure)`: every writer of `priority` (enrichment, `Reacher`,
`exploitintel.Repository.Apply`, `finding.Reprioritize`) must pass the finding's
current other signals (`Enrichable` / `ReachTarget` carry `ExploitMaturity` and
`AssetExposure`, read through `asset_id`). Otherwise one pass silently
undoes another's uplift. `exploit_maturity` is an enrichment-written read column
(not in the upsert). A failed feed does not delete its rows (`Replace` runs only on
success, and an empty parse counts as a failure).

Asset exposure & relations: `internal/asset`. `assets.exposure` (NULL =
unknown, never discounts) is either `manual`, which inference must not overwrite,
or `inferred` by the `exposure` ingest applier (`asset.Infer`, pure and tested; it
only raises). The applier runs after the triage rules and recomputes the
scan's priorities with `finding.Reprioritize`. Any exposure change re-ranks the
asset's findings and regroups the project (priority elects dedup primaries).
Relations cross projects, so their handlers check the other end's visibility
themselves (`visible`/`mustSee`; invisible = 404), and blast radius drops assets the
caller can't see. The middleware only covers the path asset.

Engagements & manual findings: `internal/engagement`. An engagement groups
scans (`scans.engagement_id`, composite FK `(engagement_id, project_id)` so a scan
can only join its own project's engagement; `ON DELETE SET NULL (engagement_id)`).
Manual findings go through `scan.Service.AddFindingsTo` with scanner
`finding.ManualScanner` and `Target.Actor`, so the history credits the reporter
(`UpsertBatch`'s actor sets `xila.actor` inside the batch's implicit
transaction). **Do not use `ApplyFindings`: it would auto-close every earlier
manual finding.** Only manual findings' write-ups are editable
(`finding.Repository.UpdateDetails`). Report templates live in `internal/report`
(`Template`, sections as `{{define}}` blocks in `report.html`). Any value placed
into CSS or a URL goes through the `css` / `dataURI` funcs, which re-validate
even what the API already validated.

Remediation actions: `internal/remediation` tracks findings grouped by the
change that fixes them. The grouping itself is `fixplan.Changes` (pure, in one
place; the fix plan is its `package_upgrade` slice), so a new kind or grouping
rule goes there with a table test, not in SQL or the UI. A change's `key` must be
stable across scans (no line numbers, versions only where the change is
version-specific), or live actions stop collecting their new findings. One live
action per (project, kind, key) is enforced by a partial unique index. A finding
is in at most one live action (`AddFindings` skips the rest). Due date, owner, and
auto-close are derived in `Repository.Refresh` (write only what changed). The
ingest pass runs after dedup (`scan.Service.WithFollowUps`), not as an applier.
Action tickets sync through `issuetracker.LinkSyncer`, reusing
`issuetracker.Decide`.

Root causes: `internal/rootcause` answers "what's the same problem
everywhere?" by merging every visible project's `fixplan.Changes` into one row
per (kind, key) in `fixplan.RootCauses` (pure, table-tested); no second grouping
decision. `GET /root-causes` and `GET /root-causes/{kind}/{key}` are
portfolio-wide lists scoped by `authz.VisibleScope`, like the fix plan and
remediation; `POST /root-causes/{kind}/{key}/remediation` spans the caller's
visible projects carrying the change (`routeScope{}`, editor checked per
project in the handler, like `POST /findings/bulk`; never load or name a project
outside the visible scope) and reuses `remediation.Service.Accept` so its
invariants (one live action per change, idempotent) hold rather than writing a
second path to the same table. A change's key can hold `/` and `@` (scoped
npm packages, purl bases), so it's a base64url path segment, not raw. Gated by
the `remediation` feature switch, not a feature of its own.

PR comments: `cmd/xila` (`upload --comment`) posts the gate result and the
findings this scan introduced (`GET /findings?scan_id=…&new=true`) to the pull
request. `github.go` is a stdlib GitHub client. The comment carries a hidden
`<!-- xila-report -->` marker and is edited in place on every push, so each PR has
one comment. Rendering is in `report.go`, which is pure and unit-tested without a
network. Commenting is best-effort: a GitHub failure logs a warning but does not
change the exit code, and outside a PR context it does nothing. `upload --check`
(and `gate --check`) post the same best-effort way to a GitHub check run
(`checks.go`: pure annotation/batching logic, matched for update by name and head
SHA; more than 50 annotations are split across PATCH calls per the Checks API's
per-request limit).

Document an endpoint: the OpenAPI spec is hand-written at
`internal/apidoc/openapi.yaml` and embedded (`GET /api/v1/openapi.{json,yaml}`,
public; the UI renders it at `/docs`). This step is required:
`internal/server/openapi_drift_test.go` walks Fiber's real route table and fails if
a route is undocumented or a documented path no longer exists. Conditionally
registered routes (OIDC) go in that test's `optional` set. Quote YAML flow
scalars that contain a colon (`description: "…Authorization: Bearer…"`).
Otherwise the spec silently stops parsing. After any spec change, including descriptions, run `make clients`
and commit the regenerated `clients/`: CI's `clients` check fails otherwise.

Export what a list shows: exports (`internal/export`, `/…/export`) and the
HTML reports (`internal/report`) must share the list endpoint's filter parsing
and SQL (`finding.listQuery` / `Repository.Each`, the sbom `componentQuery`), so an
export cannot show a row the list hides (RBAC scope, default version,
duplicates). CSV cells go through the formula-injection escape. Interchange
formats (VEX in `internal/vex/export.go`, CycloneDX BOM in
`internal/sbom/bom_export.go`) have round-trip tests against our own
importers. Keep them passing when you change either side.

Metrics snapshots: `internal/metrics` writes one `metric_snapshots` row per
UTC day and scope. Every stored figure must be summable (counts, sums of
remediation days, not averages), because non-admin trends are the sum of the
visible projects' rows. New metric columns follow the same `onDefaultVersion` /
`duplicate_of IS NULL` rules as every other count, and today's snapshot must keep
matching `/summary` (`TestSnapshotTodayMatchesLiveViews`).

Outbound HTTP: every server-side request to a URL that came from config or
a user (trackers, connectors, SSO discovery/metadata, webhooks, registries,
advisory sources, mirrors) goes through `internal/netguard` (`NewClient(timeout)`,
or `Transport()` + `WrapTransport` for a tuned transport). It checks the resolved
address in the dialer, so redirects and DNS rebinding can't bypass it. The policy
is process-wide (`SetDefault` in main from `OUTBOUND_*`; tests get `Permissive`,
which allows the loopback `httptest` servers). Don't build an `http.Client{}` for
such a URL, and validate URLs on save with `netguard.CheckURL`. A remote's own
words (response body, dial error) are shown to instance admins only: keep
them in a `RemoteError` detail and store only the public message (e.g. connector
`last_error`).

Accounts and sessions: JWTs carry `tv` (the user's `token_version`).
`auth.Middleware` rejects stale or deactivated sessions via `user.SessionValid` on
every request. Anything that should end a user's sessions bumps the version
(`SetPassword`, `RevokeSessions`, `SetDisabled`). Don't rely on JWT expiry. A
deactivated user is refused everywhere: password login, SSO (`sso.Service.Login`),
API tokens (`apitoken.GetByHash`). Reset tokens are stored hashed, single use,
newest-only. Account-security actions refuse API tokens (`sessionOnly`).
Sessions also carry `auth_time`, when the user last proved who they are.
`auth.Service.TokenFor` stamps it now, so call it only right after a real
authentication (sign-in, MFA, SSO, password change/reset, `Reauthenticate`);
reissuing a session without credentials (`RevokeSessions`) must use `reissue`,
which keeps the old one. Creating an API token requires a recent `auth_time`
(`REAUTH_WINDOW`).
Password/reset endpoints go behind `throttle` (`ratelimit`; reset-request uses
`ResetMiddleware`, whose bucket a 202 never clears).

Notifications are durable: `notify.Service.Notify` only *enqueues*
(`notification_outbox`, one row per subscribed channel). The leader's
`RunDispatcher` sends with backoff, leases claimed rows (`FOR UPDATE SKIP
LOCKED`) and logs one delivery row per final outcome. Callers may keep `go
notifier.Notify(...)`, but it no longer sends anything itself. Tests that need
the send call `DispatchDue`; payload tests use `SendTo` (the synchronous Test
button path).

Secrets at rest: integration credentials (issue trackers, connectors) are
encrypted with `internal/secretbox` (AES-GCM, key `INTEGRATION_SECRET_KEY`, the
project id as AAD) and are write-only in the API (`has_token`). Reuse it.

Audit log: `internal/audit` records every mutating request on `secured`
(middleware between auth and authz, so refusals are logged) and the public
sign-in endpoints (`Recorder.Auth`, matched in `authAction`; a new public auth
endpoint must be added there). New secured routes are covered automatically
(`TestAuditLogCoversEveryMutatingRoute` walks the route table). A handler that
knows the prior state calls `audit.SetChanges(c, before, after)`. Otherwise the
request body is stored redacted, so a new request field holding a credential
must match the one policy in `audit/redact.go` (add it there and to its test).
Writes never fail the request. The table is append-only (trigger). Only
`audit_log_purge` (retention) may delete. **Do not run `DELETE FROM audit_log` anywhere else.**

Add a migration: `NNNNNN_name.up.sql` / `.down.sql` in
`internal/database/migrations/` (embedded). If it adds a table, also add it
to `pgtest.allTables` (children first; tables are truncated between tests).

Add a column to `findings`: this table has a hand-written positional
upsert. Update these together: the `Finding` struct, `findingColumns`,
`scanFinding` (scan order must match column order), and `upsertSQL` + `upsertArgs`
(arg order must match the placeholders; `Upsert` and the batched `UpsertBatch`
both use them, so they can't drift). The exception/enrichment columns are worked examples. `Upsert`
sets `first_scan_id = last_scan_id` on insert, which is how "new this scan" is
detected (`ListNewHighSeverity`). `correlation_key`/`duplicate_of` are not set
by `Upsert` (leave them out of the INSERT arg list). They're recomputed by
`Repository.Deduplicate` (cross-tool dedup), which `scan.Ingest` runs after
auto-triage. A plain read column only needs `findingColumns` + `scanFinding`
(not the INSERT). **Anything that lists or counts findings for display or metrics must
exclude `duplicate_of IS NOT NULL`** (see `List`'s `IncludeDuplicates`,
`CountByProject`, `ListNewHighSeverity`, `ListForTriage`, and the portfolio
aggregates) so cross-tool copies aren't counted twice.

**Cross-tool dedup correlation key**: `finding.Repository.deduplicate` (both
`Deduplicate` and the scan-scoped `DeduplicateScan` call the same unexported
function) computes `correlation_key` in one SQL `CASE`: CVE findings key on
min CVE + package, or + location for a package-less CVE (network/DAST); a
finding with no CVE (SAST, secrets, IaC) keys on category + file_path + line,
plus CWE when it has one. A finding's key simply omits the CWE segment when it
has none, so a CWE-bearing and a CWE-less report at the same line never share
a key, while two CWE-less reports there still fall back to grouping by
location alone. A finding with neither a CVE nor a file_path/line (most DAST
without a CVE) gets no key; do not add fuzzy title matching. Election (step
2 of `deduplicate`) elects the highest-priority row per `(version_id,
correlation_key)` as primary and marks the rest `duplicate_of` it. For a
CVE-keyed group that happens unconditionally (same scanner or not, unchanged from before
this feature); for a location-keyed group (`correlation_key LIKE 'loc|%'`),
only when every member of that group is a different scanner
(`scanner_counts`: `count(*) = count(DISTINCT scanner)` per
`(version_id, correlation_key)`, computed in a grouped CTE since Postgres has
no `count(DISTINCT …)` window function). A location-keyed group with more than
one report from the same scanner never collapses at all, not even the
cross-scanner pairs inside it, so no member hides behind a report that isn't
actually a duplicate of it. Migration 000089 backfilled this for data that
predates the location key; keep its SQL in sync with this function if the
formula changes again (see migration 000057/000056 for the CVE-location
precedent).

**Archive instead of delete**: projects, engagements, scans and findings are
archived (`archived_at`), not deleted by a user DELETE (`internal/archive`;
`?purge=true` is admin-only, and the retention job purges past
`ARCHIVE_RETENTION`). Liveness has one SQL fragment per entity
(`archive.Project/Engagement/Scan/Finding(alias)`). Any new query that lists or
counts these entities appends it next to `duplicate_of IS NULL` /
`onDefaultVersion`. A project's children are archived through the project (the
fragment reads it), so don't stamp their rows.

**Branches / versions**: every scan, SBOM and finding has a `version_id`
(`project_versions`, one `is_default` per project). Resolution is in SQL. The
`project_version(project, name, kind)` function creates a version on first use,
and the `fill_version_id` triggers fill a missing `version_id` on insert. Write
paths therefore don't pass versions around in Go beyond the explicit ones
(scan/SBOM create, `ApplyFindings`, the upsert's `$22`). Two rules. First, a new
metric, summary or alert query must read only default versions: append the
`onDefaultVersion` SQL fragment (`internal/finding`). Second, anything scoped
"per project" that compares findings across scans must also match `version_id`
(auto-close, dedup partitions by `(version_id, correlation_key)`, inventory
matching). Triggers on `findings` fire alphabetically: `findings_0version` runs
before `findings_sla` on purpose. Keep new BEFORE triggers ordered by name.

**Finding history**: `finding_events` is written by the `findings_events`
trigger on every status, severity or assignee change, so there is no need to log
manually. To attribute a user-driven change, run it in a transaction that first calls
`withActor(ctx, tx, userID, reason)` (transaction-local `xila.actor`/`xila.note`).
Anything else is recorded as `system`. New user-facing finding mutations must go
through a transaction that does this. Cross-project actions on findings (like
`/findings/bulk`) can't be authorized by `authz.Middleware`. Make the path scope
`routeScope{}` in `parseScope` and authorize each finding's project in the
handler (`finding.Handler.can`), answering "not found" for unauthorized ids.

**Feature switches**: `internal/feature`. A switchable feature is one `Def` in
`feature.Defs` (key, the API `Routes` and unauthenticated `Public` patterns it
owns, and `OwnerOnly`). Turning a feature off has three effects, all keyed by the same string:

- Its routes answer 404. `Middleware` runs on `secured` after auth and audit and before authz,
so anonymous callers still get 401 and refusals are logged. `PublicMiddleware` runs on
the app for the public routes.
- Its background work and ingest side effects are skipped. The owning service takes a `Features` interface via
`WithFeatures` and checks it (see `cra`, `remediation`, `notify` personal routing,
`auth.mfaRequired`).
- The UI hides it (`features` store, `isOn`).

**Do not delete or rewrite data when a feature goes off**: turning it back on must restore it.
Patterns are case-insensitive regexes over the full path.
`TestFeatureRoutesMatchRouteTable` checks every gated route against Fiber's real
table, so a new route under a feature's path fails until you list it. A feature the
server's config rules out goes in `feature.Unavailable` (it reads as off and the switch
can't turn it on). Unknown keys read as on, so a typo can't switch
something off. Anything that weakens sign-in security is `OwnerOnly`.

**Wire a new handler**: add the field to `server.Handlers`, call
`h.X.Register(secured)` in `server.New`, and construct it in both `main.go`
and `internal/server/smoke_test.go` (missing smoke wiring causes a nil panic in the test).

## Testing conventions

- Unit (no DB): pure logic and services with fakes. Fast, run on every change.
- Integration (`*_db_test.go`, `package x_test`): real Postgres via
  `pgtest.Pool(t)`. Seed with small raw `INSERT`s or sibling repos.
- Smoke (`internal/server/smoke_test.go`): the whole app via `app.Test`. Add
  an assertion when you add a user-visible flow.
- Async code (notifications) is made deterministic in tests with a channel in a
  fake notifier, or an `httptest.Server` for real delivery.
- Weights and scores live in Go (`domain`), so tests assert exact numbers.

## Gotchas (learned the hard way)

- UI build: `web/build` is gitignored and only a `-tags embedfrontend` build
  serves the UI. `make run`/`go run` serve the API only. After editing Svelte,
  run `pnpm build` in `web/` (or `make bundle` / `make up`) and hard-refresh
  the browser (hashed assets cache). Nav pages live under `web/src/routes/`.
- The ingest queue has backpressure. `scan.QueueMonitor` samples `scan_jobs`
  on an interval (one query per tick, not per request) and feeds both the OTel
  gauges and the upload handler's `429` shed at `INGEST_MAX_QUEUE_DEPTH`. A failed
  sample keeps the last good snapshot. Reporting an empty queue when the DB is
  down would disable backpressure when it's needed most.
- Queued payloads can live outside Postgres (`INGEST_PAYLOAD_STORE=s3`, M11
  11.8, `internal/objectstore`): `scan.Service.Enqueue` uploads to the object
  store and leaves only `scan_jobs.payload_ref`; `ProcessJob` fetches it and
  deletes it on success. A job that exhausts its retries keeps its object —
  deliberately, so it stays inspectable — until `LOG_RETENTION` purges the
  parked row and the object together (`retention.pruneFailedJobs`). Anything
  that reads `scan_jobs.payload` directly must handle it being `NULL` when
  `payload_ref` is set (the migration's xor `CHECK`).
- The ingest tail is scan-scoped and must stay that way. `scan.finish` runs
  `triage.ApplyToScan` + `finding.DeduplicateScan`, both scoped to the findings
  *this scan* reported, so ingest cost tracks the scan's size, not the project's
  history. Dedup still has to revisit the groups a scan *disturbed* indirectly:
  the ones a finding moved out of (its CVE set changed) and the ones whose member
  was just auto-closed. That is why `CloseMissing` returns the ids it closed.
  `TestDeduplicateScanMatchesFullRun` asserts the scoped run produces the same result as
  a full recompute. The full `Deduplicate`/`ApplyToProject` are the
  *backfill* path (a rule changed, so any group in the project may need re-electing).
- Auto-close is scoped to the scan's target. `CloseMissing` only closes a
  finding whose `last_scan_id` scan had the same `asset_id` and `branch` as the
  closing scan (no last scan ⇒ the project-level target: no asset, no branch). A
  project-wide close would let a feature-branch or second-image scan remediate
  findings it never looked at. `TestCloseMissingScopedToScanTarget` pins this.
- Skip-unchanged compares against the *latest* completed scan of the target
  only (`scan.LatestCompletedTarget`: project version + scanner + asset, same
  scoping `CloseMissing` uses), never any earlier one. An A, B, A sequence of
  uploads must reprocess the third: it differs from B, the scan it is actually
  being compared against, even though it repeats A. The content hash is over
  the *parsed* findings (`scan.contentHash`), not the raw bytes, so a
  scanner-embedded timestamp never present in `ParsedFinding` (Trivy's
  top-level `CreatedAt`) does not defeat it, while a parser upgrade that
  extracts a new field does. A skipped scan still has to carry its target's
  live findings forward (`finding.CarryForward`: `last_scan_id`/`last_seen_at`
  only, `first_scan_id` untouched) so a later, different scan's `CloseMissing`
  still finds the right `asset_id` through the chain, and the skipped scan
  itself never looks like it introduced anything new. A matching hash is not
  enough: skip only if nothing a re-ingest acts on changed since the previous
  scan finished (`finding.ChangedSince`: `findings.state_changed_at`, stamped by
  the `findings_state` trigger on status, severity, title, description, the
  manual flags and archiving, plus the asset's `exposure_updated_at`), and only
  if every finding is still there to carry (`CarryForward` moves them in one
  transaction and refuses on a count mismatch). A reset field, a manual close or
  a cleared exposure must get the full pipeline. A new column that ingest
  rewrites belongs in that trigger.
- Dedup writes only what changes. Its statements are guarded with
  `IS DISTINCT FROM`. Do not rewrite a row to store the value it already has, or
  each scan churns the project's findings (dead tuples, WAL, vacuum).
  `TestDeduplicateDoesNotRewriteUnchangedRows` pins this via `ctid`. It also takes
  a per-project `pg_advisory_xact_lock` so concurrent workers can't elect primaries
  from stale snapshots.
- Severity feeds dedup. Anything that changes a finding's severity in bulk
  (triage backfill, enrichment) must regroup afterwards, because severity decides which
  tool's report of a CVE is the primary. `triage.ApplyToProject` does this.
- SLA windows come from one SQL function: `sla_days_for` → `sla_scaled_days`
  (criticality scaling, migration 000035). Do not compute a window in Go or JS.
  Read `sla_days`, or call the function (the `/sla/settings` matrix does). Anything
  that changes an input (policy, `sla_settings`, `projects.business_criticality`)
  must re-apply windows: `sla.reapply` / the `projects_sla_criticality` trigger.
  `sla_settings` is a singleton *row*, so `pgtest.Truncate` resets it rather than
  truncating it.
- `-p 1` for integration tests. They share one DB and truncate; parallel
  packages deadlock on `TRUNCATE`.
- Live-testing the binary: use fresh ports each run and stop by PID.
  Avoid `pkill`; it has disrupted the tool harness here.
- Module path is `github.com/xilasec/xila-api` (renamed from
  `xila-security`). Watch for stale imports after generated/edited files.
- jsonb via CopyFrom (sbom components) works by passing Go maps directly.
- Postgres 18: the compose volume is mounted at `/var/lib/postgresql` (18+
  stores data in a versioned subdir). Don't revert it to `/data`.
- Background crons default on (`ENRICH_ENABLED`, `VULNMATCH_ENABLED`) with long
  intervals. This is harmless in dev; they no-op without data/channels.
- Leader election (`internal/leader`): a session-level advisory lock on a
  hijacked connection. A new leader waits 2×`Check` before starting jobs so a
  dead predecessor has stopped (`TestOneLeaderAndFailover` panics on any overlap).
  Advisory locks are per-database, so installs sharing a server don't contend.
- Releases: `.github/workflows/release.yml` runs on `v*` tags, calls `ci.yml`
  (`workflow_call`) first, then builds the multi-arch image (the Dockerfile
  cross-compiles from `$BUILDPLATFORM`; keep it that way, no QEMU), binaries
  (`-X main.version`), the chart (versioned from the tag) and an SBOM.
- Actions: `uses:` lines are SHA pins only, never tags (`git ls-remote`; peel
  annotated tags with `^{}`; keep the `# vX.Y.Z` comment). Workflows are also
  recorded in `.github/workflows/actions.lock`: after adding or changing a
  `uses:`, run `gh actions-lock --no-narrow` (without `--no-narrow` it rewrites
  SHA pins to tags), and CI's `actions-lock` job runs `--verify`. Dependabot
  (`.github/dependabot.yml`, 3-day cooldown) updates pins and the lockfile
  together, and its PRs auto-merge after the required checks pass.
- svelte-check is at zero: CI runs `pnpm check` (in `web/`), which fails if
  the error count exceeds `web/.svelte-check-baseline` (now `0`). Type new UI
  code with JSDoc (`$state(/** @type {any[]} */ ([]))`, typed `$props()`,
  `errorMessage(err)`, `instanceof ApiError`). Route params are
  `string | undefined`, so narrow them (`page.params.id ?? ''`). Do not add
  `@ts-ignore` or raise the baseline.
- SvelteKit 3: import UI modules as `#lib/…` with the file extension (package.json
  `imports`), read `page` from `$app/state` (no `$` prefix), keep config in the
  `sveltekit()` options in `web/vite.config.js`, and change the URL without
  navigating via `goto(url, { shallow: true, replace: true })`. Don't run `sv
  migrate` codemods over the tree: their printer reformats whole files and moves
  JSDoc casts.
- Helm chart (`deploy/helm/xila`): new env settings need no chart change
  (users pass them via `config` / `secrets.extra`). Update the chart when a
  setting is a *secret* that should be generated, or the app needs a new port,
  volume or probe. `helm lint --strict` and the render-failure check run in CI.

## Map

```
cmd/api/main.go            wiring + crons (leader-elected) + graceful shutdown
deploy/helm/xila           Helm chart (bundled or external Postgres; see its README)
cmd/xila                   stdlib CI client (upload + gate); repo is also a GitHub Action (action.yml)
internal/{team,project,asset}          ownership hierarchy (CRUD)
internal/{scan,scanner}                ingestion + parser registry (60+ native parsers + SARIF; see docs/PARSERS.md)
                                       scan/queue.go = durable SKIP-LOCKED job queue for async ingest (INGEST_ASYNC);
                                       queued payloads optionally live in internal/objectstore (INGEST_PAYLOAD_STORE=s3)
internal/finding                       dedup store, triage, exceptions, enrichment fields, priority
internal/triage                        auto-triage rules (conditions→action) applied on ingest + backlog
internal/{sbom,correlation,license}    SBOM history/search (+ CycloneDX services), finding↔component link, SPDX license data
internal/vulnmatch                     advisory matcher (OSV online/local mirror, GitHub, private advisories): stored
                                       SBOM inventory → findings (scanner "osv"), new CVEs appear, upgraded deps auto-close
internal/pkgmeta                       registry metadata (npm/PyPI/Maven/Go/Cargo/NuGet/Gems/Composer) → outdated
internal/policy                        component policy engine (security / license / operational) → "policy" findings
internal/{compliance,portfolio}        framework posture, cross-project rollup
internal/metrics                       daily metric snapshots (90-day backfill) + trends API
internal/{export,report}               CSV/XLSX export of any list filter; printable HTML project/portfolio reports
internal/connector                     pull findings from Dependency-Track, DefectDojo, Snyk, GitHub, GitLab, Wiz, Tenable (+ RemoteTriage applier)
internal/issuetracker                  Jira / GitHub / GitLab issues, two-way sync
internal/objectstore                   S3-compatible object storage client for queued ingest payloads (M11 11.8)
internal/secretbox                     AES-GCM for integration tokens at rest
internal/engagement                    DefectDojo-style engagements (scans as tests) + manual findings
internal/findingtemplate               reusable write-ups for manual findings
internal/fixplan                       fix-first plan: upgrades ranked by risk removed
internal/rootcause                     cross-project root causes: fixplan.Changes merged by (kind, key) over every visible project
internal/exploitintel                  ExploitDB / Metasploit / Nuclei → finding exploit_maturity → priority
internal/badge                         token-gated public README badges (SVG)
internal/cra                           EU CRA evidence report (framework eu-cra)
ci/                                    GitHub Action + GitLab template that run scanners and upload
internal/gate                          CI security gates: policy → pass/fail on the deduped/triaged backlog
                                       (new-only mode = findings where first_scan_id = last_scan_id)
internal/sla                           remediation SLA policies (global/org/project) + breach/due-soon sweep;
                                       per-finding deadlines are kept by the findings_sla DB trigger
internal/{enrichment,notify}           EPSS/KEV priority; webhook/Slack alerts + delivery log
internal/{auth,apitoken,user}          JWT + API-token auth, user identities (SSO linking)
internal/{sso,oidc,saml}               SSO: OIDC + SAML protocols over a shared link + group→role sync layer
internal/{config,database,observability,httpx,domain,pgtest}   plumbing
web/                                   SvelteKit UI (embedded)
docs/ROADMAP.md                        what to build next
```

When adding a feature, follow the nearest existing domain package end-to-end
(migration → repo → service → handler → wiring → unit + integration + smoke
tests → UI). Keep `gofmt`/`vet` clean, and update `README.md` if endpoints or
behavior change.

