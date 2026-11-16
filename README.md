# xila-api

API for the Xila security platform: a central store for security information,
vulnerabilities and scanner output.

New here? [`docs/QUICKSTART.md`](docs/QUICKSTART.md) gets you from
`docker compose up` to your first finding in 5 minutes.

This repository is a production-shaped boilerplate: a Go HTTP API with user
registration/login, PostgreSQL persistence, and OpenTelemetry observability
(traces, metrics and logs) wired in from the start.

## Stack

| Concern         | Choice                                                      |
| --------------- | ---------------------------------------------------------- |
| HTTP framework  | [Fiber](https://gofiber.io) (fasthttp), fast and lightweight |
| Database        | PostgreSQL 15+ via `pgx/v5` connection pool (compose ships 18) |
| Migrations      | `golang-migrate`, embedded in the binary                   |
| Auth            | bcrypt password hashing + JWT (HS256) access tokens        |
| Observability   | OpenTelemetry traces, metrics & logs over OTLP/gRPC        |
| Logging         | `slog`, bridged to OTLP and mirrored to stdout as JSON     |
| Container       | Multi-stage build on a distroless static image            |

## Project layout

```
cmd/api/                 entrypoint (wiring + graceful shutdown)
internal/config/         env-based configuration
internal/observability/  OpenTelemetry setup + slog fan-out handler
internal/database/       pgx pool + embedded migrations
internal/user/           user entity + repository
internal/auth/           register/login service, JWT, HTTP handlers
internal/domain/         shared enums (severity, category, status, criticality)
internal/team/           teams CRUD
internal/project/        projects CRUD + risk summary
internal/scanner/        scanner parsers (Parser interface + Trivy) + registry
internal/scan/           scan records + ingestion (parse -> dedup -> finalize)
internal/finding/        deduplicated findings store + triage
internal/asset/          assets (repo/image/cloud/host) findings attach to
internal/sbom/           SBOM snapshots + CycloneDX/SPDX parsers + component search
internal/compliance/     frameworks/controls + finding-derived posture scoring
internal/portfolio/      cross-project rollup (risk, categories, compliance avg)
internal/export/         CSV + dependency-free XLSX writers for list exports
internal/report/         printable HTML project / portfolio reports
internal/metrics/        daily metric snapshots (project/team/org/portfolio) + trends
internal/notify/         outbound notifications (webhook, Slack, Teams, Mattermost, email)
internal/correlation/    links findings to the SBOM components that introduced them
internal/license/        SPDX license list + ScanCode categories, expression resolution, license groups
internal/policy/         component policies (security / license / operational) -> violation findings
internal/enrichment/     EPSS/KEV enrichment + priority scoring; NVD CVSS vectors
internal/vulnmatch/      advisory matching (OSV, GitHub, local OSV mirror, private advisories); keeps stored SBOMs current
internal/apitoken/       API tokens for CI/service access
internal/serviceaccount/ service accounts (non-human users with roles and expiring keys)
internal/federation/     workload identity federation: trusted OIDC issuers, claim bindings, RFC 8693 token exchange
internal/sso/            SSO providers (env + admin-managed registry), identity linking + IdP group → role sync, shared by OIDC and SAML
internal/oidc/           OpenID Connect login (PKCE, ID-token verification)
internal/saml/           SAML 2.0 service provider (crewjam/saml; replay + request tracking)
internal/server/         Fiber app, middleware, routes
```

## Run the full stack

Brings up the API with every feature on, plus PostgreSQL, an OpenTelemetry
Collector, Jaeger and Mailpit:

```bash
make up          # docker compose up --build -d
make logs        # tail the API logs
```

- App (UI + API): http://localhost:8080. The first account you register is the owner.
- Mailpit: http://localhost:8025 catches every email (password resets, email
  alerts, summaries).
- Jaeger: http://localhost:16686 (search for service `xila-api`).
- Prometheus metrics: http://localhost:9090/metrics.

Two-factor, MCP, PSIRT publishing with the public CSAF directory, CRA reporting
and SSO providers work out of the box with fixed development secrets. Features
that need your own credentials turn on when you set them in your shell or a `.env`
next to the compose file: AI triage (`AI_TRIAGE_ENABLED=true` with `AI_API_KEY`,
`AI_MODEL`, `AI_BASE_URL`), NVD (`NVD_ENABLED=true`, `NVD_API_KEY`), VulnCheck
(`VULNCHECK_API_TOKEN`) and GitHub advisories (`VULNMATCH_GITHUB_TOKEN`).

The SvelteKit + daisyUI UI in [`web/`](web/README.md) is compiled and embedded
into the Go binary (`make bundle`, or the Docker build), so `make up` serves
everything on a single port. For frontend development, run the UI separately with
hot reload: `cd web && pnpm install && pnpm dev` (http://localhost:5173).

The collector prints metrics and logs (`docker compose logs otel-collector`).

Tear down (Postgres data is kept in a named volume and survives restarts):

```bash
make down     # stop everything, keep the database
make purge    # stop everything AND delete all data (drops the pgdata volume)
```

## API documentation

An OpenAPI 3.1 spec is embedded in the binary and served by every instance:

| | |
| --- | --- |
| `GET /api/v1/openapi.json` | For Postman, Insomnia, Bruno, code generators |
| `GET /api/v1/openapi.yaml` | Same document, YAML |
| `/docs` (in the UI) | A browsable reference, rendered from the spec |

These endpoints are public. An API description is not a secret, and requiring a token to
read one defeats the purpose of publishing it. Because the spec ships with the
binary, the docs describe the version you are running, they work
air-gapped, and there is no hosted copy to fall out of date.

`internal/server/openapi_drift_test.go` keeps the docs in sync. It walks Fiber's real
route table and fails the build in both directions: a live endpoint that isn't
documented, or a documented path that no longer exists. Undocumented live
endpoints are worse than no docs, because the documentation is then wrong, so
this is checked automatically.

Every operation has a stable `operationId`, and the core schemas include examples
taken from real responses. A test fails when an example field isn't a documented
property, so response fields can't go undocumented unnoticed.

Generated clients in [`clients/`](clients/README.md): a Go module
(`github.com/xilasec/xila-api/clients/go`, oapi-codegen) and a TypeScript package
(`@xilasec/client`, typed `fetch` from openapi-typescript), both generated from the
spec by `make clients`. CI regenerates them and fails if the committed copies are
out of date, so each client matches the API it ships with.

## Endpoints

All routes except `/health`/`/ready` and `/api/v1/auth/*` require a `Bearer`
token: either a JWT (from login, for humans) or an API token (for CI, prefix
`xila_`). An API token can be scoped to a single project, in which case it may
only act on that project (useful for a repo's CI). CI can also go keyless: it
exchanges its platform's OIDC identity token for a short-lived service-account
session (see [Service accounts and workload identity federation](#service-accounts-and-workload-identity-federation)). Only a hash of each token
is stored; the secret is shown once at creation. List endpoints accept `?limit=`
(default 50, max 200) and `?offset=`, and return a `pagination` object (`limit`,
`offset`, `count`, `has_more`) alongside the results.

Access control (RBAC). The tenancy hierarchy is Organization → Team → Project,
and access can be granted at any level:

- Instance owner: the first registered user. Always an admin, and nobody can
  demote or remove them, including themselves. Ownership moves only when the owner
  hands it over (`POST /users/{id}/transfer-ownership`). Without this, any admin
  could demote any other admin, including whoever set the instance up, so one
  careless or compromised admin account could lock everyone else out. Exactly one
  owner exists, enforced by a database constraint rather than by application checks.
- Instance admin: bypasses all authorization. Admin status is read from the
  database on every request, not from the token, so a demotion takes effect
  immediately rather than when the user's JWT expires.
- Org roles: `admin` manages the organization and (implicitly) every team in it;
  `member` is a plain member. Creating an org makes you its admin.
- Team roles: `owner` > `editor` > `uploader` > `viewer`. An org admin is treated
  as `owner` of every team in the org.
- Project roles: the same four roles, granted on one project without joining its
  team (`POST /projects/{id}/members`). This covers cases like giving Dana read
  access to one project, which team membership cannot express, because joining a
  team grants access to every project in it. Granting access requires `owner` on
  the project.
- Uploader role: `viewer` plus uploads, for CI tokens. It reads everything a
  viewer does (the project, its findings, scans, SBOMs, VEX) and, on top of
  that, may upload scans, SBOMs and VEX and run the gate: the minimum a CI
  build needs to report its result. It still can't triage, comment, change
  settings or manage members; those need `editor`. Because roles only add
  access, combining it with a higher role behaves as that role: `uploader` +
  `viewer` is still `uploader` (keeps the upload grant), `uploader` + `editor`
  is `editor` (which already includes upload). Recommended for CI service
  accounts and project-scoped tokens that only push reports (see "Break the
  build in CI").
- Project hierarchy: a project may have a parent project in the same organization
  (`parent_id`, at most 5 levels, no cycles; enforced in the database). A project
  or team grant on a parent applies to every descendant with the same role (the
  permission audit lists it as `parent_project`, naming the ancestor). Setting or
  changing a parent requires `owner` on the project and on the new parent; moving
  a project out of a tree removes the inherited access. A parent can be a
  collection (`is_collection`): it holds no scans or SBOMs of its own (uploads to
  it return `409`) and exists to roll up its children.

A user's effective role on a project is the highest of: their direct project
grant, their role on the owning team, `owner` if they administer the owning org,
and any project or team grant on one of its ancestor projects. The highest role
wins, not the most specific one. Roles only add access; they do not subtract it.
A team editor cannot be restricted to `viewer` on one project, because a model
where a grant in one place cancels a grant in another is hard to reason about,
and its mistakes are silent.

Reading a resource requires `viewer`, mutating it requires `editor`, and managing
members requires `owner`.

Portfolio-wide lists (`/orgs`, `/teams`, `/projects`, `/findings`, `/components`,
`/portfolio`, `/assets`) are filtered to what you can see. User management
(`/users`), SSO settings and group mappings (`/sso`), notification-channel
management, and enrichment are admin-only.
Instance admins bypass all checks.

Single Sign-On (optional). OpenID Connect and SAML 2.0 are supported, with any
number of providers side by side. Providers can be added, tested, and disabled in
the UI at runtime, or configured by environment. IdP groups can be mapped to
roles, and password login can optionally be turned off. See [Single sign-on](#single-sign-on-oidc--saml) below.

| Method | Path                                | Description                          |
| ------ | ----------------------------------- | ------------------------------------ |
| GET    | `/health`                           | Liveness check                       |
| GET    | `/ready`                            | Readiness check (pings the database) |
| GET    | `/api/v1/me`                        | The current user (id, email, is_admin) |
| POST   | `/api/v1/me/password`               | Change your password (current one required; SSO-only accounts may add one); signs out every other session, returns a fresh token |
| POST   | `/api/v1/me/logout`                 | Sign out; `redirect` is the IdP's Single Logout URL after a SAML sign-in (empty otherwise) |
| POST   | `/api/v1/me/sessions/revoke`        | Sign out everywhere else (every earlier JWT stops working); returns a fresh token |
| GET    | `/api/v1/me/mfa`                    | Two-factor status, recovery codes left, and whether it can be turned on (`available`: needs `INTEGRATION_SECRET_KEY`) |
| POST   | `/api/v1/me/mfa/setup` / `enable` / `disable` | Enroll a TOTP authenticator (QR + key), confirm with a code (→ recovery codes), or turn it off with a code |
| POST   | `/api/v1/auth/mfa`                  | Second sign-in step: the `mfa_token` from login + a TOTP or recovery code |
| DELETE | `/api/v1/users/{id}/mfa`            | Reset a user's two-factor (lost device; signs them out) (admin) |
| GET    | `/api/v1/auth/config`               | Public: `{password_login_enabled, providers: [{kind, name, login_url}]}`, the enabled, working providers by sort order |
| GET    | `/api/v1/auth/oidc/login`, `/oidc/callback` | OIDC login, environment provider (404 unless `OIDC_ENABLED`) |
| GET    | `/api/v1/auth/oidc/{slug}/login`, `/oidc/{slug}/callback` | OIDC login, admin-managed provider (404 if unknown/disabled) |
| GET    | `/api/v1/auth/saml/metadata`, `/saml/{slug}/metadata` | SAML SP metadata XML (environment / admin-managed provider) |
| GET    | `/api/v1/auth/saml/login`, `/saml/{slug}/login` | Start a SAML login (SP-initiated) |
| POST   | `/api/v1/auth/saml/acs`, `/saml/{slug}/acs` | SAML assertion consumer service (HTTP-POST) |
| GET/POST | `/api/v1/auth/saml/slo`, `/saml/{slug}/slo` | SAML Single Logout (IdP-initiated requests, and responses to ours) |
| GET/POST | `/api/v1/sso/providers`           | List providers (environment + database, with status and what to enter at the IdP) / add one (admin) |
| GET/PUT/DELETE | `/api/v1/sso/providers/{id}` | One provider; environment ones (`oidc`/`saml`) are read-only (admin) |
| POST   | `/api/v1/sso/providers/test`, `/sso/providers/{id}/test` | Dry-run a draft / a saved provider: discovery or metadata fetch, endpoints, certificate expiry (admin) |
| GET/POST | `/api/v1/sso/group-mappings`      | List / add IdP group → role mappings (admin) |
| DELETE | `/api/v1/sso/group-mappings/{id}`   | Remove a group mapping (admin)       |
| GET    | `/api/v1/users`                     | List users (admin)                   |
| POST   | `/api/v1/users`                     | Pre-provision a passwordless (SSO) user (admin) |
| PATCH  | `/api/v1/users/{id}`                | Promote/demote admin (admin)         |
| POST   | `/api/v1/users/{id}/deactivate` / `reactivate` | Block / restore an account: password, SSO and its API tokens; deactivation ends every session (admin; not the owner, not yourself) |
| DELETE | `/api/v1/users/{id}`                | Delete an account permanently (admin; not the owner, not yourself) |
| POST   | `/api/v1/users/{id}/password-reset-link` | Single-use reset link, valid 24 h, to hand over out of band (admin) |
| POST   | `/api/v1/orgs`                      | Create an org (you become its admin) |
| GET    | `/api/v1/orgs`                      | List your organizations              |
| GET/POST/DELETE | `/api/v1/orgs/{id}/members` | List / add (by email) / remove org members (org admin) |
| POST   | `/api/v1/orgs/{id}/teams`           | Create a team in an org (org admin)  |
| GET    | `/api/v1/portfolio`                 | Portfolio rollup (scoped to your teams) |
| GET    | `/api/v1/portfolio/report`          | Printable executive HTML report over the projects you can see |
| GET    | `/api/v1/metrics/trends?days=90`    | Daily trend: open by severity, new, closed, risk, SLA, MTTR (scoped to what you can see; max 365 days) |
| GET    | `/api/v1/{projects,teams,orgs}/{id}/metrics/trends` | The same trend for one project / team / org |
| POST   | `/api/v1/metrics/snapshot`          | Take the daily metric snapshots now (admin; also runs on `METRICS_SNAPSHOT_INTERVAL`) |
| POST   | `/api/v1/auth/register`             | Create a user (first = owner + admin; closed once a user exists when `PASSWORD_LOGIN_ENABLED=false`) |
| POST   | `/api/v1/auth/login`                | Authenticate, get JWT (owner only when `PASSWORD_LOGIN_ENABLED=false`) |
| POST   | `/api/v1/auth/password-reset/request` | Email a reset link (needs `SMTP_*` + `PUBLIC_URL`); always returns `202` |
| POST   | `/api/v1/auth/password-reset/confirm` | Set a new password with the link's token; signs out every other session and signs you in |
| GET/POST/DELETE | `/api/v1/teams/{id}/members` | List / add (by email) / remove team members (owner) |
| POST   | `/api/v1/tokens`                    | Mint an API token (CI); secret shown once. Needs a session that signed in within `REAUTH_WINDOW` (else `403` + `X-Reauth-Required: true`); API tokens can't mint tokens |
| POST   | `/api/v1/me/reauth`                 | Confirm your password (`{password, code}`; the TOTP code when two-factor is on) for a session marked freshly authenticated |
| GET    | `/api/v1/tokens`                    | List your API tokens (no secrets)    |
| DELETE | `/api/v1/tokens/{id}`               | Revoke an API token                  |
| POST   | `/api/v1/auth/token`                | Public, rate limited: RFC 8693 token exchange (a CI job's OIDC identity token → a short-lived service-account access token) |
| GET/POST | `/api/v1/service-accounts`        | List / create service accounts (admin) |
| GET/PATCH/DELETE | `/api/v1/service-accounts/{id}` | Read / edit the description / delete a service account (admin) |
| POST   | `/api/v1/service-accounts/{id}/suspend` / `resume` | Suspend (ends its sessions, revokes its keys, refuses the exchange) / resume (admin) |
| GET/POST/DELETE | `/api/v1/service-accounts/{id}/keys[/{keyID}]` | List / issue (expiring, secret shown once) / revoke its API keys (admin) |
| GET/POST/GET/PUT/DELETE | `/api/v1/federation/issuers[/{id}]` | Trusted OIDC issuers for the token exchange; `POST …/{id}/test` runs discovery (admin) |
| GET/POST/GET/PUT/DELETE | `/api/v1/federation/bindings[/{id}]` | Claim conditions → service account (and project) (admin) |
| GET    | `/api/v1/teams`                     | List your teams                      |
| GET/PATCH/DELETE | `/api/v1/teams/{id}`      | Read / update / delete a team        |
| POST   | `/api/v1/teams/{id}/projects`       | Create a project under a team        |
| GET    | `/api/v1/projects?team_id=`         | List projects (optionally by team)   |
| GET/PATCH/DELETE | `/api/v1/projects/{id}`   | Read / update / archive a project (DELETE archives, owner; `?purge=true` deletes permanently, admin) |
| DELETE | `/api/v1/scans/{id}` · `/engagements/{id}` · `/findings/{id}` | Archive (editor; `?purge=true` deletes permanently, admin) |
| POST   | `/api/v1/{projects,scans,engagements,findings}/{id}/restore` | Restore an archived record within `ARCHIVE_RETENTION` (owner) |
| GET    | `/api/v1/projects/{id}/summary`     | Risk score + severity/status rollup  |
| GET    | `/api/v1/projects/{id}/children`    | A project's direct child projects    |
| POST   | `/api/v1/projects/{id}/scans`       | Ingest raw scanner output (`?branch=` or `?release=`; default: the project's default version) |
| GET    | `/api/v1/projects/{id}/scans`       | List scans for a project             |
| GET    | `/api/v1/scans/{id}`                | Read a scan                          |
| GET    | `/api/v1/projects/{id}/versions`    | The project's branches / releases (default first) |
| PATCH/DELETE | `/api/v1/projects/{id}/versions/{versionID}` | Make a version the default / delete a non-default one with its findings (owner) |
| GET    | `/api/v1/findings`                  | Cross-project triage inbox (`?status/severity/category/scanner/kev/project_id/sla/assignee`, `?q=` full-text search, `?tag=a,b`, `?all_versions=true`, `?sort=priority\|sla_due`, paginated) |
| GET    | `/api/v1/findings/tags`             | Tags in use on the findings you can see, with open-finding counts |
| GET    | `/api/v1/projects/{id}/findings`    | List findings (`?status/severity/category/sla/assignee`, `?branch=`/`?version_id=`/`?all_versions=true`) |
| GET    | `/api/v1/findings/{id}`             | Read a finding                       |
| PATCH  | `/api/v1/findings/{id}`             | Triage a finding (status + exception `reason`/`expires_at`); `202` + a pending assessment with `ASSESSMENT_REQUIRES_APPROVAL` |
| POST   | `/api/v1/findings/bulk`             | Change status / severity / assignee / tags (`add_tags`, `remove_tags`) of up to 5000 findings by `ids` or `filter` (each authorized on its project); status / severity become `pending` assessments with `ASSESSMENT_REQUIRES_APPROVAL` |
| PUT    | `/api/v1/findings/{id}/assignee`    | Assign (or `null` to unassign); the assignee must see the project |
| PUT    | `/api/v1/findings/{id}/tags`        | Replace a finding's tags (normalized, ≤ 20; recorded in history) |
| PATCH  | `/api/v1/findings/{id}/fields`      | Override title / severity (sticky across scans until reset), set the planned remediation date; `If-Match` → `412` on a stale edit |
| PATCH  | `/api/v1/findings/{id}/custom`      | Set custom-field values (`{"key": value}`, `null` clears; validated; recorded in history) (editor) |
| PATCH  | `/api/v1/projects/{id}/custom`      | Set a project's custom-field values (editor) |
| PATCH  | `/api/v1/assets/{id}/custom`        | Set an asset's custom-field values (editor) |
| GET    | `/api/v1/custom-fields`             | Custom-field definitions (`?entity=`, `?project_id=` → the ones that apply to its organization) |
| POST/PATCH/DELETE | `/api/v1/custom-fields[/{id}]` | Define / edit / delete a custom field (instance admin); deleting removes its values |
| GET    | `/api/v1/projects/{id}/assignees`   | Who findings in a project can be assigned to |
| GET    | `/api/v1/findings/{id}/history`     | Every status / severity / assignee change (who, why), comment, attachment and assessment |
| GET    | `/api/v1/findings/{id}/assessments` | The finding's manual assessments (pending / approved / rejected) |
| GET    | `/api/v1/findings/{id}/ai-proposals` | The finding's AI triage proposals + provider / model / project opt-out (`AI_TRIAGE_ENABLED`; off = `404`). See *AI-assisted triage* |
| GET    | `/api/v1/findings/{id}/ai-proposals/prompt?kind=` | What asking would send (nothing is sent) |
| POST   | `/api/v1/findings/{id}/ai-proposals` | Ask the model (`{kind: false_positive\|exploitability\|fix}`; editor; rate-limited per project → `429`; opted-out project → `403`); records a proposal, changes nothing |
| POST   | `/api/v1/findings/{id}/ai-proposals/{pid}/accept` | Apply it as you (`{note}`; editor): `200` applied, `202` when it became a pending assessment / risk acceptance request |
| POST   | `/api/v1/findings/{id}/ai-proposals/{pid}/reject` | Reject it (`{note}`; editor) |
| GET    | `/api/v1/assessments`               | Assessment review queue across visible projects (`?state=pending`, `?project_id=`, `?actionable=true` = only what you may decide) |
| GET    | `/api/v1/ai-proposals`              | Open AI proposals across visible projects (`?mine=true` = asked by you or on findings assigned to you) |
| POST   | `/api/v1/assessments/{id}/approve`  | Approve + apply a pending assessment (`{note}`; project owner or admin, not the requester) |
| POST   | `/api/v1/assessments/{id}/reject`   | Reject a pending assessment (`{note}`; same authorization) |
| GET/POST | `/api/v1/findings/{id}/comments`  | The finding's discussion / add a comment (editor) |
| DELETE | `/api/v1/findings/{id}/comments/{commentID}` | Delete a comment (its author or a project owner) |
| GET/POST | `/api/v1/findings/{id}/attachments` | Evidence files / upload one (multipart `file`, ≤10 MiB, editor) |
| GET/DELETE | `/api/v1/findings/{id}/attachments/{attachmentID}` | Download (always as a file) / delete (uploader or project owner) |
| GET    | `/api/v1/findings/{id}/exceptions`  | False positive / won't fix exception audit history |
| GET    | `/api/v1/findings/{id}/risk-acceptances` | The finding's risk-acceptance ledger (every acceptance it was in; when and why it joined / left) |
| GET    | `/api/v1/risk-acceptances`          | Risk acceptances across visible projects (`?state=requested` = the approval queue; `?actionable=true` = requests you may approve; `?owner=me&expires_within_days=30` = yours that need renewing) |
| GET/POST | `/api/v1/projects/{id}/risk-acceptances` | List / request risk acceptances (`title`, `justification`, `owner_id`, `expires_at`, `finding_ids`) |
| GET/PATCH/DELETE | `/api/v1/projects/{id}/risk-acceptances/{aid}` | One acceptance + its ledger; edit or withdraw while requested |
| POST   | `/api/v1/projects/{id}/risk-acceptances/{aid}/{approve,reject,revoke}` | Decide (project owner; four-eyes with `RISK_ACCEPTANCE_REQUIRES_APPROVAL`) |
| POST/DELETE | `/api/v1/projects/{id}/risk-acceptances/{aid}/findings[/{fid}]` | Add findings / remove one (`?reason=`) |
| GET    | `/api/v1/findings/{id}/duplicates`  | Other scanners' reports collapsed under this one |
| POST   | `/api/v1/findings/expire-exceptions`| Reopen false positive / won't fix findings whose exception lapsed (also runs in the background) |
| GET    | `/api/v1/findings/expiring`         | Risk acceptances lapsing soon (`?days=30`) |
| GET    | `/api/v1/findings/export`           | The inbox's filter as CSV / Excel (`?format=csv\|xlsx` + every `/findings` filter; ≤100k rows, `X-Truncated`) |
| GET    | `/api/v1/projects/{id}/findings/export` | A project's findings as CSV / Excel (same filters as the list) |
| GET    | `/api/v1/projects/{id}/report`      | Printable HTML security report (print → PDF in the browser) |
| GET/POST/PATCH/DELETE | `/api/v1/triage-rules`    | Auto-triage rule policy (admin) |
| POST   | `/api/v1/triage-rules/apply`        | Apply rules to the backlog (`?project_id=` or all) (admin) |
| POST   | `/api/v1/triage-rules/preview`      | Dry-run a draft rule: findings it would change (`?project_id=`) (admin) |
| POST   | `/api/v1/triage-rules/{id}/preview` | Dry-run a stored rule (admin) |
| POST   | `/api/v1/triage-rules/{id}/approve` | Approve a pending rule, not by its author/last editor (admin) |
| POST   | `/api/v1/triage-rules/{id}/reject`  | Reject a pending rule (kept for audit) (admin) |
| GET/POST | `/api/v1/policies`                | Component policies (list: the ones covering your projects, with violation counts; create: admin) |
| GET/PUT/DELETE | `/api/v1/policies/{id}`     | Read / replace / delete a policy (mutations admin) |
| GET    | `/api/v1/policies/{id}/violations`  | A policy's open violation findings on your projects (`?project_id=`, `?all_versions=true`) |
| POST   | `/api/v1/policies/preview`          | Dry-run a draft policy: components it would flag (`?project_id=` or all visible) |
| POST   | `/api/v1/policies/evaluate`         | Re-evaluate policies now (`?project_id=` or all) (admin) |
| GET    | `/api/v1/projects/{id}/policies`    | Policies in force on a project, with its violation counts |
| POST   | `/api/v1/projects/{id}/gate`        | Evaluate the security gate → 200 pass / 422 fail (optional inline `policy`) |
| GET/PUT/DELETE | `/api/v1/projects/{id}/gate/policy` | Manage a project's gate policy |
| GET/PUT | `/api/v1/gate/policy`              | The global default gate policy (admin) |
| GET/PUT/DELETE | `/api/v1/projects/{id}/sla/policy` | The SLA policy in force for a project (+ its scope); set/remove needs project owner |
| GET/PUT/DELETE | `/api/v1/orgs/{id}/sla/policy` | An organization's SLA policy (set/remove: org admin) |
| GET/PUT/DELETE | `/api/v1/sla/policy`               | The instance-wide SLA policy (admin) |
| POST   | `/api/v1/sla/sweep`                 | Send breach / due-soon alerts now (admin; also runs on `SLA_SWEEP_INTERVAL`) |
| GET/PUT | `/api/v1/sla/settings`             | Scale every SLA by project business criticality (switch + factors) and the resulting matrix (admin) |
| GET/PUT/DELETE | `/api/v1/projects/{id}/issue-tracker` | The project's Jira / GitHub / GitLab tracker (token write-only); set/remove needs project owner |
| POST   | `/api/v1/projects/{id}/issue-tracker/test` | Verify the stored tracker credentials (owner) |
| GET/POST | `/api/v1/findings/{id}/issue`     | The finding's linked issue / create it now (editor; idempotent) |
| POST   | `/api/v1/issue-trackers/sync`       | Two-way issue sync + auto-create now (admin; also runs on `ISSUE_SYNC_INTERVAL`) |
| GET    | `/api/v1/projects/{id}/remediation` | The project's remediation actions (`?status=` comma list or `all`, default live; `?kind=`) |
| GET    | `/api/v1/projects/{id}/remediation/proposals` | Changes that would resolve findings not yet in an action |
| POST   | `/api/v1/projects/{id}/remediation` | Accept a proposal `{kind, key}` → action (editor) |
| GET    | `/api/v1/remediation`               | Remediation actions across the projects you can see |
| GET/PATCH | `/api/v1/remediation/{id}`       | One action / change its status, title or owner (editor) |
| GET    | `/api/v1/remediation/{id}/findings` | The findings an action closes |
| POST   | `/api/v1/remediation/{id}/issue`    | File the action as one tracker ticket (editor; idempotent) |
| POST   | `/api/v1/remediation/sweep`         | Group findings + refresh actions now (admin; also runs on `REMEDIATION_SWEEP_INTERVAL` and per ingest) |
| GET    | `/api/v1/root-causes`               | The same change merged across every project you can see (`?kind=`, `?ecosystem=`, `?q=`, `?kev=`, `?min_severity=`) |
| GET    | `/api/v1/root-causes/{kind}/{key}`  | One root cause's affected projects (`key` base64url-encoded; findings, priority, live action if any) |
| POST   | `/api/v1/root-causes/{kind}/{key}/remediation` | Create the missing remediation action everywhere you can edit; skips and reports the rest, idempotent |
| GET/POST | `/api/v1/projects/{id}/connectors` | The project's pull connectors (Dependency-Track, DefectDojo, Snyk, GitHub, GitLab, Wiz, Tenable; token write-only); adding needs project owner |
| PUT/DELETE | `/api/v1/projects/{id}/connectors/{connectorID}` | Change / remove a connector (owner; its imported findings stay) |
| POST   | `/api/v1/projects/{id}/connectors/{connectorID}/test` | Verify the stored connector credentials (owner; `502` with the remote's error) |
| POST   | `/api/v1/projects/{id}/connectors/{connectorID}/pull` | Pull now and report imported / new / closed counts (editor; also runs on `CONNECTOR_PULL_INTERVAL`) |
| GET/PUT | `/api/v1/me/notifications`        | Your own subscriptions: assigned-to-me / watched projects, by email or a personal Slack/Teams webhook (any signed-in person; `…/deliveries` = your delivery log) |
| GET/PUT/DELETE | `/api/v1/projects/{id}/watch` | Watch a project you can see (its events reach your subscriptions) |
| GET/POST/DELETE | `/api/v1/notifications/channels` | Manage notification channels (webhook/Slack/Teams/Mattermost/email) |
| POST   | `/api/v1/notifications/channels/{id}/test` | Send a test notification |
| GET    | `/api/v1/notifications/deliveries`  | Recent delivery outcomes (one per queued event × channel, plus Test sends) |
| GET    | `/api/v1/ingestion-health`          | Silent scanners, collapsed uploads, failed scans / pulls / ingest jobs (your projects; `/projects/{id}/ingestion-health` for one) |
| GET/POST | `/api/v1/retention` / `/retention/run` | Show / apply the data retention policy now (admin) |
| GET    | `/api/v1/audit-log`                 | The instance audit log, newest first (admin); filters `actor` (email substring), `actor_id`, `actor_kind`, `action` (or dotted prefix), `resource_type`, `resource_id`, `project_id`, `outcome`, `from`, `to`; paginated |
| GET    | `/api/v1/audit-log/export`          | The same filter as CSV / XLSX (`?format=`), formula-escaped (admin) |
| POST   | `/api/v1/mcp`                       | MCP server for AI agents (`MCP_ENABLED`; JSON-RPC 2.0: `initialize`, `tools/list`, `tools/call`). See *AI agents* |
| GET    | `/api/v1/permissions`               | Permission audit (admin): per principal (people and service accounts) and project, the effective role and every grant behind it (project grant, team role, org admin, instance admin), naming the SSO group mapping of synced grants; filters `user`, `user_id`, `project_id`, `team_id`, `org_id`, `role`, `source` (`manual`/`sso`), `principal_kind`; paginated |
| GET    | `/api/v1/permissions/export`        | The same as CSV / XLSX, one row per contributing grant (admin) |
| GET    | `/api/v1/projects/{id}/access`      | Who can reach this project and why: the permission audit for one project (project owner) |
| GET    | `/api/v1/notifications/pending`     | Queued deliveries not yet sent, with attempts, next retry and last error (admin) |
| GET    | `/api/v1/findings/{id}/components`  | SBOM component(s) that introduced the finding |
| POST   | `/api/v1/enrich`                    | Refresh EPSS + the KEV catalogs and recompute priorities now (admin; reports `kev_failed`) |
| GET    | `/api/v1/enrich/kev-catalogs`       | Each KEV catalog's sync state: entries, last sync, last error (admin) |
| POST   | `/api/v1/vulnmatch`                 | Re-match stored SBOMs against the advisory sources now (admin; reports `partial` / `failed_sources`) |
| GET    | `/api/v1/vulnmatch/sources`         | Configured advisory sources + local OSV mirror contents (admin) |
| POST   | `/api/v1/vulnmatch/osv-import`      | Import an OSV ecosystem export (`all.zip`, multipart `file`) into the local mirror (admin; idempotent) |
| POST   | `/api/v1/vulnmatch/osv-mirror/sync` | Download + import `VULNMATCH_OSV_ECOSYSTEMS` now (admin) |
| GET/POST | `/api/v1/advisories`              | List (`?q=`, `?withdrawn=true`) / publish private advisories (publish: admin) |
| POST   | `/api/v1/advisories/import`         | Import private advisories as OSV JSON (admin) |
| GET/PUT/DELETE | `/api/v1/advisories/{advisoryID}` | One private advisory; replace (set `withdrawn` to retract) / delete (admin) |
| GET    | `/api/v1/pkgmeta?purl=`             | Cached registry metadata for one package (every release, latest stable) + that version's freshness |
| POST   | `/api/v1/pkgmeta/refresh`           | Refresh package registry metadata now (admin; `?wait=true` to block) |
| POST   | `/api/v1/projects/{id}/vex`         | Upload a VEX document (OpenVEX / CycloneDX / CSAF 2.0 VEX, auto-detected) |
| GET    | `/api/v1/projects/{id}/vex`         | List a project's VEX statements      |
| GET    | `/api/v1/projects/{id}/vex/export`  | Export the project's analysis (`?format=openvex\|cyclonedx\|csaf`, `?branch=` / `?version_id=`) |
| DELETE | `/api/v1/vex/{id}`                  | Remove a VEX statement               |
| GET    | `/api/v1/ingest/queue`              | Ingest queue depth + oldest wait (admin) |
| GET/PUT | `/api/v1/ingest/settings`          | Live overrides of the queue limit and workers per worker node (admin; `null` = the env default); every node applies them within one sample interval |
| POST   | `/api/v1/projects/{id}/sboms`       | Upload a CycloneDX SBOM (snapshot)   |
| GET    | `/api/v1/projects/{id}/sboms`       | SBOM history for a project           |
| GET    | `/api/v1/projects/{id}/components`  | Project components (`?latest=true` for current inventory, `?vulnerable=true\|false`, `?license=<SPDX id>`, `?license_category=<ScanCode category>`, `?outdated=true\|false`, `?kind=ai\|model\|dataset\|ai-service\|software`) |
| GET    | `/api/v1/projects/{id}/components/export` | Project components as CSV / Excel (`?format=csv\|xlsx`, same filters) |
| GET    | `/api/v1/projects/{id}/services`    | Services declared by the current snapshots of the default version (`?branch=` / `?release=`), with warning flags |
| GET    | `/api/v1/sboms/{id}`                | Read an SBOM snapshot                |
| GET    | `/api/v1/sboms/{id}/components`     | Components in one snapshot, each with its vulnerability state and freshness (`?vulnerable=`, `?license=`, `?license_category=`, `?outdated=`, `?kind=`) |
| GET    | `/api/v1/sboms/{id}/freshness`      | How many of the snapshot's components are outdated / up to date / unknown |
| GET    | `/api/v1/sboms/{id}/components/export` | Those components as CSV / Excel (`?format=csv\|xlsx`) |
| GET    | `/api/v1/sboms/{id}/vulnerabilities`| Every vulnerability the snapshot ships, with the components it hits |
| GET    | `/api/v1/sboms/{id}/services`       | Services the snapshot declares (CycloneDX), with endpoints, auth, trust boundary/zone, data flows and warning flags |
| GET    | `/api/v1/sboms/{id}/export`         | The snapshot as a CycloneDX BOM (`?spec=1.6\|1.7`), with vulnerabilities + analysis (`?vulnerabilities=false` to omit) |
| GET    | `/api/v1/sboms/{id}/diff`           | What changed since `?base=` (default: the previous snapshot of the artifact): packages and services |
| GET    | `/api/v1/sboms/{id}/graph`          | The snapshot's dependency graph (component and service nodes with vulnerability state + edges) |
| GET    | `/api/v1/sboms/{id}/graph/paths`    | Every shortest route from the root to a package (`?ref=` or `?component_id=`) |
| GET    | `/api/v1/components`                | Global package search across projects (`?vulnerable=`, `?license=`, `?license_category=`, `?outdated=`, `?kind=`) |
| GET    | `/api/v1/components/export`         | That search as CSV / Excel (`?format=csv\|xlsx`, same filters) |
| GET    | `/api/v1/vulnerabilities/{id}/sboms`| Which releases ever shipped a CVE / advisory: introduced in, fixed in |
| GET    | `/api/v1/licenses`                  | The SPDX License List with ScanCode categories (`?q=`, `?category=`, `?osi=`, `?deprecated=`, paginated) |
| GET    | `/api/v1/licenses/{id}`             | One license or exception (any case; deprecated ids too), with the groups containing it |
| GET    | `/api/v1/license-groups`            | Custom license groups + the built-in `category:<Category>` groups |
| POST   | `/api/v1/license-groups`            | Create a license group (admin) |
| GET    | `/api/v1/license-groups/{id}`       | One group (a custom id, or `category:Copyleft`) |
| PUT    | `/api/v1/license-groups/{id}`       | Replace a group's name / description / members (admin) |
| DELETE | `/api/v1/license-groups/{id}`       | Delete a license group (admin) |
| POST   | `/api/v1/projects/{id}/assets`      | Register an asset (image/cloud/host) |
| GET    | `/api/v1/projects/{id}/assets`      | List a project's assets (`?type=`)   |
| GET    | `/api/v1/assets` · `/assets/{id}`   | Portfolio list / read an asset       |
| GET    | `/api/v1/assets/{id}/findings`      | Findings attributed to an asset      |
| PUT    | `/api/v1/assets/{id}/exposure`      | Set exposure by hand (`internet`/`internal`/`isolated`, `""` = unknown) |
| GET/POST | `/api/v1/assets/{id}/relations`   | List / add `built_from` · `deployed_as` · `depends_on` edges |
| DELETE | `/api/v1/assets/{id}/relations/{rid}` | Remove an edge                     |
| GET    | `/api/v1/assets/{id}/relations/suggestions` | Inferred `built_from` edges from SBOM OS packages |
| GET    | `/api/v1/assets/{id}/blast-radius`  | Assets built from / deployed as this one, with the findings they share |
| GET    | `/api/v1/frameworks`                | List compliance frameworks           |
| GET    | `/api/v1/projects/{id}/compliance`  | Compliance posture across frameworks |
| GET    | `/api/v1/projects/{id}/compliance/{framework}` | Posture for one framework |
| GET    | `/api/v1/projects/{id}/cra`         | CRA product declaration, manufacturer and Article 14 reporting cases |
| PUT    | `/api/v1/projects/{id}/cra`         | Declare the project a product on the EU market (`cra_in_scope`, name, version, Member States; owner) |
| POST   | `/api/v1/projects/{id}/cra/cases`   | Open a reporting case for a finding by hand (editor; in-scope projects) |
| GET    | `/api/v1/cra/cases`                 | Reporting cases across the projects you can see (`?state=active\|…`, `?project_id=`) |
| GET    | `/api/v1/cra/cases/{id}`            | A case with its history (who submitted what, when, and the payload) |
| PATCH  | `/api/v1/cra/cases/{id}`            | Edit the report content; `corrective_available_at` starts the final-report clock (editor) |
| GET    | `/api/v1/cra/cases/{id}/report?stage=early_warning\|notification\|final` | Draft ENISA payload for the stage (JSON) |
| POST   | `/api/v1/cra/cases/{id}/submit`     | Record a submission `{stage, reference, note}` (editor; stages in order) |
| POST   | `/api/v1/cra/cases/{id}/dismiss`    | Dismiss with a reason (owner) |
| POST   | `/api/v1/cra/cases/{id}/close`      | Close after the final report (editor) |
| POST   | `/api/v1/cra/sweep`                 | Open cases + send deadline alerts now (admin; also on `CRA_SWEEP_INTERVAL`) |

## Domain model

```
Team ──< Project ──< Version (branch / release; one is the default)
                 │      ├──< Scan    (ingestion events)
                 │      ├──< SBOM    (snapshots)
                 │      └──< Finding (persistent, deduplicated vulnerabilities)
                 └──< Asset   (repo, container image, cloud resource, host)
```

- Project: one per repository or application. Carries `business_criticality`,
  which is used to weight risk.
- Version: a branch or release of the project. Every scan, SBOM and finding
  belongs to one (see *Branches and releases* below).
- Asset: the concrete thing being secured (a repo, container image, cloud
  resource, host, etc.). Scans and findings can be *attributed to an asset*
  (`?asset_id=` on ingest), so a container CVE or cloud misconfiguration points
  at what it affects, not just the project. This generalizes "project = repo"
  and is the basis for container, cloud and CSPM coverage.
- Scan: a single tool run ("Trivy on commit abc123"). It is an *ingestion
  event*, not a navigation layer.
- Finding: a normalized vulnerability, unique per `(version, fingerprint)`.
  It persists across scans. Re-running a scanner refreshes `last_seen_at`
  instead of creating duplicates, and a finding previously marked `remediated`
  is reopened automatically if it reappears. This is the main difference from
  DefectDojo's re-import model, which produces many duplicates.

Findings carry a lifecycle status (`open`, `confirmed`, `false_positive`,
`risk_accepted`, `remediated`, `wont_fix`). The same data serves every role:
executives read the project risk score, PMs the open counts by severity, and
developers the filtered findings list.

### Branches and releases

Uploads state what they belong to: `?branch=feature/x` or `?release=1.4.0` (CLI
`--branch` / `--release`; the GitHub Action passes the branch). A version is
created on first use, and the first version a project uses becomes its default.
If no name is given, the default version is used (`main` if none exists yet).

- Each version has its own lifecycle. The same CVE on `main` and `feature/x`
  is two findings: fixing it on the branch doesn't close it on `main`, and
  accepting the risk on `main` doesn't hide it on a release. A scan only
  auto-closes findings of its own version (and asset).
- The default version represents what the organization runs. Project summaries,
  the portfolio, compliance, SLA alerts, new-critical alerts, summaries and an
  unqualified gate read only default versions. Listings show the default version
  unless you pass `?branch=`, `?version_id=` or `?all_versions=true`.
- Gates per branch: `POST /projects/{id}/gate?branch=feature/x` (CLI
  `xila gate --branch`). An unknown branch returns `404`, so CI fails instead
  of passing against an empty backlog. `upload --gate` gates the version it just
  uploaded to.
- Housekeeping: **non-default branches not scanned for `BRANCH_RETENTION`
  (default 90 days) are deleted along with their findings.** Releases are not
  pruned. Owners can change the default or delete a branch from the project's
  Branches tab.
- Data from before versions existed was placed on a single default version,
  named after the branch with the most scans.

### Analyst workflow

- Editing a finding: `PATCH /findings/{id}/fields` (the Edit link by the
  title) overrides the scanner's `title` or `severity` and sets a
  `planned_remediation_at` date. An override persists. The next scan keeps it and
  triage rules don't reset the severity, until *use the scanner's* (`reset_title` /
  `reset_severity`) hands the field back. A severity change (here, in bulk, or by
  an approved assessment) recomputes priority from every input (EPSS, KEV,
  exploits, reachability, exposure), not just the severity weight.
- Conflict detection: the finding page sends `If-Match: "<updated_at>"` with
  every edit (fields, status, assignee, tags, write-up). If someone changed the
  finding since you loaded it, nothing is written. The response is `412` with the
  current finding, and the page reloads it.
- Source links: a finding's `file:line` links into the repository at the
  commit its last scan reported (`commit=` on upload; otherwise the branch), for
  GitHub (incl. Enterprise), GitLab, Bitbucket, Azure DevOps and Gitea/Forgejo
  `repo_url`s. An unrecognized host gets no link rather than a guessed one.
- Assignee: who owns fixing a finding (`PUT /findings/{id}/assignee`). Only
  people who can see the project can be assigned. `?assignee=me|none|<id>` filters
  any finding list (`?active=true` keeps open and confirmed ones); the inbox has *Assigned to me*.
- My work: one page with everything waiting on you. Findings assigned to you,
  assessments and risk acceptances you may decide, acceptances you own that
  expire within 30 days, and AI proposals you asked for or on your findings.
  Each list is the server's own queue (`?actionable=true`, `?owner=me`,
  `?mine=true`), so nothing is trimmed in the browser.
- Links out: CVE ids link to NVD and OSV, GHSA ids to GitHub Advisories and OSV,
  and a package URL to its deps.dev page (npm, PyPI, Maven, Go, Cargo, NuGet).
- Comments and attachments: the discussion and the evidence (screenshots,
  PoC output; ≤10 MiB each, stored in Postgres). Downloads are always served as
  files with `nosniff`, and HTML/SVG/scripts as `application/octet-stream`, so an
  attachment cannot run in Xila's origin.
- Custom fields: admins define typed fields (Admin → Custom fields,
  `/custom-fields`) on projects, assets or findings: `text`, `number`, `date`
  (`YYYY-MM-DD`), `enum` (fixed options) or `user`, optionally `required` and
  optionally scoped to one organization. Values appear under `custom` in every
  project / asset / finding response and are written with
  `PATCH /{projects|assets|findings}/{id}/custom` (editor). Every key must be a
  defined field of that entity (and its organization), every value must fit the
  type, a user field may only name someone who can see the project, and a required
  field must stay set. Otherwise the response is `400` and nothing is written. Every finding,
  project and asset list filters on them: `?cf.<key>=value`, numeric / date ranges
  `?cf.<key>.gte=` (`gt`, `lte`, `lt`), `?cf.<key>.set=true|false`. Finding
  exports include one column per finding field (a user field as the email). Triage
  rules read them in CEL (`finding.custom.<key>`, `project.custom.<key>`; component
  policies `project.custom.<key>`) and can set one with the `set_custom_field`
  action. Changes to a finding's fields are added to its history (`kind: custom_field`,
  `field`), whether made by people or rules.
- History: every status, severity and assignee change, with who made it and
  the reason they gave, plus comments and attachments. It is written by a
  database trigger, so automatic changes (auto-close, reopen on reappearance,
  auto-triage, VEX, the exception sweep) are recorded too, as *system*.
- Bulk edits: `POST /findings/bulk` applies one status / severity / assignee
  change to a selection (`ids`) or to everything a filter matches (`filter`, the
  `GET /findings` keys), up to 5000 findings, in one transaction. Each finding is
  authorized against its own project; the ones you can't edit are returned in `failed`.
  In the inbox, select a page and then *Select all matching* to triage a whole
  filtered backlog.
- Approval of manual assessments (four-eyes, off by default): with
  `ASSESSMENT_REQUIRES_APPROVAL=true`, a status change (`PATCH /findings/{id}`)
  or a bulk status / severity change is not applied directly. It becomes a pending
  assessment (`202`; bulk lists them in `pending`). At most one can be pending per
  finding (a second request returns `409`, or `failed` in a bulk). An owner of the
  finding's project, or an instance admin, other than the requester approves
  (`POST /assessments/{id}/approve`) or rejects (`…/reject`) it, with an optional
  `note`. The requester can't decide their own request (403), and instance admins'
  own changes are gated too. Approval applies the change as a direct change
  would (resolved_at, exception audit row, dedup regroup). The history attributes it
  to the requester with their reason, followed by an `assessment`
  event by the approver. A rejection leaves the finding untouched. A stale
  request still applies its *target* state even if the finding changed since
  (a rescan reopened it, someone else triaged it). The reviewer approves the
  outcome the request shows. Assignee changes and comments are not gated. The
  review queue is `GET /assessments?state=pending` (the UI's *Approvals* page),
  and the finding page shows its pending request with Approve / Reject.

Search and tags. `?q=` on any finding list is full-text search in websearch
syntax (words in any order, `"a phrase"`, `-excluded`, `or`) over title, rule
id, CVEs, package, purl, tags, path and description. It uses PostgreSQL `tsvector`, GIN
indexed, and matches whole tokens without stemming, so `CVE-2021-44228` and `log4j-core` match as
typed. Without an explicit `sort`, results are ordered by relevance. Tags are
your own labels (`pci`, `internet-facing`, `sprint-9`). You can set them on a finding,
add or remove them in bulk, and filter with `?tag=a,b` (all must match). Scanners do not
change them, re-ingest keeps them, changes appear in the finding's history, and
exports carry the same filter.

Exceptions / risk acceptance: triaging a finding to `false_positive` or
`wont_fix` records a reason and an optional expiry on the finding, audited in
`GET /findings/{id}/exceptions`. A background sweep (`EXCEPTION_SWEEP_INTERVAL`,
default hourly) reopens them when the expiry passes.

Risk acceptances are first-class objects. One acceptance covers many
findings of a project, with a title, justification, owner and expiry, and a
`requested → approved → expired / revoked` (or `rejected`) lifecycle. **A finding
is `risk_accepted` only while an approved acceptance covers it.** "Accept
risk" (PATCH / bulk `status: risk_accepted`, the `a` key) creates a request,
and until it is approved the findings stay open and counted. Approval requires a
project owner and, with `RISK_ACCEPTANCE_REQUIRES_APPROVAL` (default on in
production), someone other than the requester. Approval pauses the findings'
SLA clocks. When the acceptance expires (same sweep) or is revoked, the findings reopen
and the clock resumes with the paused time added. A per-finding ledger
(`GET /findings/{id}/risk-acceptances`) keeps every stay after a finding leaves.
Triage rules with the accept action keep one approved acceptance per rule and
project. Imported verdicts (DefectDojo, SecObserve…) are grouped into one acceptance per scanner,
reason and expiry, held as requests under four-eyes. Events:
`risk_acceptance.requested`, `.approved`, `.expiring`
(`RISK_ACCEPTANCE_EXPIRY_WARNING`, default 7 days ahead) and `.expired`.

Ingestion health. A quiet project may be one whose scans stopped arriving.
`GET /ingestion-health` (and a banner on the dashboard) lists the following for the projects you
can see: scanners that uploaded on a cadence and went silent for more than 3× their
usual gap (`stale`); uploads that suddenly report under half the findings of the
previous ones (`volume_drop`, which is how an expired token or a misconfigured scanner looks, rather
than a clean project); failed latest scans; failing connectors; and
uploads that exhausted their ingest retries. The leader checks hourly and sends
`ingestion.anomaly` once per new problem, and again only if it clears and returns.

Per-channel rules. Each channel can set a minimum severity (lower-severity
events skip it; events without a severity always pass) and a scheduled summary:
`daily` at an hour or `weekly` on a weekday at an hour (UTC). A summary covers
the channel's scope (its project, or every project): new findings by severity and
fixed in the period, the open backlog by severity, SLA breaches, open KEV,
acceptances expiring in 30 days, and the top five open findings by priority. It goes only to that
channel (event type `summary`), once per slot even across a leader
handover. A new or edited schedule starts at the next slot. Edit rules with
`PATCH /api/v1/notifications/channels/{id}` or the Edit button. This replaces
the fixed daily digest and `DIGEST_ENABLED` / `DIGEST_INTERVAL`. Channels that
received the digest were moved to a daily summary at 08:00 UTC.

Personal notifications. Anyone can subscribe themselves, without an admin,
under Account → My notifications (`GET/PUT /me/notifications`).
They can receive events on findings assigned to them (`finding.assigned` and every later event
naming the finding) and on projects they watch (the ☆ Watch button,
`PUT/DELETE /projects/{id}/watch`). Delivery is by email to their account address
and/or a personal Slack or Teams webhook (sealed with `INTEGRATION_SECRET_KEY`,
write-only), each with event types and a minimum severity. Deliveries use the same
outbox and retries as every channel and are listed in their own log. **Access is
checked twice, when the event is routed and again when it is sent: someone who
lost access to the project, or was deactivated, receives nothing.** Service accounts
can't subscribe.

Channel filters (CEL). A channel can also carry a `filter`, a
[CEL](https://cel.dev) expression over the event. The channel then gets an event
only when the expression holds, in addition to its event types, project and minimum
severity. It uses the same language as triage rules and component policies:

| Variable | Fields |
|---|---|
| `event` | `type`, `title`, `severity`, `project_id`, `finding_id`, `fields` (the event's key/value details) |
| `event.project` | `name`, `slug`, `tags`, `criticality` |
| `event.finding` | `scanner`, `category`, `rule_id`, `title`, `severity`, `status`, `cve`, `cvss`, `epss`, `kev`, `kev_sources`, `kev_ransomware`, `package`, `fixed_version`, `file_path`, `tags` |

```cel
event.finding.kev && "internet-facing" in event.project.tags
event.type.startsWith("cra.") || event.project.criticality == "critical"
"enisa" in event.finding.kev_sources && event.finding.epss >= 0.5
```

A filter is checked when you save it (`400` with the reason: syntax, an unknown
field, a non-boolean result). At delivery, an unknown fact is null and does not
match: an event that names no finding has no `event.finding`, and a finding
without CVSS has `cvss = null`. A filter that can't be evaluated skips its own
channel and does not affect the others.

Channel types. A channel's `url` field is the target, validated per type:

| `type`       | `url` holds                         | Payload |
|--------------|-------------------------------------|---------|
| `webhook`    | http(s) URL                         | the raw event JSON, optionally signed (below) |
| `slack`      | Slack incoming-webhook URL          | `{"text": …}` |
| `mattermost` | Mattermost incoming-webhook URL     | Slack-compatible `{"text": …, "username": "Xila"}` |
| `teams`      | Teams incoming-webhook / Workflows URL | Office 365 connector MessageCard (`summary`, `title`, `text`, severity `themeColor`, event fields as `sections[].facts`). Accepted by legacy incoming-webhook connectors and by the Teams Workflows *"When a Teams webhook request is received"* trigger |
| `email`      | comma-separated recipients, e.g. `alice@example.com, Bob <bob@example.com>` | multipart plain + HTML mail, subject = event title, via `SMTP_*` |

Email channels need `SMTP_HOST` + `SMTP_FROM`; creating one without them returns
`400 SMTP is not configured`. `POST /notifications/channels/{id}/test` delivers to
that one channel synchronously (three quick tries) and returns the result.

Signed webhooks. Every generic `webhook` delivery carries `X-Xila-Delivery` (a
UUID per outbox row, the same on every retry, so drop ones you've seen) and
`X-Xila-Timestamp` (unix seconds of this attempt). If you give the channel a
`signing_secret` (16–256 characters; the Signing secret field of the channel
editor), each delivery also carries

```
X-Xila-Signature: v1=<hex HMAC-SHA256(secret, timestamp + "." + raw body)>
```

The secret is encrypted at rest with `INTEGRATION_SECRET_KEY` (required to set
one) and is write-only: the API only reports `has_secret`. `PATCH` with a new value
rotates it, with `""` removes it. **Verify on the raw body**, compare in constant
time, and reject timestamps more than 5 minutes from your clock (a replayed
delivery). The header may hold several comma-separated `v1=` values; accept any
match. `notify.VerifySignature` is the reference implementation.

```go
func verify(secret string, r *http.Request, body []byte) bool {
	ts := r.Header.Get("X-Xila-Timestamp")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || time.Since(time.Unix(sec, 0)).Abs() > 5*time.Minute {
		return false // missing, malformed or replayed
	}
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(ts + "."))
	m.Write(body)
	want := m.Sum(nil)
	for _, v := range strings.Split(r.Header.Get("X-Xila-Signature"), ",") {
		got, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(v), "v1="))
		if err == nil && hmac.Equal(got, want) {
			return true
		}
	}
	return false
}
```

```js
const crypto = require("node:crypto");

// rawBody: the request body as a Buffer (e.g. express.raw({ type: "application/json" })).
function verify(secret, headers, rawBody) {
  const ts = headers["x-xila-timestamp"];
  if (!/^\d+$/.test(ts ?? "") || Math.abs(Date.now() / 1000 - Number(ts)) > 300) return false;
  const want = crypto.createHmac("sha256", secret).update(`${ts}.`).update(rawBody).digest();
  return (headers["x-xila-signature"] ?? "").split(",").some((v) => {
    const got = Buffer.from(v.trim().replace(/^v1=/, ""), "hex");
    return got.length === want.length && crypto.timingSafeEqual(got, want);
  });
}
```

Delivery is durable. An event is written to a PostgreSQL outbox (one row per
subscribed channel, decided when the event happens) and sent by the leader
instance (below). A failed send is retried with exponential backoff
(`NOTIFY_RETRY_BASE` 30 s, doubling, capped at `NOTIFY_RETRY_MAX` 1 h) up to
`NOTIFY_MAX_ATTEMPTS` (8, ≈3 hours). Retries survive restarts and leader
failover: a claimed row is leased, so a row whose sender died is picked up again.
A receiver that is down for an hour misses nothing. `GET /notifications/pending`
(and the Notifications page) shows what is still waiting, with the last error.
Each row's final outcome (delivered, or given up after N attempts) is written to
the delivery log (SMTP records status `null` plus the error text). Finished rows
are purged after `NOTIFY_RETENTION` (7 days).

SLAs (remediation deadlines): every finding gets a deadline based on its
severity. The defaults are 7 / 30 / 90 / 120 days for critical / high / medium /
low, with no SLA for info. You can override this per instance, per organization,
or per project (`PUT …/sla/policy`). The most specific stored policy applies as a
whole. **Saving a policy re-dates existing findings immediately.** Each finding
carries `sla_days`, `sla_due_at`, and `sla_status`:

| `sla_status` | Meaning |
| --- | --- |
| `on_track` | live, inside its window |
| `due_soon` | live, in the last 25% of its window (critical 7d → last 1¾ days; low 120d → last 30) |
| `breached` | live, past its deadline |
| `paused` | risk-accepted / false positive / won't fix. The clock stops, and reopening adds the paused time to the deadline |
| `met` / `missed` | remediated before / after the deadline |
| `none` | no SLA for this severity |

Filter with `?sla=breached` (or any status) and work the queue with
`?sort=sla_due`. Project summaries and the portfolio report breached and due-soon
counts, SLA compliance (share of fixes in the last 90 days that were on time),
and mean time to fix per severity. A sweep (`SLA_SWEEP_INTERVAL`, hourly) sends
`finding.sla_breach` and `finding.sla_due_soon` notifications: one per project,
listing the worst first, and once per deadline per finding. Gates can fail on any
breach (`block_sla_breach`, `xila gate --block-sla-breach`). Changing a project's
SLA requires the project owner role, not editor, so the team working the backlog
can't relax its own deadlines. A database trigger maintains deadlines, so every
path that changes a status or severity (manual or auto-triage, VEX, auto-close,
reopen, expiry) updates the clock correctly.

Scale by business criticality (optional): an instance admin can enable
`scale_by_criticality` (`PUT /sla/settings`, or the *Business criticality* card
on the SLA page). Every window, from whichever policy, then becomes
`round(days × factor)` for the project's `business_criticality` (defaults:
critical ×0.5, high ×0.75, medium ×1, low ×1.5; each 0.1–10; minimum 1 day; no
SLA stays none). Under the default policy, a critical CVE in a business-critical
system is due in 4 days, and in a low-importance one in 11. Saving re-dates every
existing finding. While the setting is on, changing a project's criticality
re-dates that project's findings. `GET /sla/settings` returns the resulting
criticality × severity matrix, and a project's `GET …/sla/policy` adds the
windows it actually gets (`applied`).

Issue trackers (Jira, GitHub Issues, GitLab Issues): each project can have
one tracker. The project owner configures it: kind, base URL, target (Jira
project key, GitHub `owner/repo`, or GitLab project id/path), and an API token.
The token is encrypted at rest (AES-256-GCM with `INTEGRATION_SECRET_KEY`,
bound to the project) and is not returned; the API only reports `has_token`.
Without the key configured, trackers can't be created (400). An editor files a
finding with `POST /findings/{id}/issue`. This is idempotent: a finding has at most one
issue. With `auto_create` on, every sync also files live, non-duplicate findings
at or above `min_severity` (at most 50 per tracker per run, most severe first).
The issue title is `[severity] title`, and the body contains the description, package@version, fixed
version, CVEs, CVSS / EPSS / KEV and, when `PUBLIC_URL` is set, a link back.
The sync (`ISSUE_SYNC_INTERVAL`, 15 min, or `POST /issue-trackers/sync`) is
two-way. A finding leaving the backlog (remediated, risk accepted, false
positive, won't fix) closes its issue, and one coming back reopens it. An issue
closed in the tracker marks the finding remediated. If the problem is still
there, the next scan reopens the finding, and the sync then reopens the issue.
An issue reopened in the tracker reopens a remediated finding, but does not overturn a
risk acceptance or false positive; in that case the issue is closed again. Each link stores
the last state both sides agreed on, so the sync can tell which side changed and
the two directions don't undo each other. Jira closes and reopens issues via workflow
transitions matched by name (`done_transition` / `reopen_transition`, default
`Done` / `To Do`). Jira Cloud authenticates with `jira_email` + API token; Server
/ Data Center uses a PAT. A failing tracker or issue is logged and counted, and does not
stop the run.

Remediation actions: open findings grouped by the single change that fixes
them, tracked as work items with an owner, a due date and a status (`open`,
`in_progress`, `done`, `wont_do`). The grouping comes from the fix plan
(`internal/fixplan`), extended to every kind:

| Kind | Groups | Example |
|------|--------|---------|
| `package_upgrade` | package findings on one package version; target = the smallest version fixing all of them | Upgrade setuptools 65.5.1 → 70.0.0 |
| `base_image` | distro packages (Trivy `os-pkgs`, deb/rpm/apk purls) with a fix, of one scanned image (Trivy / Grype image reports) | Rebuild python:3.11-slim on a patched base image (debian 12.5) |
| `iac_rule` | IaC / cloud / Kubernetes findings by rule + file (+ resource when the scanner names one) | DL3008 in Dockerfile.nginx |
| `code_location` | SAST and secret findings by file, one fix per file | Fix src/app.py |
| `config` | other rule-based findings (DAST, infrastructure) by rule | HSTS missing |

A sweep (`REMEDIATION_SWEEP_INTERVAL`, 15 min, leader-elected, or `POST
/remediation/sweep`) and a pass after each ingest's dedup group the live,
non-duplicate default-version findings not yet in an action. Findings matching a live
action's change join it. The rest become proposals (`GET
…/remediation/proposals`) that an editor accepts or, with
`REMEDIATION_AUTO_CREATE=true`, become actions immediately. Every live action
is then refreshed: its due date is the earliest SLA deadline of its open
findings, its owner is the assignee of most of them (unless set manually), and it
closes itself (`close_reason: findings_resolved`) once every finding is
remediated or a false positive. An action is filed as one ticket in the
project's issue tracker (`POST /remediation/{id}/issue`) and kept in step by the
issue sync: closing the action closes the ticket, closing the ticket closes the
action (`issue_closed`), and reopening the ticket reopens the action. The project page has a
Remediation tab (proposals and actions, expandable to their findings); the
portfolio list is under Remediation in the nav. The fix plan endpoints still
list package upgrades (distro packages included, as individual upgrades).

Root causes (`internal/rootcause`): the same package upgrade, base-image
rebuild or rule fix needed in more than one project is one row instead of one
per project, merging `fixplan.Changes` over every project you can see, with no
second grouping logic. `GET /root-causes` lists them, sorted by priority
removed then projects affected, with filters for kind, ecosystem, a text
search, KEV-only and a minimum severity; `GET /root-causes/{kind}/{key}`
(`key` base64url-encoded, since it can hold `/` and `@`) shows the affected
projects, each with its findings, priority removed and live remediation
action if it has one. `POST /root-causes/{kind}/{key}/remediation` creates the
missing action in every visible project you hold at least editor on, reusing
`remediation.Service.Accept` so its invariants hold (one live action per
change, idempotent). Visible projects that are already live, or that you can't
edit, are reported in `skipped`; projects you can't see are never touched or
named. Gated by the `remediation` feature switch
alongside remediation actions; the nav has a Root Causes page with the same
list, an expandable row per change for its affected projects, and a button to
create the missing actions.

Pull connectors (Dependency-Track, DefectDojo, Snyk, GitHub, GitLab, Wiz,
Tenable): point a project at a running
Dependency-Track project (by UUID) or DefectDojo product (`42`) or engagement
(`engagement:42`) and Xila imports its findings, either on demand (Pull now,
project editor) or every `CONNECTOR_PULL_INTERVAL` (6 h). A project can have
several connectors (one per kind per version; `version` names the branch the
findings land in, empty = the default). Each pull is one scan by scanner
`dependency-track` / `defectdojo` through the normal ingest pipeline (triage
rules, VEX, cross-tool dedup, alerts), so new findings appear and findings the
remote no longer reports auto-close. A pull applies only a complete fetch.
If the remote is unreachable, rejects the key, or returns fewer findings than it
says it has, nothing is applied or closed: the connector records `last_error`
and the next pull retries. Dependency-Track: `GET /api/v1/finding/project/{uuid}`
(suppressed included, paged) with `X-Api-Key` (the key needs VIEW_PORTFOLIO +
VIEW_VULNERABILITY); component name/version/purl, vulnId (GHSA aliases lifted to
their CVE), severity, CVSS, CWEs, description + recommendation. DefectDojo:
`GET /api/v2/findings/?test__engagement__product=…` (non-duplicate, non-mitigated,
paged) with `Authorization: Token …`; active findings plus the inactive ones it
triaged; title, severity, vulnerability ids, CWE, component, file/line,
description + mitigation, `unique_id_from_tool`. Remote triage (DT analysis
`NOT_AFFECTED` / `FALSE_POSITIVE` → false positive, `EXPLOITABLE` → confirmed; DD
false positive / risk accepted / verified) is kept in the finding's metadata and
applied only to newly imported findings that nothing local has triaged. It does not
overturn Xila's triage. Tokens are encrypted at rest the same way as tracker tokens
(`INTEGRATION_SECRET_KEY`), only the owner can configure them, and changing `base_url`
requires re-entering the token. Scheduled pulls are serialized across instances
by a per-connector advisory lock. A failing remote does not stop the others.

The other kinds, each its own scanner name so they never close each other's
findings. Every one pages through the vendor API, honours `Retry-After` on 429,
lifts the CVE and maps the vendor's dismissal to remote triage:

| Kind | `remote_project` | API | Remote triage |
| ---- | ---------------- | --- | ------------- |
| `snyk-api` | `<org id>` or `<org id>:<project id>` | REST `GET /orgs/{org}/issues` (SCA, Code, IaC, license), `Authorization: token` | ignored issues |
| `github` | `owner/repo` or `org:<org>` (github.com or GitHub Enterprise Server) | code scanning and Dependabot alerts, Bearer token | dismissed alerts, with the reason |
| `gitlab` | namespaced project path (gitlab.com or self-managed) | GraphQL `project.vulnerabilities`, `read_api` token | dismissed vulnerabilities, with the reason |
| `wiz` | comma-separated Wiz project ids, or empty for all | OAuth client credentials at the tenant's token URL (`auth_url`), GraphQL `vulnerabilityFindings` | rejected findings |
| `tenable` | optional asset tag `<category>=<value>` | Vulnerability Management export (`POST /vulns/export`, poll, download chunks), `X-ApiKeys` | accepted (risk-accepted) vulnerabilities |

Fixed or resolved items aren't fetched, so the next pull auto-closes them. Wiz and
Tenable take two secrets (client id and secret, access and secret key), stored
together like any connector token.

Auto-triage rules (noise reduction): persistent rules (*conditions → action*)
that run automatically on every ingest and across the existing backlog, so
the same triage decision doesn't have to be made twice. Conditions (all AND-ed, any
subset) match on scanner, category, severity, CWE, scanner rule id, CVE,
file-path / package regex, reachability (`dep_scope`, `dep_transitive`), exploit
signals (`min_epss`: EPSS ≥ threshold, inclusive, and a finding with no EPSS score
does not match; `kev`: only findings a KEV catalog lists), and `project_criticality`
(the project's business criticality is one of the listed values). The action is
suppress (`false_positive`), accept risk, won't fix, downgrade
severity, or set a custom field (`set_custom_field` with `custom_field` +
`custom_value`, validated against the field on save; a finding already holding the
value is left alone, and one the value isn't valid for, such as another organization's
field or a user who can't see the project, is skipped). The first matching rule wins, and it applies before the new-critical
alert fires, so muted findings don't page anyone. Rules are instance policy
(admin-managed) and can be global or scoped to one project. See
`POST /api/v1/triage-rules` and the Triage Rules UI. Rules work the same way for
appsec, SCA, and CSPM/KSPM findings.

- Dry run: `POST /api/v1/triage-rules/preview` (a draft rule body) or
  `POST /api/v1/triage-rules/{id}/preview` (a stored rule, in any state)
  lists the findings the rule *would* change and how. Evaluation matches a
  backlog apply (live open/confirmed, non-duplicate findings; the rule slotted into
  the live rules by `sort_order`, first match acts, chained rules included). Results are capped at 200 with a `total`.
- Order and chaining: rules evaluate by `sort_order` (lowest first) and the first
  match acts. A rule with `continue: true` lets the rules after it evaluate too,
  against the finding as it left it: raise internet-facing findings to critical,
  then let a later rule act on every critical.
  `?project_id=` narrows it. Nothing is written.
- Hit metrics: each rule's `hit_count` grows by the findings it actually
  changed (ingest and backfill; idempotent re-runs add nothing), with `last_hit_at`.
- Approval workflow (four-eyes, off by default): with
  `TRIAGE_RULES_REQUIRE_APPROVAL=true`, creating or editing a rule makes it
  `pending`, and pending rules do not apply. **Editing an approved rule stops it
  applying until it is re-approved.** `POST /api/v1/triage-rules/{id}/approve` must
  come from an admin other than the rule's author and last editor (403 otherwise).
  `POST /api/v1/triage-rules/{id}/reject` marks it `rejected` (kept for audit, does not
  apply; editing it re-submits it). With the setting off, rules are approved on
  save.

Cross-tool dedup: the same CVE in the same package reported by two scanners
(e.g. Trivy *and* Grype) is one issue, not two. On every ingest, findings are
grouped by a scanner-agnostic correlation key: CVE findings key on min CVE +
package (or + location for a package-less CVE, e.g. network/DAST); findings
with no CVE (SAST, secrets, IaC) key on category + file path + line, plus CWE
when the finding has one (a CWE-bearing and a CWE-less report at the same line
never share a key; two CWE-less reports there still fall back to location
alone). Within each active CVE-keyed group a primary is elected (highest
priority, stable) and the rest are linked to it (`duplicate_of`), same scanner
or not. A location-keyed group (no CVE) collapses the same way, but only when
every one of its members is from a *different* scanner: two rules from the
same tool sharing a line/CWE must never hide one another, so if a group has
more than one report from the same tool, none of its members is marked a
duplicate at all (visible as separate findings). Duplicates are hidden from
lists, counts, risk, alerts, and triage, so metrics reflect issues rather than
report copies. Each scanner's report is still preserved (its own lifecycle +
provenance). Primaries are badged with how many tools agree. Grouping is
recomputed each ingest, so it self-heals when a scanner stops reporting. See
`?include_duplicates=true` and `GET /findings/{id}/duplicates`. A finding with
neither a CVE nor a file path/line (most DAST without a CVE) still gets no key:
matching by title alone is not a sound cross-tool signal.

Security gates (break the build): a per-project (or global-default) policy
that CI evaluates to fail a pipeline on unacceptable risk. `POST /projects/{id}/gate`
checks the deduped, triaged backlog against these thresholds: `max_critical`,
`max_high`, `max_medium`, `max_low`, `max_info`, `block_kev` (optionally only for the catalogs in `kev_sources`),
`max_epss`, `block_license`, `max_risk_score` (the same business-weighted risk
score the project summary shows, scoped to the gated version). It returns
200 when it passes and 422 when it fails, both with the full result (violations
+ live stats), so plain `curl --fail-with-body` works and a CLI can read the
body. Waived and duplicate findings do not trip it (which is why the noise-reduction
work comes first). Pass a policy in the request body to gate with ad-hoc
thresholds without storing them. Set the policy at `PUT /projects/{id}/gate/policy`
or the Gate tab.

New-only gating (PR checks): set `new_only` (policy flag, or `"new_only": true`
in the request / `xila gate --new`) to fail only on newly introduced findings.
By default "new" means seen in only one scan so far (`first_scan_id =
last_scan_id`), so a PR isn't blocked by pre-existing debt. It composes with
dedup: a new tool reporting an *old* vulnerability doesn't count as new.

Baseline-branch gating: set a `baseline_branch` on the policy (or
`?baseline=` on the request / `xila gate --baseline <name>` / `upload
--baseline`) to redefine "new" as *not already open on that branch*, instead of
using the single-scan heuristic. The heuristic stops being useful once a long-lived
branch has been scanned more than once. The identity compared is the finding's
fingerprint (scanner, category, rule, file path, package; see "Add a
column to `findings`"). This is the same cross-scan identity `Upsert`/`CloseMissing`
already use to recognize the same finding reappearing. Unlike
`correlation_key` (grouped by CVE or by category+file+line+CWE, not by
exact fingerprint), it covers every finding type and is already branch-independent. A
baseline finding only excuses the reappearance while it is open or
confirmed there. Once triaged away (false positive, won't-fix,
risk-accepted, remediated), it no longer vouches for the fingerprint resurfacing
on a feature branch. An unknown baseline name returns `404`, same as an unknown
`branch`/`release`, so a misconfigured baseline cannot silently pass.

Auto-close: an ingest treats the scan as the scanner's complete current view
of its target (the `asset_id` and `branch` it was uploaded with), so a
scanner's `open`/`confirmed` findings on that target that no longer appear are
automatically marked `remediated` (triaged states are left alone). A scan does not
close what it didn't look at: scanning `feature/x` leaves `main`'s findings open,
and scanning image B leaves image A's open. Disable per-upload with
`?close_missing=false`. Combined with reopen-on-reappearance, findings track the
real state of the code without manual bookkeeping.

Prioritization: findings carry `cvss` (captured from the scanner), `epss`
(exploit probability, FIRST.org), `kev` (on a Known Exploited Vulnerabilities
catalog) with `kev_sources` (which ones), and a computed `priority =
severity_weight × exploitability` (KEV ⇒ ×3, else `1 + 2·EPSS`). So `critical +
KEV = 45` outranks a quiet `critical = 15`. Enrichment runs on a schedule and on
demand via `POST /enrich`. List findings with `?sort=priority` to work the backlog
exploit-first.

KEV catalogs. Each enrichment run downloads the catalogs in `KEV_SOURCES`:

| Catalog | Source | Default |
|---|---|---|
| `cisa` | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) `known_exploited_vulnerabilities.json` | on |
| `enisa` | [ENISA EU Vulnerability Database](https://euvd.enisa.europa.eu), exploited vulnerabilities (`euvdservices.enisa.europa.eu/api/search?exploited=true`, paged); each entry asserts its EUVD id and its CVE / GHSA aliases | on |
| `vulncheck` | [VulnCheck KEV](https://docs.vulncheck.com/community/vulncheck-kev/schema) (`/v3/index/vulncheck-kev`, cursor-paged) | with `VULNCHECK_API_TOKEN` |

A finding is matched by every id it is known by: its CVEs, its rule id, the
aliases its scanner reported, and the aliases of the advisory its rule id names
in the local OSV mirror or the private advisories. So a CISA entry for a CVE
also flags the GHSA record of the same flaw, and ENISA's GHSA alias flags a
GHSA-only finding. `kev_sources` lists the catalogs (sorted), `kev` is true when
any does, and the finding page shows them on the KEV badge. A catalog that fails
to download (or comes back empty) keeps asserting what it last delivered, so an
outage does not clear a KEV flag. The failure is reported in `kev_failed` and at `GET
/enrich/kev-catalogs`; a catalog removed from `KEV_SOURCES` stops asserting. Point
a catalog at a mirror with `KEV_CISA_URL` / `KEV_ENISA_URL` / `KEV_VULNCHECK_URL`.
Policies (`kev_source in [enisa]`, CEL `"vulncheck" in vulns.kev_sources`), triage
rules (`"cisa" in finding.kev_sources`) and gates (`kev_sources` limits
`block_kev` to some catalogs) can all read it.

CISA KEV and VulnCheck KEV also say whether a flaw is known to be used in
ransomware campaigns (`knownRansomwareCampaignUse`). A finding a catalog marks
that way has `kev_ransomware: true`, a Ransomware badge, a findings filter
(`?kev_ransomware=true`) and the `kev_ransomware` fact in triage rule and
notification expressions. Like the KEV ids, the flag survives a failed download.

### Engagements, manual findings & templates (DefectDojo workflow)

An engagement is a time-boxed piece of security work on a project, such as a
pentest, an audit, or a CI/CD pipeline (`kind` `interactive` | `ci_cd`, `status`
`not_started` → `in_progress` → `on_hold` / `completed` / `cancelled`, dates and a
lead). Scans uploaded with `?engagement_id=` (CLI `--engagement`, Action input
`engagement`) are its tests. An engagement from another project is refused.
`GET /engagements/{id}` returns its tests and stats (findings its scans reported,
open by severity). `?engagement_id=` filters every findings list and export.
Deleting an engagement keeps its scans and findings. An engagement is a view and a
lineage, not a silo.

Manual findings (found by a person, not a tool) are created with
`POST /projects/{id}/findings` (`editor`): title, severity, category, description,
steps to reproduce, impact, mitigation, references, CWE/CVEs, URL or file:line,
package, tags, and an optional engagement. They are recorded as scanner `manual`
and go through the whole pipeline (triage rules, dedup, priority, SLA, alerts),
with the history crediting the reporter. They are added without auto-close, so a
later manual report or scan does not close them. Their write-up stays editable
(`PATCH /findings/{id}/details`). A scanner's finding returns 409 there because its
text belongs to the scanner.

Finding templates (`/finding-templates`; read: everyone, write: instance
admin) are a team's standard write-ups. `template_id` on a manual finding fills
every field left empty. In the UI, *Report finding* copies the template into the
form, so what is filed matches what is on screen.

### SBOMs (Dependency-Track style)

Upload a CycloneDX or SPDX JSON BOM to `POST /projects/{id}/sboms`. The format is
detected from the content. Each upload is stored as an immutable snapshot
(`sboms`) with its full component list (`sbom_components`), so history is
preserved rather than overwritten:

- History: `GET /projects/{id}/sboms` lists snapshots newest-first (filter
  by `?artifact=`), giving the timeline of a project or artifact's dependencies.
- Current inventory: `GET /projects/{id}/components?latest=true` returns
  only the newest snapshot per artifact.
- Filter by package: `GET /components?name=log4j-core` (exact),
  `?search=log4j` (substring), plus `?version=`/`?purl=`. This answers "which
  projects/artifacts contain this component?" across the whole portfolio, with
  project context on each hit. Lookups are indexed by `name` and `purl`.
- Vulnerable or not: every component row (search, project inventory, one
  snapshot) carries `vuln_count`, `max_severity`, `kev` and the vulnerability ids,
  and `?vulnerable=true|false` filters on it. See *SBOM history* below for the rule.
- Where it came from: each component records the `file_path` it was found in
  (from CycloneDX `evidence.occurrences` or syft location properties), e.g.
  `package-lock.json`, shown in the Components views.
- Component policies: license, security and operational rules over the
  components raise findings (scanner `policy`). See *Component policies* below.

### SBOM history you can interrogate

Snapshots are kept so you can answer questions about releases:

- Was this release vulnerable, and to what? `GET /sboms/{id}/vulnerabilities`.
  A component version counts as vulnerable when an advisory matched that
  snapshot (OSV matching runs over every snapshot, not just the current one,
  and records the result per snapshot) or a scanner reported that exact package
  version in the project, in any status except `false_positive`. The second
  condition is deliberate. A `remediated` finding means the project moved off the
  version, not that the version became safe, so release 1.0.0 still reports
  Log4Shell after 1.1.0 upgraded and the finding closed. The same CVE from two
  sources counts once.
- What did this release change? `GET /sboms/{id}/diff` lists added, removed,
  upgraded, and downgraded packages (or `changed` when versions don't order) since the
  previous snapshot of the artifact or any `?base=` from the same project, with
  the vulnerabilities each change fixed or introduced. Packages are matched
  across versions by purl-without-version, so `lodash 4.17.20 → 4.17.21` is one
  upgrade.
- Which releases ever shipped CVE-X? `GET /vulnerabilities/CVE-X/sboms` (CVE or
  advisory id) returns, per artifact, every snapshot in order with whether it was
  affected, the snapshot that introduced it, the one that fixed it, and
  whether the newest still ships it. Results are scoped to the projects you can see.
- Why is this package here at all? The dependency graph (CycloneDX
  `dependencies`, SPDX relationships) is stored with each snapshot.
  `GET /sboms/{id}/graph` returns it with vulnerability state on every node, and
  `GET /sboms/{id}/graph/paths?ref=…` returns the shortest routes from the root to a
  package. This shows which direct dependency to upgrade to remove a vulnerable
  transitive one. A finding's page shows this for the component that introduced it.

### License data

On upload, each component's license is resolved into a normalized SPDX
license expression (`license_expression`), the license ids it mentions
(`license_ids`), their [ScanCode LicenseDB](https://scancode-licensedb.aboutcode.org)
categories (`license_categories`: Permissive, Copyleft, Copyleft Limited, Public
Domain, Proprietary Free, Commercial, …) and `license_resolved`. The raw
`license` string is kept as the document stated it.

- Parser: follows SPDX spec Annex D: `AND` / `OR` / `WITH`, parentheses, precedence
  (`WITH` > `AND` > `OR`), `+`, `LicenseRef-*` / `DocumentRef-*:LicenseRef-*`.
  Ids are matched case-insensitively and normalized to canonical case.
  Deprecated ids (`GPL-2.0`) are recognized and flagged. A license given by its
  full SPDX name (`Apache License 2.0`) or by one of a small, explicit table of
  spellings tools emit (`Apache 2.0`, `The MIT License`, `BSD`, `CC0`, …) maps to
  its id. Nothing is fuzzy-guessed. Anything else stays unresolved
  (`license_resolved=false`), as do NONE / NOASSERTION and unknown ids.
- Which statement: for SPDX, `licenseConcluded`, else `licenseDeclared`.
  For CycloneDX, every `licenses[]` entry (id, name or expression), combined with
  AND. A component listing several licenses ships under all of them, which is the
  conservative reading for policy. CycloneDX 1.6 entries acknowledged as
  `concluded` take precedence over `declared` ones. When one entry can't be parsed, the
  expression is empty but the ids that did parse stay in `license_ids`, so
  `?license=` still finds the component.
- Existing rows: resolved by a one-time backfill when the scheduler starts
  (`license_resolved IS NULL` rows only, per distinct raw string). It is idempotent and a
  no-op afterwards.
- Catalog: `GET /licenses` browses the embedded SPDX License List.
  `GET /licenses/{id}` shows one license and the groups it's in.
- License groups: named sets of license ids for license policies
  (`/license-groups`, admin-managed; members must be catalog ids or
  `LicenseRef-*`), plus one built-in group per ScanCode category, referenced as
  `category:Copyleft`.
- Filter components: use `?license=GPL-3.0-only` or
  `?license_category=Copyleft` on any component list.

The SPDX License List (CC0-1.0, [spdx/license-list-data](https://github.com/spdx/license-list-data))
and the ScanCode LicenseDB categories (CC-BY-4.0, © nexB Inc. and others) are
embedded in the binary (`internal/license/data/catalog.json`, currently SPDX
list 3.29.0). `make licenses` refreshes them.

### Services & data flow

CycloneDX BOMs can declare the services the software talks to (`services`,
spec 1.2–1.6; SaaSBOMs are mostly this). Each snapshot stores them (nested
services flattened with their parent's bom-ref) with endpoints, provider,
`authenticated`, the trust boundary (`x-trust-boundary`) and zone (`trustZone`,
1.5+), licenses, external references, properties and their data flows: both the
≤1.4 `{flow, classification}` pairs and the 1.5+ shape with name, description,
governance and source/destination BOM-Links. Service dependencies (services
on services, components on services) are part of the graph like any other edge.
SPDX has no notion of services.

`GET /sboms/{id}/services` and `GET /projects/{id}/services` (current snapshots,
default version unless `?branch=`/`?release=`) flag two conditions:

- `unauthenticated_external`: `authenticated: false` with an http(s) endpoint;
- `crosses_trust_boundary`: `x-trust-boundary: true`, or a data flow whose
  source/destination resolves (by BOM-Link, bom-ref or endpoint URL) to a service
  of the snapshot in a different trust zone (`crosses_trust_zone` on the flow).
  A peer that resolves to nothing has no known zone and does not count.

`GET /sboms/{id}/diff` also lists the services added, removed or changed between
releases: version, endpoints, authentication, trust boundary/zone and data
classifications (with flow direction). Services are matched by group/name, since bom-refs are
often per-document UUIDs.

In the UI, each snapshot has Vulnerabilities, Components, Services,
Changes and Graph tabs. The graph is a collapsible dependency tree with
"only paths to vulnerable packages" and package search. The Components page
answers "who shipped CVE-X?". The project overview counts its services and their
warnings.

### SBOMs stay alive (continuous advisory matching)

An SBOM is static once written. The vulnerabilities in it are
whatever the scanner knew that day. Xila keeps the risk attached to a stored SBOM
current without re-scanning: a background job takes the current
inventory (newest snapshot per project/artifact), batch-queries [OSV.dev] for
every PURL, and records the results as an `osv` scan on the project.

Because the results go through the normal ingestion pipeline, a stored SBOM
stays up to date:

- A newly disclosed advisory for a package you already ship shows up as a
  finding, with no new scan or upload. (Nothing is scanned locally; this matches
  an inventory you already provided against a public advisory feed, like EPSS/KEV.)
- If you upgrade the dependency, the finding auto-resolves on the next match
  (the same "closed because no longer reported" rule every scanner gets).
- Findings carry the CVE, so they are deduplicated across tools against the same CVE from
  Trivy/Grype instead of being counted twice. They then get EPSS/KEV priority,
  auto-triage, compliance mapping, gates and alerts.

The workflow: generate SBOMs however you like (Syft, `cdxgen`, your build),
upload once, and Xila keeps them scored. Each upload is matched immediately
(in the background, so the upload does not wait on the sources), then again every
`VULNMATCH_INTERVAL` (12h) and on demand via `POST /vulnmatch` (admin). Disable
with `VULNMATCH_ENABLED=false` (this also turns off match-on-upload). Matches for the
same project can overlap (for example, two quick uploads). A run whose snapshot was superseded
mid-run leaves the findings to the newer run instead of re-opening what it closed.

[OSV.dev]: https://osv.dev

### Publishing your own advisories (PSIRT)

Advisories → Our advisories (admin, `/psirt/advisories`) writes CSAF 2.0
security advisories (`csaf_security_advisory`) about your own products. Each covers one
project and has a tracking id (`PSIRT_ADVISORY_PREFIX-YYYY-NNNN`), title, summary,
CVE, CWE, CVSS 3.x vector (score and severity are computed), affected and fixed
versions (project versions or ranges), remediation, and acknowledgments. A draft can
start from a private advisory. Publish freezes a CSAF document checked against
the CSAF 2.0 mandatory fields. Editing and republishing bumps `version` with a
revision note. Withdraw finalizes it with a last revision. The publisher is
`PSIRT_PUBLISHER_NAME` / `_NAMESPACE` / `_CONTACT`.

With `PSIRT_PUBLIC=true`, Xila acts as a CSAF provider and serves unauthenticated
`/.well-known/csaf/provider-metadata.json` and `/csaf/advisories/` (`index.txt`,
`changes.csv`, `<year>/<id>.json`; file names are lowercased, with characters outside
`[a-z0-9+-]` replaced by `_`), so CSAF aggregators and your customers' tools can pick them up.
When it is off, those paths return 404 and documents are admin downloads only.

ScanCode.io projects import as SBOMs. Upload the project's JSON results
(`packages` + `dependencies`) like any SBOM (the format is sniffed) to get components with
their licences and dependency edges.

Syft output (`syft <target> -o json`) is also sniffed as an SBOM upload, not a
scanner. It reports packages, not findings, so there is no `?scanner=syft`.
Grype, which matches a Syft SBOM against advisories, is the scanner; see the
scanners table above.

### Vulnerability sources

`VULNMATCH_SOURCES` selects the advisory sources (comma-separated list, default `osv`). Their
answers are merged per package, so the same advisory from several sources produces
one finding:

| Source      | What                                                                                 |
|-------------|--------------------------------------------------------------------------------------|
| `osv`       | [OSV.dev] API (`VULNMATCH_OSV_URL`). Aggregates GHSA, PyPA, Go, RustSec, …           |
| `github`    | GitHub Advisory Database: REST `GET /advisories?ecosystem=&affects=`, batched per ecosystem and Link-paginated. Honors `X-RateLimit-*` / `Retry-After` and caches each purl's answer for 30 min. `VULNMATCH_GITHUB_TOKEN` lifts the anonymous limit of 60 req/h; use `VULNMATCH_GITHUB_URL` for GHES |
| `osv-local` | A local OSV mirror in Postgres, for air-gapped setups (below)                    |
| `private`   | The private advisory database (below)                                            |
| `vulnerablecode` | [VulnerableCode](https://github.com/aboutcode-org/vulnerablecode) bulk purl search, using the public instance (needs `VULNMATCH_VULNERABLECODE_API_KEY`) or your own (`VULNMATCH_VULNERABLECODE_URL`) |
| `jvn`       | [JVN iPedia](https://jvndb.jvn.jp) (Japan). JVNDB records are synced (`VULNMATCH_JVN_INTERVAL`, starting from `VULNMATCH_JVN_FROM_YEAR`; `POST /vulnmatch/jvn/sync`) and used for CVE alias enrichment: a matched CVE gains its JVNDB id as an alias, so feed rules and search see it. It does not match inventory itself, because JVN's CPEs rarely name packages |
| `nvd`       | CPE matching against the NVD CVE API for components that have a CPE but no purl: vendored C/C++ libraries, firmware, appliances, and anything else no package ecosystem names. Opt-in. Sends one rate-limited request per distinct CPE (answers cached 12 h) and shares `NVD_URL` / `NVD_API_KEY` and their rate limit with CVSS enrichment. A CPE needs a concrete version (`cpe:2.3:a:openssl:openssl:1.1.1k`; CPE 2.2 URIs are accepted). CPEs with `*` / `-` versions are skipped rather than reported against every CVE the product has had. "Fixed in" is the end of the NVD range that contains the installed version |

Feed rules (admin, Advisories → Feed rules, `/feed-rules`) apply policy to the
incoming feed. They run inside the matcher after all sources have answered, so they
apply to every source. Conditions: source, id/alias glob (`GHSA-*`), ecosystem,
package glob, severity, CVSS range, and a CEL expression over `advisory` and `pkg`.
Rules are evaluated in position order. A matching mute drops the advisory for that package (an
existing finding closes on the next *healthy* run; a partial run does not close
anything). The first matching set_severity rule decides the severity. Every matching
add_tags rule adds tags. The rules that acted are recorded in `metadata.feed_rules`.

**Merging.** Reports whose ids or aliases intersect (GHSA ↔ CVE ↔ PYSEC, a private
`XILA-…` aliasing a CVE) are one advisory. Its id is the GHSA when any source knows
one (so the finding's identity doesn't depend on which sources answered), otherwise the
record's own id. The highest *stated* severity and CVSS win (unknown never beats
known), and the fix is the lowest `fixed` above the installed version. All
sources record findings under one scanner name, `osv`, so existing `osv` findings
keep their identity when you add sources (a per-source scanner would auto-close and
recreate them, and duplicate merged ones). `metadata.sources` lists who reported it.

A failed source never closes findings. If some sources fail (GitHub rate limit,
network), matches from the others are still *added*, but nothing is auto-closed and
snapshot history stays at its last complete evaluation. Otherwise a finding reported only
by the failed source would look "missing" and be closed as fixed. `POST
/vulnmatch` reports `partial: true` and `failed_sources`; the next complete run
closes what's really gone. If every source fails, the run fails.

Air-gapped: local OSV mirror (`osv-local`). Import OSV's ecosystem exports
(`https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`, one OSV
JSON per entry) into `osv_advisories`:

- upload: `POST /vulnmatch/osv-import` (admin, multipart `file`; streamed entry by
  entry and idempotent: an advisory is only replaced by a newer `modified`; large
  exports need `HTTP_BODY_LIMIT_MB` raised), or the Advisories page;
- scheduled: set `VULNMATCH_OSV_ECOSYSTEMS` (e.g. `npm,PyPI,Maven,Go`) and the
  leader downloads `<VULNMATCH_OSV_MIRROR_URL>/<Ecosystem>/all.zip` at start and
  every `VULNMATCH_OSV_MIRROR_INTERVAL` (point the URL at an internal file server to
  stay offline), re-matching when anything changed; `POST /vulnmatch/osv-mirror/sync`
  forces it.

Matching follows the [OSV schema's evaluation algorithm]: a version is
affected if listed in `versions` or inside a range, replaying the range's events in
version order (`introduced` on, `fixed` off at that version, `last_affected` off
after it, `limit` caps). SEMVER ranges compare as SemVer 2.0. ECOSYSTEM ranges use
the ecosystem's ordering: PEP 440 for PyPI (`4.0.dev1 < 4.0a1 < 4.0rc1 < 4.0`),
RubyGems' for gems, and the repo-wide best-effort ordering otherwise. GIT ranges are
ignored, since their events are commit hashes that can't be evaluated without the repository.
OSV requires such records to also list `versions`, and those do match. Language
ecosystems are mapped from purls (npm, PyPI, Maven, Go, RubyGems, NuGet, Packagist,
crates.io, Hex, Pub, …). OS-distribution advisories stay with the online `osv`
source. `GET /vulnmatch/sources` shows the configured sources and mirror contents.

Private vulnerability database (`private`). Internal advisories against
internal packages, in OSV's shape: id (`XILA-<year>-<NNNN>` assigned when omitted),
summary, details, severity, CVSS vector, aliases, affected packages (OSV ecosystem +
name, or a version-less purl such as `pkg:generic/acme/billing-core`) with
ranges/versions, and published/withdrawn. They are evaluated by the same range code. `GET
/advisories[/{id}]` for anyone signed in; create/edit/withdraw/delete and `POST
/advisories/import` (OSV JSON, one document or an array) are admin-only. Every
change starts a background re-match: affected components become findings right
away, and withdrawing an advisory (or moving its fix below what you ship)
auto-closes them. The Advisories page has a package + range editor. An alias
to a public CVE merges the private advisory with the public one.

[OSV schema's evaluation algorithm]: https://ossf.github.io/osv-schema/#evaluation

### Public exploits (ExploitDB, Metasploit, Nuclei)

EPSS estimates the chance of exploitation; a public exploit is evidence the
tooling already exists. The leader syncs three feeds daily
(`EXPLOIT_INTEL_INTERVAL`): ExploitDB's `files_exploits.csv` and Nuclei's CVE
templates (proofs of concept), and Metasploit's module metadata (an `exploit`
module referencing a CVE is weaponized; an `auxiliary` scanner is a PoC).
Every finding gets `exploit_maturity`, the strongest exploit for any of its CVEs.
It is set at ingest (from what's already synced; no network on the upload path) and on
each sync. It raises priority like EPSS does, without stacking: weaponized counts
as EPSS 0.75 (2.5×), a PoC as EPSS 0.25 (1.5×), and KEV stays the 3× ceiling. No
known exploit does not lower anything. Filter with `?exploit=weaponized|poc|any`
(lists and exports), see the references at `GET /findings/{id}/exploits`, and
see the feeds' state at `GET /exploit-intel` (admin; `POST /exploit-intel/sync` runs
one now). A feed that fails keeps the references it last delivered, so an outage
does not silently drop a finding's exploit evidence. Mirror the feeds for
air-gapped installs with `EXPLOIT_INTEL_*_URL`.

### NVD CVSS vectors

With `NVD_ENABLED=true`, the enrichment schedule (`ENRICH_INTERVAL`) also fetches
each finding CVE's CVSS from the [NVD CVE API 2.0]. Requests are batched at 100 ids each
(`cveIds`), within NVD's rolling limit of 5 requests / 30 s (50 with
`NVD_API_KEY`), and retry after a window when throttled. Answers are cached in
`nvd_cves` (refreshed weekly; CVEs NVD hasn't scored yet, daily), at most 10,000
CVEs per run, so a first backfill without a key takes a few runs. Findings get
`cvss_vector` + `cvss_version` (CVSS v3.1, else v3.0, else v4.0; NVD's own
*Primary* assessment over a CNA's), and new findings are stamped from the cache at
ingest. Precedence: a score the scanner reported wins. NVD's base score
fills `cvss` only when the scanner gave none (`cvss_source: "nvd"`), and stays
across re-ingests until the scanner starts reporting one. The finding page shows
the vector.

[NVD CVE API 2.0]: https://nvd.nist.gov/developers/vulnerabilities

### Outdated components

Like Dependency-Track's repository meta analyzers, Xila asks each package's
registry what has been released since the version you ship. Every component row
(`/projects/{id}/components`, `/sboms/{id}/components`, `/components`) carries
`latest_version`, `outdated`, `versions_behind` and `version_published_at`, and
filters with `?outdated=true|false`. The UI shows an Outdated badge with
"latest x.y (N behind)", and the snapshot page counts outdated components.

| purl type  | Registry (default)                                  | Release dates |
|------------|-----------------------------------------------------|---------------|
| `npm`      | `https://registry.npmjs.org` (`dist-tags.latest`, `time`) | yes |
| `pypi`     | `https://pypi.org/pypi` JSON API (yanked files skipped) | yes |
| `maven`    | `https://repo1.maven.org/maven2` `maven-metadata.xml` | no (the metadata has none, and mirrors don't serve Central's search API) |
| `golang`   | `https://proxy.golang.org` (`@v/list`, `@latest`)   | latest only |
| `cargo`    | `https://crates.io/api/v1` (`max_stable_version`, yanked skipped; ≤ 1 req/s) | yes |
| `nuget`    | `https://api.nuget.org/v3/index.json` or any NuGet V3 feed (registrations; unlisted skipped) | yes |
| `gem`      | `https://rubygems.org` (`/api/v1/versions/<name>.json`) | yes |
| `composer` | `https://repo.packagist.org` (`/p2/<vendor>/<name>.json`) | yes |

- Latest is the newest stable release (yanked or unlisted ones don't count).
  A component that is itself a pre-release is also compared against pre-releases,
  so someone on `2.0.0-rc.1` hears about `rc.2`. Versions are ordered per ecosystem:
  SemVer (npm, Cargo, Go, NuGet's four-part), PEP 440, Maven's
  `ComparableVersion`, RubyGems and Composer. Maven build variants stay separate:
  `33.0.0-android` is compared with `-android` releases, not `-jre`.
- Unknown is not "up to date". No purl, an unsupported ecosystem, a package
  the registry doesn't have (private), or one not looked up yet all leave the fields
  `null`, and `?outdated=false` doesn't match them.
- Schedule: every `PKGMETA_INTERVAL` (1h), a sweep refreshes the packages in the
  current SBOM inventory whose metadata is older than `PKGMETA_TTL` (24h). An
  upload looks up its never-seen packages right away, in the background.
  `POST /pkgmeta/refresh` (admin) runs a sweep immediately. Per registry, at most
  `PKGMETA_CONCURRENCY` packages are in flight, and requests are spaced to
  `PKGMETA_REQUESTS_PER_SECOND`. A failure backs off exponentially (from 1h, or
  from the TTL for a 404) up to 7 days, keeping the last good data. A
  registry that fails 5 times in a row is skipped for the rest of the sweep. Requests
  carry `User-Agent: xila/<version> (+PUBLIC_URL)`.
- Mirrors / air-gapped: point an ecosystem at Artifactory or Nexus with
  `PKGMETA_<ECO>_URL` (same API shape: npm, PyPI JSON, Maven repository
  layout, GOPROXY, crates.io API, a NuGet V3 service index, RubyGems API,
  Composer v2 repository), or turn lookups off with `PKGMETA_ENABLED=false`
  (component freshness then stays unknown).

The policy engine reads the same data (`pkgmeta.Repository.Info`), so "outdated"
and "versions behind" conditions match what the UI shows.

### Component integrity

A component's SBOM hashes are checked against the digests its registry
publishes for that version: npm (`dist.integrity` SHA-512 + `shasum`),
PyPI (each file's SHA-256, covering the wheels and the sdist), crates.io (`checksum`),
and RubyGems (each platform build's SHA-256). The check runs whenever the package metadata is
fetched (the `PKGMETA_*` schedule, and on SBOM upload). Components get
`integrity`: `verified` (a hash matches), `mismatch` (a hash the registry also
publishes disagrees, meaning **the artifact you ship isn't the one the registry served**), or empty for
unknown (no comparable hash; Maven, Go modules and Composer publish none we can
compare). Filter with `?integrity=mismatch|verified|unknown`, fail a policy on
`integrity is mismatch`, or use `component.integrity` in a CEL expression.
Unknown matches neither.

### AI inventory (ML-BOM)

A CycloneDX ML-BOM upload is part of the same inventory as every other SBOM.
Components of type `machine-learning-model` get `kind: model`, type `data` gets
`kind: dataset`, and every other component gets `kind: software`. A service in
the SBOM that serves a model (linked to a model component by a dependency in
either direction) or calls a known model-provider API (OpenAI, Azure OpenAI,
Anthropic, Bedrock, Vertex/Gemini, Mistral, Cohere, Hugging Face inference,
Groq, Together, DeepSeek, xAI, Perplexity, Replicate) also gets an inventory row
of `kind: ai-service`. It stays in the snapshot's services too, and the graph
and the BOM export show it only as the service.

AI components carry their model-card essentials as `ml`: supplier,
manufacturer, publisher, description, the model card's approach, task,
architecture family, model architecture, datasets (a `ref` to a data
component resolves to its name), input/output formats, a dataset's contents,
pedigree ancestors (the base model) and external references (the model hub
URL). An AI service carries its provider and endpoints. Licenses resolve as
for any component. `?kind=ai` (or a single kind) filters `/components`,
`/projects/{id}/components`, `/sboms/{id}/components` and their exports, which
add Kind, Supplier, Model task and Datasets columns. In the UI, the Kind filter
and AI inventory view (components page, project Components tab, the SBOM tab's
*AI inventory* link, a snapshot's Components) show kind badges that open the
model card. Diff and history work unchanged. The CycloneDX export writes models
and datasets back with their model card, supplier, publisher, pedigree, data
and external references, so re-uploading it gives the same AI inventory.

Policies evaluate AI components with their own subjects (next section), so "a
model that isn't on the approved list" is a policy finding:
`model.name no_match ["mistralai/*", "google/flan-t5-*"]`. Like every policy
violation, it auto-closes when the next SBOM no longer ships the model.

### Component policies

Dependency-Track-style policies over SBOM components, managed under Policies in
the UI or `/api/v1/policies`. Mutations require instance admin; anyone can read
policies and dry-run a draft over their own projects. A policy has a set of
conditions combined with `any` / `all`, a violation state (`fail` → high,
`warn` → medium, `info` → low finding severity), a scope (global, or a list of
projects) and the versions it evaluates: `all` (every version with an SBOM, the
default) or only the `default` version.

The scope can be narrowed by project tags. With `include_tags`, a project must
carry at least one of them. With `exclude_tags`, it must carry none of them. For
example, "every project except `internal-tool`" is a global policy with
`exclude_tags: ["internal-tool"]`, with no project list to maintain. Editing a
project's tags re-evaluates that project, so its violations open or close
(auto-close, like any other finding) as it enters or leaves a policy's scope.
Gate and SLA policies have their own scoping and don't take tags.

| Kind | Subjects |
|------|----------|
| Security | `severity` (worst vulnerability ≥), `vulnerability_id` (is / glob), `kev`, `epss` (≥), `cwe` (in) |
| License | `license` (SPDX id globs: `is` = deny, `is_not` = allow-list), `license_group` (`in` / `not_in` a group id or `category:Copyleft`…), `license_unresolved` |
| AI (ML-BOM) | `component.kind` (`in` / `not_in` software, model, dataset, ai-service), `model.name` (name or `group/name` globs: `no_match` = approved list, `matches` = deny), `model.supplier` (supplier / manufacturer / publisher globs: `not_in` = approved, `in` = deny), `model.license` (as `license`, models and AI services only), `model.task` (`in` / `not_in` globs), `dataset.name` (a dataset's name or a model's training datasets: `no_match` = approved, `matches` = deny) |
| Operational | `outdated`, `versions_behind` (≥), `age` (days since this version's release ≥), `missing_hash` (`any` / `strong` = no SHA-256+), `integrity` (`mismatch` / `verified` against the registry's published digests), `coordinates` (group/name/version globs or a version range like `>=1.2.0, <2.0.0`), `purl` (glob), `package_type` (purl type in list) |

- License semantics follow the SPDX expression, not substrings. A deny is
  violated only when the component can't be used *without* a listed license:
  `MIT OR GPL-3.0-only` passes "deny GPL-3.0*", `MIT AND GPL-3.0-only` doesn't.
  `WITH` exceptions are judged by their license. An allow-list (`is_not` /
  `not_in`) is violated when the expression can't be satisfied by allowed
  licenses alone.
- Unknown doesn't decide. A component with no license, no vulnerabilities or
  no registry metadata (or, for the AI subjects, a software component or a
  model card that doesn't state the fact) doesn't match the condition about it.
  An unknown package is neither outdated nor up to date. A version whose
  components' licenses haven't been resolved yet is left untouched until they are.
- Facts: vulnerabilities by the same rule as the components' `vuln_count`
  (advisory matches + non-false-positive scanner findings, with their KEV/EPSS/CWE,
  but not the policy engine's own findings); licenses from *License data*;
  freshness from *Outdated components*.
- Violations are findings: scanner `policy`, `rule_id` = the policy id,
  category `license` when every matched condition is a license one (so the gate's
  `block_license` covers them), else `sca`. There is one per (policy, component
  version), on the version whose current SBOM ships it, with the matched
  conditions and facts in `metadata`. Triage, gates, SLA and new-critical alerts
  apply unchanged. Each evaluation applies the complete set, so a violation that
  stops applying (the component upgraded or removed, the policy edited, disabled
  or deleted) auto-closes, while triaged ones keep their state. Fail-state
  violations an evaluation introduces also send one `policy.violation`
  notification per project.
- When: on every SBOM upload (and again once its advisories are matched),
  after each policy change (affected projects, in the background), every
  `POLICY_EVAL_INTERVAL` (6h, because KEV/EPSS, outdated and license data change
  without an upload) and on `POST /policies/evaluate`.
- `POST /policies/preview` dry-runs a draft. `GET /policies/{id}/violations` and
  `GET /projects/{id}/policies` show what is currently violated.

Replacing `LICENSE_DENYLIST`. The static denylist is gone (setting it only
logs a warning). Migration `000040` seeds the global `warn` policy "Strong
copyleft licenses" (`license is AGPL-3.0*, GPL-2.0*, GPL-3.0*`), which is the old
default with deliberate differences: ids match the parsed expression rather
than substrings (LGPL is no longer caught as "GPL-3.0"; a dual license with a
permissive branch passes), violations are per component version, and they
auto-close. Existing `license-policy` findings are carried over to it in place.
They are the same rows, so status, risk acceptances and their history survive.
Untriaged leftovers that no longer map are closed. Recreate a custom denylist
as a policy (or edit the seeded one).

Expressions (CEL). When the fixed conditions can't express a rule, a policy
condition (subject `expression`) and a triage rule (`expression`) take a
[CEL](https://cel.dev) expression. Dependency-Track 5 and Kubernetes use the
same language for this:

```
vulns.kev && pkg.versions_behind >= 3                                  # policy
component.purl.startsWith("pkg:npm/") && "GPL-3.0-only" in component.license.ids
finding.cvss >= 9 && "internet-facing" in finding.tags                 # triage rule
finding.dep_direct == false && finding.severity == "low"
```

Policies see `component` (type, kind, group, name, version, purl, hashes, license.raw /
expression / ids / resolved), `vulns` (count, ids, max_severity,
max_severity_rank 5–0, kev, kev_sources, epss, cwes), `pkg` (known, latest, outdated,
versions_behind, age_days), `model` (suppliers, task, architecture_family,
datasets; empty / null when unknown) and `project` (name, version, default_version, custom). Triage
rules see `finding` (scanner, category, rule_id, title, severity, status, cve, cwe,
cvss, epss, kev, kev_sources, kev_ransomware, package, version, fixed_version, purl, file_path, url, tags,
dep_direct, dep_depth, dep_scope, custom) and `project` (criticality, custom). `custom.<key>`
is a defined custom field. A misspelled or undefined one is refused on save. An unset
one is absent and does not match; `has(finding.custom.team)` tests for it. An unknown fact is
`null`, and anything that can't be evaluated is no match. So `pkg.outdated`
and `!pkg.outdated` are both false for a package the registry doesn't know. This is the
same "unknown doesn't match" rule as every other condition. Expressions are checked
on save: a syntax error, a misspelled field, a non-boolean result, or an expression too
expensive to run per component returns a 400 that explains the problem. The inputs are
plain JSON-shaped documents, so an external engine (OPA) could later be given the
same ones. There is one built-in language, not two.

### Reachability: why most of a dependency backlog doesn't matter

Most vulnerabilities in a dependency list are irrelevant for reasons unrelated
to exploitability: the package is build/test-only and doesn't
ship, or it's a transitive dependency deep in a tree nobody chose. Both
facts are already in the SBOM you uploaded (CycloneDX's
`dependencies` graph and component `scope`, SPDX's `DEPENDS_ON` /
`DEV_DEPENDENCY_OF` relationships), so we read them instead of discarding them.

Each finding carries `dep_direct`, `dep_depth` and `dep_scope`, matched from the
project's current inventory, and priority is scaled accordingly:

| Dependency | Multiplier |
| ---------- | ---------- |
| direct, ships | 1.0 |
| transitive | × 0.8 |
| optional | × 0.5 |
| dev / test-only | × 0.25 |

So three identical `critical` CVEs rank 15 (direct runtime), 12 (transitive) and
3.75 (dev-only). Two rules make this safe:

- Unknown is not discounted. An SBOM with no dependency graph leaves the
  finding at full priority. Absence of evidence is not evidence of safety.
- It discounts but does not suppress. A KEV'd critical in a transitive dev
  dependency still scores 9, above a quiet shipped `medium`. Reachability
  removes noise without hiding an emergency.

Filter with `?reachable=true` (ships and direct), `?direct=true`, or
`?scope=dev`. Auto-triage rules can condition on `dep_scope` / `dep_transitive`,
so *"suppress vulnerabilities in dependencies that never ship"* is one rule, and
it is usually the largest single reduction in the backlog. Uploading a new SBOM
re-scores the project's existing findings, because a package can move from direct
to transitive between releases.

This is deliberately not call-graph reachability (whether the vulnerable *function* is
invoked). That needs program analysis, i.e. a scanner, which we don't build. This
is the ~80% you get for free from a file you already have.

### Asset exposure and relationships

An asset records where it can be reached from: `exposure` = `internet`,
`internal`, `isolated`, or unknown (null). This multiplies the priority of
every finding on the asset, the same way reachability does:

| Exposure | Multiplier |
| -------- | ---------- |
| internet | × 1.25 |
| internal | × 1.0 |
| unknown  | × 1.0 (not discounted) |
| isolated | × 0.75 |

The isolated discount is bounded. A KEV'd critical in a transitive dev dependency
on an isolated host still scores 6.75, which is above a quiet `medium` on an
internet-facing asset (3.75). Findings show it as `asset_exposure`.

Exposure is set by hand (`PUT /assets/{id}/exposure`, editor; `exposure_source =
manual`, with a reason) or inferred at ingest from the scan's live findings
(`exposure_source = inferred`, with the evidence in `exposure_reason`):

- Cloud public exposure ⇒ `internet`: a failing check meaning the resource is
  public. This covers Prowler checks that Prowler itself classifies
  `internet-exposed` (for older reports without categories, check ids naming
  `public`/`internet`, but not a `…public_access_block` setting); ScoutSuite rules
  naming public/world/allUsers or opening a port `…-to-all`; AWS Security Hub FSBP
  controls that fail only for public resources (S3.2/3, EC2.1/9/13/14/18/19,
  RDS.1/2, Lambda.1, ES.2, Redshift.1, EKS.1, …) and CIS 4.1/4.2. It applies to the
  scan's asset and to any project asset whose `identifier` is the flagged
  resource's id or ARN.
- A DAST / network finding ⇒ `internal`: the scanner reached the asset over
  the network, so it isn't isolated. Where the scanner ran is unknown, so this is
  not proof of internet exposure.

Inference only raises exposure and does not override a manual value. An inferred
exposure stays until someone changes or clears it (clearing makes it unknown and
open to inference again).

Relationships are typed edges read as `from <kind> to`: `built_from` (an app
image built from a base image), `deployed_as` (an image running as a workload) and
`depends_on` (informational). They may cross projects. Creating one requires editor
on this asset's project and visibility of the other. `GET
/assets/{id}/blast-radius` walks everything that inherits an asset's content
(assets built from it, transitively, and what they're deployed as) and lists each
one's open findings that share a CVE or package with it. For example, open a
vulnerable base image to see every image and workload carrying the same bug. Assets
in projects you can't see are left out.

`built_from` can be suggested from stored SBOMs (`…/relations/suggestions`).
For container images whose SBOM `artifact` matches the asset's identifier or name,
an image whose whole OS package set (deb/apk/rpm, same versions, ≥ 5 packages) is
contained in another's is proposed as its base. SBOMs keep no layer digests, so
this is package-set evidence, not layer provenance. Suggestions are not stored
until accepted.

### VEX: analyse a vulnerability once

A scanner can only tell you a vulnerable package is present. It cannot know
whether the vulnerable code path exists in your build, or that you disabled the
feature that reaches it. That judgement, whether from an upstream vendor or from your own
team, is what VEX records, and Xila keeps it:

```bash
curl -X POST "$XILA/api/v1/projects/$PROJECT/vex" \
     -H "Authorization: Bearer $TOKEN" --data-binary @openvex.json
# {"statements":[…], "findings_resolved": 1}
```

Upload an OpenVEX or CycloneDX VEX document (auto-detected). Statements are
stored per project and re-applied on every ingest. This matters because
the scanner will keep reporting that CVE, and Xila keeps answering "we
already looked at that". Without this, every scan puts the same finding back on
the queue and someone re-derives the same conclusion.

| VEX status | What happens to the finding |
| ---------- | --------------------------- |
| `not_affected` / `fixed` | → `false_positive`, with the justification and `vex` recorded in its audit trail |
| `affected` | → `confirmed`. An upstream "yes, this affects you" is the strongest triage signal available |
| `under_investigation` | nothing |

A statement naming a specific product (PURL) takes precedence over a project-wide statement about
the CVE. `not_affected` becomes a triage state rather than "remediated",
because remediated means the scanner stopped reporting it, and the finding would be reopened
as soon as the next scan saw the package again. A triage state is sticky, which is
what a durable analysis needs. Delete the statement (`DELETE /vex/{id}`)
and the verdict is no longer asserted.

#### Exporting VEX and BOMs

In the other direction, `GET /projects/{id}/vex/export?format=openvex|cyclonedx|csaf`
publishes the project's analysis (default version, or `?branch=` / `?version_id=`)
as OpenVEX v0.2.0, CycloneDX VEX (1.6, or 1.7 with `&spec=1.7`) or
CSAF 2.0 (`csaf_vex` profile). All three can be imported back: uploading a CSAF VEX
document (Xila's or a vendor's, e.g. Red Hat's) resolves its product ids through
the product tree to the component purls. There is one statement per (vulnerability, product), built from the version's
non-duplicate findings that carry a CVE (or a CVE/GHSA rule id) and merged with the
stored statements above. A stored statement that no current finding covers is exported
as stored.

| Finding status | VEX status | Carries |
| -------------- | ---------- | ------- |
| `false_positive` | `not_affected` | the stored justification when a VEX statement triaged it (or `fixed`, if that statement said fixed); otherwise the exception reason as `impact_statement`. A justification code is not invented |
| `remediated` | `fixed` | |
| `confirmed` | `affected` | action: "Upgrade to *fixed version*" (CycloneDX response `update`, CSAF `vendor_fix`), else `none_available` |
| `risk_accepted` / `wont_fix` | `affected` | action: the exception reason and expiry (`will_not_fix`, CSAF `no_fix_planned`) |
| `open` | `under_investigation` | |

The product is the package purl. For a package the scanner gave no purl, it is
`pkg:generic/<name>@<version>`. A finding with no package at all (and a
project-wide stored statement) is attributed to the project version itself,
`pkg:generic/<project-slug>@<version-name>`. When several findings refer to the
same pair, the most cautious verdict wins (affected > under_investigation > fixed >
not_affected). Timestamps are each finding's latest status change, or else its last
sighting. The OpenVEX `@id` is stable per project version (built from `PUBLIC_URL`
when set). The author is the requesting user. Justifications are translated between
the OpenVEX/CSAF and CycloneDX vocabularies. Uploading an export to another project
with the same findings reproduces the verdicts, except for statements about the
project product, which name no package and so match no finding on import.

`GET /sboms/{id}/export` downloads any snapshot as a CycloneDX BOM (1.6, or
1.7 with `?spec=1.7`; 1.7 only adds optional fields, so the content is the same). The export contains the root
as `metadata.component` (timestamp = snapshot time), every component with its
original bom-ref, purl, licenses and hashes, every service (re-nested) with its
endpoints, authentication, trust boundary/zone and data flows, and the dependency
graph. Unless
`?vulnerabilities=false` is set, it also includes the vulnerabilities `GET /sboms/{id}/vulnerabilities`
reports, each with its severity, `affects` refs and the `analysis` that the project's
triage on that version amounts to (none when untriaged; a `remediated` finding says
nothing about an immutable snapshot that still ships the package). Re-uploading the
export reproduces the same inventory, services and dependency edges (a service
provider's contacts and 1.6 `tags` aren't kept).

### Findings ↔ components (one tool, not two)

`GET /findings/{id}/components` correlates a vulnerability to the SBOM
component that introduced it. It matches within the finding's project by package
name + version (stable across tools) and falls back to PURL. This lets
the DefectDojo-style finding view and the Dependency-Track-style SBOM view
work as a single product: from a CVE you can go to the dependency,
and from a dependency you can see which projects ship it. Non-package findings
(secrets, IaC, most SAST) return no components.

### Compliance posture

`GET /projects/{id}/compliance` turns findings into framework posture: each
control passes unless an open finding maps to it, and the score is the
share of passing controls. Mappings are by CWE (tool-agnostic, so it works with
any scanner that emits CWEs) or by scanner rule (`scanner` + `rule_id`, ready
for Prowler/CIS). OWASP Top 10 (2021) ships seeded and mapped by CWE, so a
Semgrep/Trivy finding with `CWE-79` shows OWASP A03 (Injection) as
failing. To add a framework, insert rows into `frameworks` / `controls` /
`control_mappings`. No code changes are needed.

Beyond CWE and rule, a mapping can test an open finding's state (`kev`: on CISA
KEV; `sla`: past its remediation deadline) or a project fact (`sbom`: an SBOM on
the default branch; `vex`: vulnerability analysis documented as VEX statements or
assessments). A control marked `manual` (a process requirement no scan can judge)
is not scored and is not shown as passing. Each control reports `status`
(`passing` / `failing` / `manual`) and the `evidence` behind it.

More frameworks. Seeded alongside OWASP Top 10 and EU CRA, mapped the same
way (CWE first, scanner rules for Prowler / Checkov / KICS / Trivy config, plus the
`category` and `severity` match types), with everything a scan can't judge marked
`manual`:

| Key | Framework |
|---|---|
| `owasp-asvs-5.0` | OWASP ASVS 5.0 (V1–V17): requirement level where OWASP's own ASVS 5.0 CWE mapping gives a CWE, section level (manual) otherwise |
| `pci-dss-4.0` | PCI DSS 4.0.1: secure configuration (2.2), secure development (6.2–6.4), authentication, vulnerability scanning (11.3), the rest manual |
| `iso-27001-2022` | ISO/IEC 27001:2022 Annex A: the technological controls (A.8) a scan evidences (vulnerabilities, secure coding, configuration, cryptography, logging), the rest manual |
| `soc2` | SOC 2 Trust Services Criteria: CC6.x, CC7.x, CC8.1 mapped, the rest manual |
| `nis2` | NIS2 Directive Article 21(2)(a)–(j): (e) vulnerability handling, (h) cryptography, (i)/(j) access control and MFA mapped, the rest manual |

Titles are short paraphrases; the ISO, PCI and AICPA texts are not
reproduced.

Attesting manual controls. On the Compliance tab, each framework's *Manual
controls* list records how a process requirement is met:
`PUT /projects/{id}/compliance/{framework}/attestations/{code}` with a `note`, an
optional `evidence_url` and an optional `expires_at` (editor). A live attestation
scores the control as passing ("attested by …"); an expired one returns it to
`manual`. `DELETE` removes it. Changes are recorded in the audit log.

Evidence reports. `GET /projects/{id}/compliance/{framework}/report` (the
*Evidence report* button on each framework) prints, for any framework, the posture
per control with the open findings behind each failing one, the attestations, the
SBOM and vulnerability-handling evidence, and for `eu-cra` the Article 14 section.

EU Cyber Resilience Act. The `eu-cra` framework covers Annex I of Regulation
(EU) 2024/2847. It maps Part I's measurable requirements to weakness classes
(I.2(d) unauthorised access ← CWE-284/287/798/…, I.2(e) confidentiality ←
CWE-311/319/327/…, …), I.2(a) "no known exploitable vulnerabilities" to KEV, II.1
SBOM to `sbom`, II.2 remediate without delay to `sla`, and II.4 to `vex`. The
process requirements (disclosure policy, update distribution, …) are manual.
`GET /projects/{id}/compliance/eu-cra/report` (Compliance tab → *Evidence report*
on the CRA card) prints the evidence, including the Article 14 reporting section. It contains per-requirement status and the reason for it, the default branch's SBOMs
(components, purl / hash / license coverage, integrity mismatches), open findings
by severity, KEV, SLA compliance and MTTR, documented analysis, and the manual
requirements with space to record how each is met.

CRA Article 14 reporting. From 11 September 2026, a manufacturer must report
every *actively exploited* vulnerability in a product with digital elements to
the CSIRT designated as coordinator (of its main establishment) and to ENISA,
through the single reporting platform. Three reports are required:

- an early warning within 24 h of becoming aware, naming the Member States the product is available in;
- a vulnerability notification within 72 h, covering the nature of the exploit and the vulnerability, corrective and mitigating measures, and how sensitive the information is;
- a final report within 14 days of a corrective or mitigating measure becoming available, covering a description with severity and impact, the malicious actor where known, and the security update.

An owner marks a project `cra_in_scope` on its Compliance tab and enters the product's name, version and
Member States. The manufacturer is set in instance config (`CRA_MANUFACTURER_*`).

A case opens when an open, default-branch, non-duplicate finding of an in-scope project is
KEV-listed or has a weaponized exploit. There is one case per (project, vulnerability), where the vulnerability is the lowest CVE, or the rule id if there is no CVE. A case opens at any of these points: when enrichment or exploit
intel flags the finding, on the leader sweep (`CRA_SWEEP_INTERVAL`, 15 min), when the
project is brought into scope, or manually for exploitation Xila can't see. The
clock runs from that awareness time in absolute hours (+24 h, +72 h). The final
report's 14 × 24 h start when the finding gets a fixed version or is remediated,
or when an editor records the measure. States: `open → early_warning_sent →
notification_sent → final_report_sent → closed`, or `dismissed` with a reason
(owner only; for example, the vulnerable code isn't in the shipped product). Each submission
is recorded with who, when, the platform's reference and the payload as sent.
The sweep queues `cra.case_opened`, `cra.deadline_due_soon` (6 h before) and
`cra.deadline_missed` through the notification outbox, once per case and stage.
`GET /cra/cases/{id}/report?stage=…` exports the stage's payload. This is a draft
structure for the ENISA platform, because the platform's format comes from Commission
implementing acts (Art. 14(10)). `missing` lists what the stage still needs.
The CRA evidence report lists every case with each stage's deadline compliance
(met / late / missed / pending), and `/cra` lists the cases of every project you
can see. Severe incidents (Art. 14(3)) are not tracked.

### Portfolio rollup

`GET /portfolio` aggregates the whole estate for an exec view: project count,
total open findings, business-weighted risk score, exploitable/KEV counts,
open findings by category (appsec, SCA, secrets, cloud, k8s…), each
framework's average compliance score across projects, and the top-risk
projects. It backs the dashboard on the UI home page.

### Metrics history & trends

Posture is recorded daily in `metric_snapshots`, with one row per UTC day for every
project, team, org and the portfolio. Each row holds open findings by severity, new (first seen
that day), closed (remediated that day), risk score (the project summary's
definition, summed), SLA breaches at day end, SLA met/missed for that day's
fixes, and MTTR inputs. Every figure is additive, so a non-admin's portfolio
trend is the sum of the projects they can see (likewise an org trend for an
org member), not the instance-wide row. As with every metric, only each project's
default version counts and cross-tool duplicates are excluded.

The `METRICS_SNAPSHOT_INTERVAL` job (1h; also at startup and via
`POST /metrics/snapshot`) recomputes yesterday, closing it out, and
today, whose numbers match the live project summary. On the first run it
reconstructs the last 90 days so charts aren't empty on day one. Those points are
flagged `reconstructed` and drawn faded in the UI. Snapshots are computed from
each finding's lifecycle timestamps:

- A finding is open at the end of a day if it was first seen before then and is open now or was resolved later.
- A finding reopened and closed again counts by its latest resolution.
- A finding in an exception (risk accepted, false positive, won't fix) stops being open when the exception was set.
- Severity and SLA due date are the current ones.

Days with no snapshot (the server was down) are omitted from trends, not zero-filled.

`GET /metrics/trends?days=90` (and `/projects|teams|orgs/{id}/metrics/trends`)
returns `{days, points: [...]}`, oldest first. `sla_compliance` is the 0–1 share
of that day's SLA-tracked fixes made on time, and `mttr_days` is the mean days from first
seen to fixed. Both are `null` when nothing qualifying was fixed.

### Exports & reports

CSV / Excel. Every findings and components listing has an `/export` twin
that takes the same filters and returns the whole filtered set as a
download (`?format=csv`, the default, or `?format=xlsx`):
`GET /findings/export`, `/projects/{id}/findings/export`, `/components/export`,
`/projects/{id}/components/export` and `/sboms/{id}/components/export`. They
share the listing's query (same RBAC scope, same default-branch and
duplicate rules, same sort), so the file matches the screen. Rows stream
from one database cursor straight into the response, capped at 100,000. A
capped file carries `X-Truncated: true`, and the UI says so. Findings columns: id,
project, branch, scanner, category, rule, severity, priority, status, title,
CVEs, CWE, CVSS, package, version, fixed version, `file:line`, URL, first/last
seen, resolved, SLA due + status, assignee, EPSS, KEV, exception reason/expiry.
CSV text cells a spreadsheet would evaluate (leading `=` `+` `-` `@`, tab, CR)
get a leading `'`, so a finding titled `=HYPERLINK(…)` can't run for whoever opens
the file. The `.xlsx` is written by a ~200-line SpreadsheetML writer
(`internal/export`, `archive/zip` + `encoding/xml`, no dependency): inline
strings (no formulas), real numbers / booleans / dates, and a bold frozen header.

Reports. `GET /projects/{id}/report` and `GET /portfolio/report` (scoped to
the projects you can see) return a self-contained, print-optimized HTML page
(inline CSS, no scripts or external assets, `@media print` page breaks). It includes the
risk score, open findings by severity, SLA posture (breached, due soon,
on-time share, MTTR), the top 20 findings by priority with KEV/EPSS flags,
compliance per framework, which branches are covered (the default only) and, for
the portfolio, a per-project table. Every value goes through `html/template`, and
the page is served with a CSP that forbids scripts.

Report templates (`/report-templates`; read: everyone, write: instance admin)
brand and lay out those reports. You can set a brand line, a logo (an inline PNG/JPEG/SVG `data:`
URI, so the report still fetches nothing), an accent colour, a classification banner
("Confidential"), an intro (scope, methodology) and a footer. You can also choose which sections appear
and in which order (`summary`, `severity`, `compliance`, `findings`, `details`
(per-finding write-ups with steps, impact, mitigation and references),
`projects`), a minimum severity, and how many findings to list. Pick a template with
`?template=`. `GET /projects/{id}/report?engagement_id=` is an engagement
report, the pentest deliverable. It covers the engagement's findings on every branch, in any status
except false positive, with the summary figures labelled as project-wide.

README badges. A project owner issues a badge token on the project's Gate
tab (`POST /projects/{id}/badge-token`). The token is shown once, with ready-made Markdown.
Rotate it to replace it, or use `DELETE` to revoke it. After that,
`GET /api/v1/badges/{token}/findings.svg` (open findings, worst two severities),
`gate.svg` (security-gate verdict) and `sla.svg` (breaches, otherwise on-time share)
are public SVGs, cached for five minutes. The token is the only secret, and only its
SHA-256 is stored. An unknown, rotated or revoked token returns the same neutral
"unknown" badge with 404, so it can't be used to probe projects. Links use
`PUBLIC_URL` when set.

PDF is the browser's job. The server has no PDF engine (no headless
Chrome, no PDF library, nothing to patch). The UI's *Report → Download PDF*
opens the report and calls `window.print()`, and the browser's *Save as PDF*
produces the file from the print stylesheet. Use *Report → Open report* to read
it on screen, or `curl` the endpoint for the HTML.

### Scanners & formats

Xila doesn't scan anything itself. It ingests the output your tools already produce. Native
parsers are selected by `?scanner=`:

| Tool | `?scanner=` | Produce with | Category |
| --- | --- | --- | --- |
| Trivy | `trivy` | `trivy fs --format json -o out.json .` | SCA / secrets / IaC |
| Grype | `grype` | `grype dir:. -o json` | SCA |
| OSV-Scanner | `osv-scanner` | `osv-scanner --format json -r .` | SCA |
| npm audit | `npm-audit` | `npm audit --json` | SCA |
| OWASP Dependency-Check | `dependency-check` | `dependency-check --format JSON` | SCA |
| govulncheck | `govulncheck` | `govulncheck -json ./...` | SCA (call-graph reachability) |
| Gitleaks | `gitleaks` | `gitleaks detect --report-format json` | secrets |
| TruffleHog | `trufflehog` | `trufflehog filesystem . --json` | secrets (verified = live credential) |
| OWASP ZAP | `zap` | `zap-baseline.py -t $URL -J out.json` | DAST |
| Nuclei | `nuclei` | `nuclei -u $URL -jsonl` | DAST |
| Prowler | `prowler` | `prowler aws -M json` | cloud (CSPM) |
| Kubescape | `kubescape` | `kubescape scan --format json` | Kubernetes (KSPM) |
| kubeaudit | `kubeaudit` | `kubeaudit all -f manifest.yaml -o json` | Kubernetes (KSPM) |
| Checkov | `checkov` | `checkov -d . -o json` (one framework or a list) | IaC |
| tfsec | `tfsec` | `tfsec . --format json` | IaC |
| Terrascan | `terrascan` | `terrascan scan -o json` | IaC |
| ScoutSuite | `scoutsuite` | `scout aws` → `scoutsuite_results_*.js` | cloud (CSPM) |
| Clair | `clair` | `clairctl report --out json $IMAGE` (or clair-scanner JSON) | container |
| Anchore Enterprise | `anchore` | `anchorectl image vulnerabilities $IMAGE -o json` | container |
| Docker Scout | `docker-scout` | `docker scout cves --format sarif $IMAGE` | container |
| Polaris | `polaris` | `polaris audit --format json` | Kubernetes (KSPM) |
| kube-bench | `kube-bench` | `kube-bench --json` | Kubernetes (KSPM) |
| Burp Suite | `burp` | *Report selected issues → XML* | DAST |
| Nikto | `nikto` | `nikto -h $URL -Format json` (or `xml`) | DAST |
| Wapiti | `wapiti` | `wapiti -u $URL -f json -o out.json` | DAST |
| Nmap | `nmap` | `nmap -sV --script vulners -oX out.xml $HOST` | DAST (network) |
| Snyk Open Source | `snyk` | `snyk test --all-projects --json > out.json` | SCA |
| pip-audit | `pip-audit` | `pip-audit -r requirements.txt --format json -o out.json` | SCA |
| Safety | `safety` | `safety check --output json > out.json` | SCA |
| cargo-audit | `cargo-audit` | `cargo audit --json > out.json` | SCA |
| Retire.js | `retirejs` | `retire --outputformat json --outputpath out.json` | SCA |
| bundler-audit | `bundler-audit` | `bundle-audit check --format json --output out.json` | SCA |
| Semgrep (native) | `semgrep` | `semgrep scan --json -o out.json` | SAST / SCA |
| Bandit | `bandit` | `bandit -r . -f json -o out.json` | SAST |
| gosec | `gosec` | `gosec -fmt json -track-suppressions -out out.json ./...` | SAST |
| Brakeman | `brakeman` | `brakeman -f json -o out.json` | SAST |
| detect-secrets | `detect-secrets` | `detect-secrets scan > .secrets.baseline` | secrets |
| ggshield | `ggshield` | `ggshield secret scan repo . --json > out.json` | secrets |
| DefectDojo Generic Findings Import | `defectdojo-generic` | `{"findings":[…]}` JSON (migration from DefectDojo) | any |
| Hadolint | `hadolint` | `hadolint -f json Dockerfile` | IaC |
| KICS | `kics` | `kics scan -p . --report-formats json` | IaC |
| ESLint | `eslint` | `eslint -f json .` | SAST |
| yarn audit | `yarn-audit` | `yarn audit --json` / `yarn npm audit --json` | SCA |
| njsscan | `njsscan` | `njsscan --json -o out.json .` | SAST |
| Bearer CLI | `bearer` | `bearer scan . --format json` | SAST |
| MobSF / mobsfscan | `mobsf` | MobSF `report_json`, `mobsfscan --json` | SAST (mobile) |
| SonarQube | `sonarqube` | `GET /api/issues/search?types=VULNERABILITY`, `/api/hotspots/search` | SAST |
| Checkmarx CxSAST | `checkmarx` | detailed XML report | SAST |
| Veracode | `veracode` | detailed XML report | SAST / DAST / SCA |
| Mend (WhiteSource) | `mend` | platform API 3.0 / legacy / CLI JSON | SCA |
| JFrog Xray | `jfrog-xray` | Unified vulnerabilities JSON | SCA |
| AWS Inspector2 | `aws-inspector2` | `aws inspector2 list-findings` | cloud / container |
| AWS Security Hub | `aws-security-hub` | `aws securityhub get-findings` (ASFF) | cloud |
| Tenable Nessus | `nessus` | `.nessus` XML or CSV export | DAST (network) |
| OpenVAS / Greenbone | `openvas` | XML report | DAST (network) |
| Qualys VM | `qualys` | scan report XML or CSV | DAST (network) |
| Acunetix / 360 | `acunetix` | XML export or Acunetix 360 JSON | DAST |
| Invicti / Netsparker | `invicti` | JSON report | DAST |
| testssl.sh | `testssl` | `testssl.sh --csvfile out.csv $URL` | DAST (TLS) |
| CryptoLyzer | `cryptolyzer` | `cryptolyze --output-format json tls all $HOST:443` | DAST (TLS, checked against BSI TR-02102-2) |
| drHEADer | `drheader` | `drheader scan single $URL --output json` (or `scan bulk`) | DAST (HTTP security headers) |
| SecObserve | `secobserve` | `GET /api/observations/?product=<id>` JSON, or SecObserve import format | any |
| Nancy | `nancy` | `nancy sleuth --output=json < go.list` | SCA (Go) |
| CloudSploit | `cloudsploit` | `cloudsploit-scan --json` | cloud (CSPM) |
| Steampipe / Powerpipe | `steampipe` | `steampipe check <benchmark> --export=out.json` | cloud (CSPM) |
| Arachni | `arachni` | `arachni_reporter --reporter json scan.afr` | DAST |
| SpotBugs | `spotbugs` | `spotbugs -xml -output out.xml` | SAST |
| Fortify | `fortify` | upload `audit.fvdl` or the `.fpr` results archive | SAST |

Import formats carry triage, conservatively. DefectDojo `false_p`/`risk_accepted`/
`out_of_scope`/`verified`, SecObserve assessments, Safety policy ignores, audited
detect-secrets baselines, justified `#nosec` and Brakeman ignores are stored in
`metadata.remote_triage`. They are applied only to findings that the upload *created* and that are
still open, so re-importing does not overturn a local triage decision. Mitigated,
resolved and duplicate entries are skipped. See `docs/PARSERS.md`.

Some mappings are deliberate, because the tool provides less than it appears to:

- Nmap: every open port is an `info` finding (rule `open-port`), an
  exposure inventory that auto-closes when the port closes. `vulners` CVEs are matched on the
  service *version banner*, and distro backports often patch without changing it, so
  they carry `metadata.match = "service-version"` and a CVSS-derived severity.
  NSE `--script vuln` results in state `VULNERABLE` were actually probed.
- Nikto and kube-bench assign no severity. Nikto items are `low`;
  kube-bench `FAIL` is `medium` and `WARN` (a manual check to verify) is `low`.
  Raise specific checks with triage rules instead of relying on an invented gradient.
- Docker Scout's SARIF also loads through `format=sarif`, but only
  `?scanner=docker-scout` reads Scout's extensions (PURL, fixed version, CVSS). With it,
  findings dedup against other scanners and get EPSS/KEV.
- Clair: distro advisories (RHSA/DSA/USN) are the rule id. The CVEs they fix
  are extracted from the advisory name and links for dedup and enrichment.

Two of these provide a signal no other tool does:

- govulncheck does call-graph analysis, so it knows whether your code
  *calls* the vulnerable function. We ingest that result instead of computing it
  (program analysis is the scanner's job). A reachable vulnerability stays
  `high`; one whose code is not called is downgraded to `low` and labelled.
- TruffleHog *verifies* secrets against the provider. A verified secret is a
  working credential, so it is `critical` rather than "a string that looks like a key".

For any tool that emits SARIF (Semgrep, CodeQL, Checkov, Hadolint, KICS, …),
pass `?scanner=<tool>&format=sarif`. One parser handles them all, and the finding
keeps the real tool as its `scanner`, so dedup and auto-close stay per-tool. SARIF
severity comes from `security-severity` (falling back to `level`), and category is
inferred from rule tags. Use a native parser when the tool has one: SARIF drops
PURLs, fix versions and CVSS, which dedup and reachability need.

Adding a tool takes one file. See [docs/PARSERS.md](docs/PARSERS.md). It is a
good first contribution, and everything downstream (dedup, triage,
priority, compliance, gates) works on the normalized model without extra work.

```bash
semgrep --sarif -o semgrep.sarif .
curl -X POST "$API/projects/$PROJECT/scans?scanner=semgrep&format=sarif" \
  -H "$AUTH" -H 'Content-Type: application/json' --data-binary @semgrep.sarif
```

Cloud and Kubernetes posture tools (CSPM/KSPM) have native parsers that produce
`cloud` / `kubernetes` findings. Attribute them to the relevant asset with
`?asset_id=`:

| Tool | `?scanner=` | Produce with | Category |
| --- | --- | --- | --- |
| Prowler | `prowler` | `prowler aws -M json` (native JSON) | `cloud` |
| Kubescape | `kubescape` | `kubescape scan --format json` | `kubernetes` |
| kubeaudit | `kubeaudit` | `kubeaudit all -f manifest.yaml -o json` | `kubernetes` |
| ScoutSuite | `scoutsuite` | `scout aws` (results `.js`) | `cloud` |
| Polaris | `polaris` | `polaris audit --format json` | `kubernetes` |
| kube-bench | `kube-bench` | `kube-bench --json` | `kubernetes` |
| CloudSploit | `cloudsploit` | `cloudsploit-scan --json` (native JSON) | `cloud` |
| Steampipe / Powerpipe | `steampipe` | `steampipe check <benchmark> --export=out.json` | `cloud` |

Prowler's `CheckID` (and Kubescape's `controlID`, ScoutSuite's rule key, Polaris's
check id, kube-bench's CIS check number such as `1.1.1`) becomes the finding `rule_id`,
so it maps to compliance controls via `scanner`-typed `control_mappings`. The
CIS AWS Foundations Benchmark is seeded (migration `000011`) and mapped to
Prowler checks, so a failing Prowler check drives CIS compliance the same way a
CWE finding drives OWASP. See `/projects/{id}/compliance`.

To add a scanner, implement `scanner.Parser` (see `internal/scanner/trivy.go`,
`sarif.go`, `prowler.go`) and register it in `cmd/api/main.go`. New SBOM formats
fit into `sbom.Parse` the same way (see `internal/sbom/spdx.go`).

### Examples

```bash
API=http://localhost:8080/api/v1

# 1. Register + login -> capture the JWT
curl -s -X POST $API/auth/register -H 'Content-Type: application/json' \
  -d '{"email":"analyst@xila.io","password":"supersecret"}'
TOKEN=$(curl -s -X POST $API/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"analyst@xila.io","password":"supersecret"}' | jq -r .token)
AUTH="Authorization: Bearer $TOKEN"

# 2. Create an org (you become its admin), then a team and a project
ORG=$(curl -s -X POST $API/orgs -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"slug":"acme","name":"Acme"}' | jq -r .id)
TEAM=$(curl -s -X POST $API/orgs/$ORG/teams -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"slug":"platform","name":"Platform Team"}' | jq -r .id)
PROJECT=$(curl -s -X POST $API/teams/$TEAM/projects -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"slug":"web","name":"Web App","business_criticality":"high"}' | jq -r .id)

# 3. Ingest a Trivy report (raw JSON as the body)
trivy fs --format json ./myrepo > trivy.json
curl -s -X POST "$API/projects/$PROJECT/scans?scanner=trivy&branch=main&commit=abc123" \
  -H "$AUTH" -H 'Content-Type: application/json' --data-binary @trivy.json

# 4. Read the risk summary and the findings
curl -s -H "$AUTH" $API/projects/$PROJECT/summary
curl -s -H "$AUTH" "$API/projects/$PROJECT/findings?severity=critical&status=open"

# 5. Upload an SBOM, then find every project that ships a given package
syft ./myrepo -o cyclonedx-json > sbom.json
curl -s -X POST "$API/projects/$PROJECT/sboms?artifact=web&version=1.4.0" \
  -H "$AUTH" -H 'Content-Type: application/json' --data-binary @sbom.json
curl -s -H "$AUTH" "$API/components?name=log4j-core&version=2.14.1"
```

## Project hierarchy rollups

The project summary, `GET /projects/{id}/findings` (+ export),
`/components` (+ export), `/policies` and `/metrics/trends` accept
`?include_children=true|false`. The default is `true` for a collection and `false`
otherwise. With children included, results cover the project and all its descendants
under the usual rules (default version only, cross-tool duplicates excluded), and
counts are the sum of the children's. The summary's `project_ids` lists the projects
covered. Its risk score weights each project's findings by that project's own
criticality. A project-scoped API token does not roll up past its project.

## Service accounts and workload identity federation

A service account is a non-human principal: a user row of kind `service`
(email `<name>@service-accounts.invalid`) with no password, no sign-in, and no
admin flag. It takes roles the same way a person does, by that email on the org,
team or project members endpoints. Every RBAC rule applies unchanged, and its
actions are attributed to it (finding history names
`ci-web@service-accounts.invalid`). It authenticates in two ways:

- API keys issued by an admin (`/service-accounts/{id}/keys`). Keys always
  expire: 30 days by default, and no longer than `SERVICE_ACCOUNT_KEY_MAX_DAYS`.
  They can optionally be project-scoped. A service account can't mint its own.
- Workload identity federation (keyless). Admins trust an OIDC issuer
  (GitHub Actions, GitLab, a Kubernetes cluster; issuer URL + audience, keys
  from the issuer's JWKS via discovery, fetched through the outbound guard) and
  bind claim conditions (exact or glob, e.g. `repository=acme/web`,
  `ref=refs/heads/main`) to a service account and optionally one project. A
  job posts its identity token to `POST /api/v1/auth/token` (RFC 8693:
  `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`,
  `subject_token_type=urn:ietf:params:oauth:token-type:jwt`). Xila verifies the
  signature, `iss`, `aud`, `exp` and `nbf`, picks the matching binding, and returns
  `{access_token, issued_token_type, token_type: "Bearer", expires_in}`: a JWT
  for the service account valid for `FEDERATION_TOKEN_TTL` (≤ 1h). Every refusal is
  a `401 invalid_grant`. **A binding must pin the workload (`repository`,
  `project_path`, `sub`, … without a leading wildcard), because public issuers sign
  tokens for every repository on the platform.** Claims that match bindings to
  different accounts or projects are refused rather than resolved by order.

Suspending a service account takes effect on the next request: its sessions
stop validating (token version), its keys are deleted, and the exchange refuses
it. The admin UI is Admin › Service accounts. CI setup: [docs/CI.md](docs/CI.md#keyless-workload-identity-federation).

## Break the build in CI

A small stdlib CLI (`cmd/xila`, `make cli` or `go install github.com/xilasec/xila-api/cmd/xila@latest`)
uploads a scanner report and enforces the gate. A non-zero exit fails the build.
Auth is `--url/--token` or `XILA_URL`/`XILA_TOKEN` (use a project-scoped API token).
With no token, it works keyless: the CLI exchanges the CI job's OIDC identity token
(`--oidc-token`/`XILA_OIDC_TOKEN`, GitLab's `XILA_ID_TOKEN`, or GitHub Actions'
own with audience `XILA_OIDC_AUDIENCE`) for a short-lived session.

If your scanners aren't wired up yet, two templates run them from
their official images and upload every report: the GitHub Action
`xilasec/xila-api/ci/github/scan` (`scanners: trivy-fs,gitleaks,semgrep,…`) and
the GitLab template `ci/gitlab/xila-scan.gitlab-ci.yml` (`include:` + `extends:`).
See [docs/CI.md](docs/CI.md).

```bash
trivy fs --format json . > trivy.json
xila upload --project "$PROJ" --scanner trivy --gate trivy.json   # upload + gate, exits 1 on violations
xila upload --project "$PROJ" --scanner trivy --branch "$BRANCH" --gate trivy.json   # track + gate this branch
xila upload --project "$PROJ" --scanner trivy --release 1.4.0 trivy.json             # a release's findings
xila gate   --project "$PROJ" --max-critical 0 --block-kev        # ad-hoc gate, no stored policy needed
xila gate   --project "$PROJ" --branch feature/x                  # gate a branch (404 if never uploaded)
xila gate   --project "$PROJ" --block-sla-breach                 # fail while anything is past its remediation SLA
xila gate   --project "$PROJ" --new                              # PR check: fail only on newly-introduced findings
xila gate   --project "$PROJ" --new --baseline main               # …against what's live on main, not the single-scan heuristic
xila gate   --project "$PROJ" --max-risk-score 50                # fail if the weighted risk score exceeds 50
xila upload --project "$PROJ" --scanner trivy --gate --new --comment trivy.json   # …and comment on the PR
xila upload --project "$PROJ" --scanner trivy --gate --new --check trivy.json     # …and a GitHub check run with inline annotations
```

The repo also works as a GitHub Action (`action.yml`):

```yaml
permissions:
  pull-requests: write   # needed for the PR comment
  checks: write          # needed for the check run (comment: true by default; check: false)

steps:
  - uses: xilasec/xila-api@main
    with:
      url: https://xila.internal
      token: ${{ secrets.XILA_TOKEN }}
      project: 00000000-0000-0000-0000-000000000000
      scanner: trivy
      file: trivy.json
      new-only: true     # fail on what this PR introduces, not on inherited debt
      check: true        # opt in: a check run with inline annotations
      baseline: main     # compare "new" against what's live on main
      # gate: "true" and comment: "true" are the defaults
```

### The pull-request comment

On a PR, the Action posts the result as a comment on the PR:

> ## ❌ Xila security gate failed
>
> - 1 open critical findings exceed the limit of 0
>
> This change introduces 3 new findings:
>
> | Severity | Finding | Package | Fix |
> | --- | --- | --- | --- |
> | 🔴 critical | [CVE-2021-44228: Log4Shell RCE](#) | `log4j-core@2.14.1` | `2.15.0` |
> | 🟠 high · transitive | [CVE-2021-23337: Prototype pollution](#) | `lodash@4.17.20` | `4.17.21` |
> | 🟡 medium · dev-only | [ReDoS in a test helper](#) | `jest@29.0.0` | - |

Three design choices:

- It's edited in place, not appended. A PR has one Xila comment, kept current.
  A bot that posts a new verdict on every push tends to get muted, so the comment
  carries a hidden marker and each run updates it.
- It reports what the PR introduced (`first_scan_id = last_scan_id`), not the
  size of the backlog. The question for a pull request is whether it made things
  worse.
- Reachability and exploit data are in the table because they affect what you do
  next: `KEV` means it's being actively exploited; `dev-only` / `transitive` mean
  it can wait. The fix version has its own column because it's the most actionable
  information.

Commenting does not fail the build. If GitHub is unreachable, the security verdict
still stands and the exit code is unchanged. Outside a PR (a push to `main`) it
does nothing.

### The check run

With `check: true` (and `permissions: checks: write`), the same verdict also
becomes a GitHub check run named "Xila security gate". It is matched by name and
head commit, so it's updated in place on each push instead of accumulating. Its
summary has the same content as the PR comment. Findings with a known file and
line (SAST, secrets; most SCA findings have no source line) also become inline
annotations on the "Files changed" tab:
`failure` for critical/high severity or any CISA-KEV finding, `warning`
otherwise. The Checks API accepts at most 50 annotations per request, so larger
sets are posted over several calls. The total is capped at 200, and a summary
note says how many more findings had a location but weren't annotated.

Like the comment, posting the check run does not fail the build. A missing
`checks: write` permission (403) only produces a warning, and outside a GitHub
Actions context it does nothing.

## Security scanning of this repository

grype (dependencies and the built image), opengrep (SAST), KICS (IaC) and
gitleaks (secrets) gate every commit through pre-commit hooks (`make hooks`), and every push, pull
request, release and nightly run in CI (`.github/workflows/security.yml`). Run them
locally with `make security`. For thresholds, installation and how to handle a
finding, see [docs/SECURITY_SCANNING.md](docs/SECURITY_SCANNING.md).

## Tests

Tests use only the standard library (`testing`,
`httptest`, Fiber's `app.Test`), with no third-party framework. They are table-driven where it helps.

- Unit (no DB, always run): parser normalization, fingerprint stability,
  risk-score math, enums, JWT signing/expiry/algorithm pinning, and the
  ingestion orchestration (via in-memory fakes).
- Integration (real Postgres): the dedup core. `Upsert` deduplicates by
  fingerprint, a `remediated` finding reopens when it reappears, triage
  statuses stick, and filters/counts work. This logic lives in SQL, so it is
  tested against SQL.
- HTTP smoke (real Postgres): the whole app wired together:
  register → login → 401-without-token → team → project → Trivy ingest →
  risk summary → re-ingest is deduplicated.

```bash
# Unit only (integration/smoke self-skip without a database):
make test

# Everything, against a disposable Postgres (compose's DB works):
export TEST_DATABASE_URL="postgres://xila:xila@localhost:5432/xila?sslmode=disable"
make test-integration
```

DB-backed tests are gated on `TEST_DATABASE_URL` and run with `-p 1`. They share
one database and truncate between tests, so packages must not run in parallel.

## Languages

The UI supports English and German. The language follows the browser
(`navigator.language`) until the user picks one in the header (stored in the
browser). Dates and numbers follow it too, and `<html lang>` is set. Every page
is translated. A new page is added to `TRANSLATED_ROUTES` (`#lib/i18n.js`) only once
all of it is translated. Until then it renders entirely in English, so no page is
half-translated. Some text stays in English by design: the API reference's rendered
OpenAPI content (served verbatim from the spec), identifiers and example values
(`pkg:maven/…`, CEL, claim names, OSV event kinds), and everything the server
writes itself (API error messages, HTML reports and notification e-mails).

Messages live in `web/src/lib/i18n/en.js` (the source) and `de.js`. `t(key, params)`
interpolates `{name}` and picks `one|other` plurals by `count`. `pnpm check` fails
on a missing or extra key, or on a placeholder or plural form that differs from the
English. To add a language, create a catalogue typed like `de.js`, add an entry to
`LOCALES`, and add an import to `CATALOGUES` (`#lib/i18n.js`).

## AI agents (MCP)

With `MCP_ENABLED=true`, Xila is a [Model Context Protocol](https://modelcontextprotocol.io)
server at `POST /api/v1/mcp` (Streamable HTTP, JSON-RPC 2.0; MCP revisions
2025-06-18, 2025-03-26 and 2024-11-05). An agent can search and triage findings,
upload scans and SBOMs, read the fix plan and remediation actions, run the gate
and generate VEX:

| Tool | Does | Needs |
|---|---|---|
| `search_findings`, `get_finding` | the finding list / one finding, same filters as `GET /findings` | viewer |
| `triage_finding` | status (+ reason / expiry), assignee, comment; `risk_accepted` files an acceptance request | editor |
| `list_projects`, `get_fix_plan`, `list_remediation_actions` | what to fix next | viewer |
| `upload_scan`, `upload_sbom` | ingest a report / SBOM (marked destructive: missing findings auto-close) | editor |
| `ask_ai` | record an AI triage proposal for a finding (`AI_TRIAGE_ENABLED`; does not apply it) | editor |
| `generate_vex`, `get_gate_result` | VEX (OpenVEX / CycloneDX / CSAF), the CI gate's verdict | viewer / editor |

Every tool call is an API request carrying the caller's token, so the agent can
do what that token can: roles, a project-scoped token's single project,
validation and the audit log apply unchanged. The audit entry names the tool
(`changes.via = "mcp:triage_finding"`), and finding history names the user. Give an
agent a service account (or a project-scoped token) with the narrowest role
that does the job. Tool results quote scanner output; the tool descriptions tell
the model that titles, descriptions and file contents are data, not instructions.

Desktop clients that launch a stdio server use the CLI as a bridge:

```json
{
  "mcpServers": {
    "xila": {
      "command": "xila",
      "args": ["mcp"],
      "env": { "XILA_URL": "https://xila.example.com", "XILA_TOKEN": "xila_…" }
    }
  }
}
```

## AI-assisted triage (opt-in, bring your own model)

With `AI_TRIAGE_ENABLED=true` a finding page gets an Ask AI panel. The
configured model proposes a false-positive verdict, an exploitability
assessment (status and/or severity) or a fix. The model is set with
`AI_PROVIDER=openai-compatible` (OpenAI or any server with the
chat-completions API, e.g. vLLM, Ollama, LM Studio) or `anthropic`, plus
`AI_BASE_URL`, `AI_MODEL` and `AI_API_KEY`.

- Not applied automatically. Every answer is recorded in `ai_proposals`
  (kind, provider, model, SHA-256 of the exact prompt, raw response, proposed
  status / severity, confidence, who asked) as `proposed`; a newer proposal of
  the same kind `supersedes` it. An editor accepts or rejects it. Accepting
  applies it as that person through the normal path: the finding history names
  them, with a note naming the proposal and the model. With
  `ASSESSMENT_REQUIRES_APPROVAL` it becomes a pending assessment, a proposed
  `risk_accepted` becomes a risk acceptance request, and a fix (or a verdict
  that changes nothing) becomes their comment.
- Data minimisation. The prompt holds the finding's own fields (scanner,
  rule, title, severity, CWE / CVE, CVSS / EPSS / KEV, package, location,
  description), with no project, repository or asset names, and a code snippet
  only if the scanner provided one. Secret-scanner findings send neither
  snippet nor description, the value the scanner matched is scrubbed from every
  field, and well-known credential shapes (`password = …`, cloud / VCS tokens,
  private keys, JWTs, URL credentials) are redacted everywhere. The panel shows
  what will be sent (`GET …/ai-proposals/prompt`) before you send it.
  A project can opt out (`PATCH /projects/{id}` `{"ai_triage_opt_out": true}`,
  or the panel's button); then nothing from it is sent (`403`).
- Model output is untrusted. It must be one JSON object with exactly the
  expected keys. An out-of-set verdict / status / severity, an out-of-range
  confidence or extra text makes the proposal `invalid` (recorded, `502`,
  can't be accepted). The UI renders it as plain text, not HTML.
- Limits. `AI_RATE_LIMIT` requests per project per hour (`429` +
  `Retry-After`). Calls go through the outbound-URL guard (`OUTBOUND_*`). The
  provider's own error text is shown to instance admins only. `AI_API_KEY` is
  not logged or returned.

There is deliberately no triage-rule action that applies proposals. A
proposal only exists because a person asked, and applying one is that
person's decision.

## Local development (without Docker)

You need a reachable PostgreSQL and, if `OTEL_ENABLED=true`, an OTLP endpoint.

```bash
cp .env.example .env      # then export the vars, or use direnv/dotenv
make tidy
make run
```

Set `OTEL_ENABLED=false` to skip telemetry exporters and log JSON to stdout only.

### Prometheus metrics

`METRICS_ENABLED=true` serves the OpenTelemetry instruments in the Prometheus
text format at `/metrics`, alongside or instead of the OTLP push. Both use the
same instruments, so a dashboard built on one works on the other.

| Metric | What |
|---|---|
| `http_server_duration_milliseconds` | requests by method, status and route template (`/api/v1/projects/:projectID`, not the raw path) |
| `xila_ingest_queue_depth`, `xila_ingest_queue_oldest_wait_seconds` | the async ingest queue (`INGEST_ASYNC`) |
| `xila_notify_outbox_pending`, `…_failed`, `…_oldest_wait_seconds` | the notification outbox (sampled by the dispatching replica) |
| `xila_job_runs_total{job,outcome}`, `xila_job_duration_seconds` | each background job: enrichment, NVD, OSV match/mirror, exploit intel, package metadata, policy evaluation, SLA/CRA/remediation sweeps, issue sync, connectors, retention, metric snapshots |
| `xila_job_last_success_seconds{job}` | unix time of each job's last success. `time() - xila_job_last_success_seconds{job="enrichment"}` is the age of the KEV/EPSS feed |
| `xila_audit_write_failures_total` | failed audit-log inserts |
| Go runtime | `go_*` / `process_*` from the OTel runtime instrumentation |

Background jobs run only on the elected leader, so their series come from one
replica at a time. Alert on ages (`oldest_wait`, `time() - last_success`)
rather than depths. With the Helm chart, set `metrics.enabled` (it uses its own
port, which the Ingress does not route) and optionally `metrics.serviceMonitor.enabled`.

## Configuration

All configuration is via environment variables (see `.env.example`). Xila also
reads a `.env` file from its working directory, or the file named by `ENV_FILE`
(which must exist); variables already set in the environment take precedence.

Secret settings can be read from a file instead: set `NAME_FILE` to its path (for
example `INTEGRATION_SECRET_KEY_FILE=/run/secrets/xila_key`). One trailing
newline is trimmed, and setting both `NAME` and `NAME_FILE` is a startup error.
This is how Docker and Kubernetes secrets, Vault Agent, the Secrets Store CSI
driver and External Secrets Operator (AWS Secrets Manager, GCP Secret Manager,
Azure Key Vault, Vault) hand secrets to the app. It applies to `JWT_SECRET`,
`DB_PASSWORD`, `INTEGRATION_SECRET_KEY`, `SMTP_PASSWORD`, `OIDC_CLIENT_SECRET`,
`SAML_SP_KEY`, `LDAP_BIND_PASSWORD`, `METRICS_TOKEN`, `AI_API_KEY`,
`NVD_API_KEY`, `VULNCHECK_API_TOKEN`, `VULNMATCH_GITHUB_TOKEN` and
`VULNMATCH_VULNERABLECODE_API_KEY`.

| Variable                      | Default              | Notes                                   |
| ----------------------------- | -------------------- | --------------------------------------- |
| `APP_ENV`                     | `development`        | `development`, `production`, or `test` (aliases like `prod` accepted); drives hardening defaults and startup validation |
| `HTTP_HOST` / `HTTP_PORT`     | `0.0.0.0` / `8080`   |                                         |
| `DB_*`                        | `xila`               | host, port, user, password, name, sslmode |
| `DB_MAX_CONNS` / `DB_MIN_CONNS` | `20` / `2`         | pool sizing                             |
| `DB_MAX_CONN_LIFETIME` / `_IDLE_TIME` | `1h` / `30m` | pool recycling (Go durations)           |
| `DB_CONNECT_TIMEOUT`          | `10s`                | dial timeout (added to the DSN)         |
| `DB_STATEMENT_TIMEOUT`        | `30s`                | cap on any single query (`0` disables); set per pooled connection, not in the DSN |
| `DB_READ_URL`                 | (none)               | `postgres://` URL of a read replica for reporting reads (portfolio, trends, reports); also `DB_READ_URL_FILE` |
| `DB_READ_STATEMENT_TIMEOUT`   | `0` (= `DB_STATEMENT_TIMEOUT`) | statement cap for reporting reads; set it or `DB_READ_URL` to give reporting its own pool |
| `DB_READ_MAX_CONNS`           | `10`                 | size of that reporting pool |
| `HTTP_READ_TIMEOUT` / `_WRITE_TIMEOUT` / `_IDLE_TIMEOUT` | `15s`/`30s`/`60s` | server timeouts |
| `HTTP_BODY_LIMIT_MB`          | `32`                 | max upload size (scans/SBOMs)           |
| `JWT_SECRET`                  | dev-only fallback    | **Must be a strong value in production (boot fails otherwise).** |
| `JWT_TTL`                     | `24h`                | Go duration                             |
| `REAUTH_WINDOW`               | `10m`                | how recently a session must have signed in to create an API token (`0` = no check) |
| `CORS_ALLOWED_ORIGINS`        | `*` dev / none prod  | comma-separated allow-list              |
| `TRUSTED_PROXIES`             | (none)               | proxy IPs/CIDRs to trust for `X-Forwarded-*` |
| `COOKIE_SECURE`               | `true` in prod       | `Secure` flag on auth cookies           |
| `AUTH_RATE_LIMIT_IP_PER_MIN`  | `60`                 | password sign-in, registration, and reset attempts per client IP per minute (shared across replicas, stored in PostgreSQL); `0` = off. `/auth/config` and SSO are not throttled |
| `AUTH_RATE_LIMIT_ACCOUNT`     | `10`                 | failed sign-ins per account (email) per window. A successful sign-in clears it. Reset-mail requests have their own budget, which is not cleared. `0` = off |
| `AUTH_RATE_LIMIT_ACCOUNT_WINDOW` | `15m`             | window for the per-account budget |
| `SERVICE_ACCOUNT_KEY_MAX_DAYS` | `90`                | longest lifetime of a service-account API key (keys default to 30 days, or this value if lower) |
| `FEDERATION_TOKEN_TTL`        | `15m`                | lifetime of a session from the workload-identity token exchange; at most `1h` |
| `OUTBOUND_ALLOW_PRIVATE`      | `true`               | let integration URLs (trackers, connectors, SSO, webhooks, mirrors) reach private networks (RFC 1918, fc00::/7, 100.64/10), where self-hosted Jira/GitLab usually run. Set `false` if all are public. Link-local and cloud-metadata addresses are always refused |
| `OUTBOUND_ALLOW_LOOPBACK`     | `true` dev / `false` prod | let them reach 127.0.0.0/8 and ::1 (warns in production) |
| `OUTBOUND_ALLOWED_HOSTS`      | (none)               | hostnames exempt from the two rules above, e.g. `jira.internal,localhost` |
| `MCP_ENABLED`                 | `false`              | serve the MCP server for AI agents at `POST /api/v1/mcp` (see *AI agents*); off = 404 |
| `AI_TRIAGE_ENABLED`           | `false`              | opt-in AI-assisted triage (see *AI-assisted triage*); off = its routes return 404 and the panel is hidden |
| `AI_PROVIDER`                 | `openai-compatible`  | `openai-compatible` (POST `{AI_BASE_URL}/chat/completions`) or `anthropic` (POST `{AI_BASE_URL}/v1/messages`) |
| `AI_BASE_URL`                 | (none; `https://api.anthropic.com` for anthropic) | the provider's API root, e.g. `https://api.openai.com/v1`; required for openai-compatible |
| `AI_MODEL`                    | (none)               | the model to use; required when enabled |
| `AI_API_KEY`                  | (none)               | the provider's API key (secret; required for anthropic, optional for a local server) |
| `AI_RATE_LIMIT`               | `30`                 | AI requests per project per hour |
| `AI_TIMEOUT`                  | `90s`                | timeout for one model call |
| `PASSWORD_LOGIN_ENABLED`      | `true`               | email and password sign-in. `false`: registration closes once a user exists, and only the instance owner may log in with a password (break-glass, logged). API tokens are unaffected |
| `SSO_AUTO_CREATE_USERS`       | `true`               | create an account on a user's first SSO login; `false` = only users with an existing account (pre-provision via `POST /users`) can sign in. This is the default; each admin-managed provider can override it |
| `OIDC_ENABLED`                | `false`              | the environment-configured OpenID Connect provider (more providers can be added on the SSO page) |
| `OIDC_ISSUER` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | - | provider (discovery at `<issuer>/.well-known/openid-configuration`) and client |
| `OIDC_REDIRECT_URL`           | -                    | `<PUBLIC_URL>/api/v1/auth/oidc/callback`, registered at the provider |
| `OIDC_PROVIDER_NAME`          | `SSO`                | login button label |
| `OIDC_SCOPES`                 | `openid email profile` | space- or comma-separated; `openid` is always added. Add `groups` only if your IdP needs it to emit groups |
| `OIDC_GROUPS_CLAIM`           | `groups`             | ID-token claim with the user's groups; a dotted path reaches nested claims (`realm_access.roles`); string or string array |
| `OIDC_TRUST_UNVERIFIED_EMAIL` | `false`              | treat an ID token without `email_verified` as verified (may link to an existing account by email). Needed for Entra ID, which omits the claim |
| `SAML_ENABLED`                | `false`              | the environment-configured SAML 2.0 provider (requires `PUBLIC_URL`, https in production; more can be added on the SSO page) |
| `SAML_IDP_METADATA_URL` / `SAML_IDP_METADATA` | - | the IdP metadata, fetched from the URL (at boot, then hourly), or the XML itself (takes precedence when both are set) |
| `SAML_ENTITY_ID`              | `<PUBLIC_URL>/api/v1/auth/saml/metadata` | the SP entity ID (the assertion audience) |
| `SAML_SP_CERT` / `SAML_SP_KEY` | generated           | PEM RSA certificate and key for signing AuthnRequests and decrypting assertions (`\n` escapes allowed). If unset, they are generated once and stored in the database sealed with `INTEGRATION_SECRET_KEY` (which is then required), shared by all replicas |
| `SAML_PROVIDER_NAME`          | `SAML SSO`           | login button label |
| `SAML_EMAIL_ATTRIBUTE`        | auto                 | attribute containing the email; if unset, tries `email`, `mail`, `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`, `urn:oid:0.9.2342.19200300.100.1.3`, then an `emailAddress`-format NameID |
| `SAML_GROUPS_ATTRIBUTE`       | `groups`             | comma-separated attributes holding groups (Name or FriendlyName), e.g. `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` or `memberOf` |
| `SAML_LINK_BY_EMAIL`          | `true`               | trust the IdP's email to link a first login to an existing account with that email |
| `SAML_ALLOW_IDP_INITIATED`    | `false`              | accept unsolicited responses (IdP dashboard tiles); allows login CSRF, warns in production |
| `SAML_SIGN_REQUESTS`          | `true`               | sign AuthnRequests (RSA-SHA256) |
| `LDAP_ENABLED`                | `false`              | LDAP / Active Directory sign-in through the password form |
| `LDAP_URL`                    | -                    | `ldaps://dc.example.com:636` or `ldap://…` (with StartTLS) |
| `LDAP_STARTTLS`               | `true`               | upgrade an `ldap://` connection (production refuses plain `ldap://` without it) |
| `LDAP_CA_CERT`                | system roots         | PEM CA for the directory's certificate (`\n` escapes allowed) |
| `LDAP_BIND_DN` / `LDAP_BIND_PASSWORD` | anonymous    | the service account used to search users |
| `LDAP_BASE_DN`                | -                    | where users are searched (subtree) |
| `LDAP_USER_FILTER`            | person with `mail`/`uid`/`sAMAccountName`/`userPrincipalName` = `{login}` | `{login}` is replaced by the escaped name entered |
| `LDAP_EMAIL_ATTRIBUTE` / `LDAP_GROUP_ATTRIBUTE` | `mail` / `memberOf` | email and group-DN attributes |
| `LDAP_UID_ATTRIBUTE`          | auto                 | the stable account ID; if unset, tries `entryUUID`, `objectGUID`, then the DN |
| `LDAP_LINK_BY_EMAIL`          | `true`               | a first directory login may attach to an existing account with the directory's email |
| `SMTP_HOST` / `SMTP_PORT`     | (none) / `587`       | mail server for `email` notification channels and password-reset mail (with `PUBLIC_URL`) |
| `SMTP_USERNAME` / `SMTP_PASSWORD` | (none)           | optional AUTH PLAIN credentials          |
| `SMTP_FROM`                   | (none)               | sender address, e.g. `Xila <xila@example.com>` (required for email) |
| `SMTP_TLS`                    | `starttls`           | `starttls` (required), `tls` (implicit, e.g. port 465), or `none` (warns in production) |
| `NOTIFY_MAX_ATTEMPTS`         | `8`                  | send attempts per queued notification before giving up |
| `NOTIFY_RETRY_BASE` / `NOTIFY_RETRY_MAX` | `30s` / `1h` | backoff after the first failure, doubling, capped |
| `NOTIFY_RETENTION`            | `168h` (7 days)      | how long delivered or given-up outbox rows are kept |
| `NOTIFY_DISPATCH_INTERVAL`    | `2s`                 | how often the leader polls the outbox (events raised on the leader are sent immediately) |
| `OTEL_ENABLED`                | `true`               |                                         |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `localhost:4317`     | `host:port`, no scheme                  |
| `OTEL_EXPORTER_OTLP_INSECURE` | `true`               | use plaintext gRPC                      |
| `OTEL_SERVICE_NAME`           | `xila-api`           |                                         |
| `METRICS_ENABLED`             | `false`              | serve Prometheus metrics at `/metrics` (works with `OTEL_ENABLED=false`) |
| `METRICS_ADDR`                | *(empty)*            | serve `/metrics` on a separate listener (e.g. `:9090`) instead of the main port |
| `METRICS_TOKEN`               | *(empty)*            | bearer token scrapers must send. In production, `/metrics` on the main port refuses to boot without one; a separate `METRICS_ADDR` does not need it |
| `POLICY_EVAL_INTERVAL`        | `6h`                 | re-evaluate component policies on every project (also on upload and policy edits); `0` = off. Replaces the removed `LICENSE_DENYLIST` (ignored, with a startup warning) |
| `ENRICH_ENABLED`              | `true`               | run periodic EPSS/KEV enrichment         |
| `ENRICH_INTERVAL`             | `6h`                 | how often to refresh exploit intel (and NVD CVSS when enabled) |
| `KEV_SOURCES`                 | `cisa,enisa` (+`vulncheck` with a token) | KEV catalogs to download on each enrichment run: `cisa`, `enisa` (ENISA EUVD exploited list), `vulncheck` |
| `VULNCHECK_API_TOKEN`         | -                    | VulnCheck API token; required for the `vulncheck` catalog, and adds it to the default `KEV_SOURCES` |
| `KEV_CISA_URL` / `KEV_ENISA_URL` / `KEV_VULNCHECK_URL` | upstream | mirror URL for a KEV catalog |
| `EXPLOIT_INTEL_ENABLED`       | `true`               | sync public-exploit feeds (ExploitDB, Metasploit, Nuclei) into findings' `exploit_maturity` |
| `EXPLOIT_INTEL_INTERVAL`      | `24h`                | how often to sync them |
| `EXPLOIT_INTEL_SOURCES`       | `exploitdb,metasploit,nuclei` | which feeds |
| `EXPLOIT_INTEL_{EXPLOITDB,METASPLOIT,NUCLEI}_URL` | upstream | mirror URL per feed |
| `CRA_MANUFACTURER_NAME`       | -                    | manufacturer named in CRA Article 14 reports |
| `CRA_MANUFACTURER_ADDRESS`    | -                    | its postal address |
| `CRA_MANUFACTURER_CONTACT`    | -                    | reporting contact (e.g. the PSIRT e-mail) |
| `CRA_MANUFACTURER_MEMBER_STATE` | -                  | main establishment in the EU (ISO code, e.g. `DE`), which determines the coordinator CSIRT that receives reports; validated at boot |
| `CRA_SWEEP_INTERVAL`          | `15m`                | open cases for exploited findings and alert on reporting deadlines (0 = off) |
| `NVD_ENABLED`                 | `false`              | fetch CVSS vectors/scores from the NVD CVE API 2.0 on the enrichment schedule |
| `NVD_API_KEY`                 | -                    | NVD API key: 50 instead of 5 requests per 30 s |
| `NVD_URL`                     | NVD API 2.0          | override the CVE API base (proxy / tests) |
| `VULNMATCH_ENABLED`           | `true`               | keep stored SBOMs matched against the advisory sources |
| `VULNMATCH_INTERVAL`          | `12h`                | how often to re-match the SBOM inventory |
| `VULNMATCH_SOURCES`           | `osv`                | comma-separated list of `osv`, `github`, `osv-local`, `private`, `vulnerablecode`, `jvn`, `nvd` (merged; air-gapped: `osv-local,private`; `nvd` adds CPE matching for components without a purl) |
| `VULNMATCH_VULNERABLECODE_URL` / `_API_KEY` | public instance / - | VulnerableCode instance and key (the public instance requires a key) |
| `VULNMATCH_JVN_URL` / `_FROM_YEAR` / `_INTERVAL` | `https://jvndb.jvn.jp` / `2015` / `24h` | JVN iPedia feed sync |
| `PSIRT_ADVISORY_PREFIX`       | `XILA-SA`            | tracking-ID prefix of your published advisories |
| `PSIRT_PUBLISHER_NAME` / `_NAMESPACE` / `_CONTACT` | - | CSAF publisher (name, its URL, contact); required to publish |
| `PSIRT_PUBLIC`                | `false`              | serve published advisories as a CSAF provider (`/.well-known/csaf/…`, `/csaf/advisories/…`), unauthenticated |
| `VULNMATCH_OSV_URL`           | `https://api.osv.dev` | OSV API base for the `osv` source |
| `VULNMATCH_GITHUB_URL`        | `https://api.github.com` | GitHub REST base for the `github` source (GHES: `https://host/api/v3`) |
| `VULNMATCH_GITHUB_TOKEN`      | -                    | GitHub token (no scopes needed); lifts the anonymous limit of 60 requests/hour |
| `VULNMATCH_OSV_ECOSYSTEMS`    | -                    | OSV ecosystems to download into the local mirror (e.g. `npm,PyPI,Maven,Go`); empty = upload only |
| `VULNMATCH_OSV_MIRROR_URL`    | `https://osv-vulnerabilities.storage.googleapis.com` | where `<Ecosystem>/all.zip` exports are fetched from (an internal file server when offline) |
| `VULNMATCH_OSV_MIRROR_INTERVAL` | `24h`              | how often the mirror re-downloads (`0` = off) |
| `PKGMETA_ENABLED`             | `true`               | look up latest versions in package registries (outdated components); `false` for air-gapped installs |
| `PKGMETA_INTERVAL`            | `1h`                 | how often a sweep refreshes stale package metadata |
| `PKGMETA_TTL`                 | `24h`                | how long fetched package metadata stays fresh |
| `PKGMETA_CONCURRENCY`         | `4`                  | packages fetched in parallel per registry |
| `PKGMETA_REQUESTS_PER_SECOND` | `5`                  | request rate cap per registry (public crates.io is always limited to 1/s) |
| `PKGMETA_NPM_URL` / `PKGMETA_PYPI_URL` / `PKGMETA_MAVEN_URL` / `PKGMETA_GO_URL` / `PKGMETA_CARGO_URL` / `PKGMETA_NUGET_URL` / `PKGMETA_GEM_URL` / `PKGMETA_COMPOSER_URL` | public registries | registry base URL per ecosystem, for internal mirrors (NuGet: the V3 service index URL) |
| `SLA_SWEEP_INTERVAL`          | `1h`                 | how often breached or due-soon SLAs trigger alerts (`0` = off; `POST /sla/sweep` still works) |
| `BRANCH_RETENTION`            | `90d` (`2160h`)      | delete non-default branches (and their findings) not scanned for this long (`0` = keep forever) |
| `RELEASE_RETENTION`           | `0` (keep)           | the same for non-default release versions. Release history is often audit evidence, so this is off by default |
| `SBOM_RETENTION_KEEP`         | `0` (keep all)       | keep the newest N SBOM snapshots per artifact and version; older ones (components, matches) are deleted. The current snapshot is not deleted |
| `SBOM_RETENTION_AGE`          | `0`                  | with or without `_KEEP`: delete snapshots beyond N only once they are older than this |
| `SCAN_RETENTION`              | `0` (keep)           | delete scan records older than this, except a finding's last scan or the latest scan of a target |
| `LOG_RETENTION`               | `90d` (`2160h`)      | notification delivery log and failed ingest jobs (which hold the uploaded report, or its S3 object with `INGEST_PAYLOAD_STORE=s3`) |
| `AUDIT_RETENTION`             | `365d` (`8760h`)     | audit log entries older than this are purged (`0` = keep forever); the purge itself is logged |
| `ARCHIVE_RETENTION`           | `30d` (`720h`)       | archived projects, engagements, scans, and findings stay restorable for this long, then the retention job deletes them (`0` = keep forever) |
| `FINDING_ARCHIVE_AFTER`       | `0` (off)            | archive findings fixed longer ago than this (e.g. `4320h`), in batches; `ARCHIVE_RETENTION` then purges them, and one reported again comes back open |
| `ASSESSMENT_REQUIRES_APPROVAL` | `false`             | four-eyes for manual status and severity changes: they become pending assessments until a different project owner (or instance admin) approves them |
| `RISK_ACCEPTANCE_REQUIRES_APPROVAL` | `true` in production, else `false` | four-eyes for risk acceptances: the requester cannot approve or reject their own; imported acceptances wait as requests |
| `RISK_ACCEPTANCE_EXPIRY_WARNING` | `168h` | announce approved risk acceptances this long before they expire (`0` = never) |
| `INTEGRATION_SECRET_KEY`      | -                    | base64 32-byte key (`openssl rand -base64 32`) that encrypts issue-tracker and connector tokens, SSO provider client secrets and SP keys, the generated SAML SP key, and two-factor secrets at rest. If unset, two-factor sign-in, trackers, connectors, and admin-managed SSO providers cannot be enabled (the account page says so; production logs a warning). **Changing it makes stored secrets unreadable: re-enter them (and reset users' two-factor).** |
| `SOURCE_URL`                  | upstream repository  | where users get this instance's source, linked on every page (AGPL-3.0 §13: if you run a modified version for others, point it at your source); must be an absolute http(s) URL |
| `PUBLIC_URL`                  | -                    | the UI's external origin, used for links back to Xila in issue bodies (unset = no link); required for SAML and for adding SSO providers on the SSO page (redirect, ACS, and metadata URLs are built from it) |
| `ISSUE_SYNC_INTERVAL`         | `15m`                | how often issue-tracker state is synced in both directions and auto-create runs (`0` = off) |
| `REMEDIATION_SWEEP_INTERVAL`  | `15m`                | how often open findings are grouped into remediation actions and live actions are refreshed (due date, owner, auto-close) (`0` = off; ingest still runs it per scan) |
| `REMEDIATION_AUTO_CREATE`     | `false`              | create remediation actions from proposals automatically instead of waiting for a user to accept them |
| `CONNECTOR_PULL_INTERVAL`     | `6h`                 | how often each enabled pull connector is pulled (`0` = off; Pull now still works) |
| `METRICS_SNAPSHOT_INTERVAL`   | `1h`                 | how often today's and yesterday's metric snapshots are recomputed; the first run backfills 90 days (`0` = off) |
| `PORTFOLIO_FROM_SNAPSHOTS`    | `false`              | serve `/portfolio`'s counts, risk and top projects from the latest snapshots instead of scanning findings per request (as of the last snapshot run; compliance and SLA stay live) |
| `INGEST_MAX_QUEUE_DEPTH`      | `10000`              | pending job count at which uploads are rejected with `429` (`0` = unbounded) |
| `INGEST_QUEUE_SAMPLE_INTERVAL`| `5s`                 | how often queue depth is measured             |
| `INGEST_SKIP_UNCHANGED`       | `true`               | skip the pipeline when a report's content hash matches its target's previous completed scan (see "Skip unchanged scans"); a per-upload `force=true` always processes in full |
| `INGEST_PAYLOAD_STORE`        | `postgres`           | where a queued job's raw upload lives until a worker processes it: `postgres` (`scan_jobs.payload`) or `s3` (any S3-compatible object storage; see "Payload storage") |
| `S3_ENDPOINT`                 | AWS's regional endpoint | override for a non-AWS S3-compatible service (MinIO, Ceph, R2, GCS interop); validated like every other configured destination (`internal/netguard`) |
| `S3_REGION`                   | `us-east-1`          | bucket region |
| `S3_BUCKET`                   | -                    | bucket for queued payloads; required when `INGEST_PAYLOAD_STORE=s3` |
| `S3_PREFIX`                   | -                    | optional key prefix under the bucket |
| `S3_ACCESS_KEY_ID` / `S3_SECRET_ACCESS_KEY` | -     | static credentials; both unset uses the standard AWS credential chain (environment, shared config, EC2/ECS instance credentials, EKS IRSA) |
| `S3_FORCE_PATH_STYLE`         | `false`              | address objects as `/bucket/key`; needed by most non-AWS S3-compatible services |

## Scaling ingestion (async)

Uploads can be processed inline (`INGEST_ASYNC=false`, the default for the bare
binary and the dev compose stack), which returns `201` with the finished scan, or
queued (`INGEST_ASYNC=true`, the default in the production compose file, the Helm
chart and `.env.example`). Queued, the endpoint persists the raw payload and a
`processing` scan row and returns `202` immediately. A worker pool drains a
durable Postgres job queue (`SELECT … FOR UPDATE SKIP LOCKED`) off the request
path. As a result:

- upload latency is about one insert (request rate is decoupled from processing cost),
- bursts are absorbed by the queue instead of exhausting the DB pool,
- throughput scales with `INGEST_WORKERS`, and multiple API instances can run
  workers that pull jobs safely in parallel (the app is stateless). Set
  `INGEST_WORKERS=0` on nodes that should only accept uploads and run dedicated
  worker nodes against the same database (the Helm chart does this with
  `ingest.workerDeployment`, optionally autoscaled by KEDA on queue age),
- crashed jobs are reclaimed (stale-lock timeout) and retried up to
  `INGEST_MAX_ATTEMPTS` before being parked as `failed`.

This needs no new infrastructure, only Postgres. The `xila` CLI's `--gate` (and
`--wait`) poll the scan to completion before gating, so CI works with either
mode. Once `INGEST_MAX_QUEUE_DEPTH` jobs are waiting, uploads get `429` with
`Retry-After`. The CLI retries that (and 502/503/504 and connection errors) with
exponential backoff and jitter for up to `--retry-for` (default 10 minutes,
`XILA_RETRY_FOR`), so a burst of CI jobs is delayed rather than failed.

The write path is sized for the volume this mode implies. Findings are persisted
with pipelined batch upserts, and the post-ingest tail (auto-triage and
cross-tool dedup) is scoped to the scan's findings rather than the whole
project. Ingest cost therefore tracks the size of the upload, not the project's
accumulated history.


### Skip unchanged scans

Most CI reruns report exactly what the previous scan of the same target did.
Each upload hashes the parsed findings (every field the upsert would write,
keyed by dedup fingerprint, plus `close_missing`) rather than the raw bytes, so
a report that differs only in a scanner-embedded value we don't read (Trivy's
top-level `CreatedAt`, for example) still counts as unchanged, while a parser
upgrade that extracts something new counts as a change. If the hash matches the
target's (project version + scanner + asset) previous completed scan, the
pipeline is skipped entirely: no upsert, auto-close, appliers, dedup or alert.
The scan is recorded completed with the previous summary, `unchanged_of` set
to the scan it repeated, and the target's live findings get their
`last_scan_id`/`last_seen_at` moved onto it in one UPDATE, so they still look
seen by this scan (and a later, different scan's auto-close still works) without
ever counting as newly introduced (`first_scan_id` is untouched). Only ever
compared against the *latest* completed scan of the target, so an A, B, A
sequence reprocesses the third upload rather than matching the stale first one.
A matching hash alone isn't enough: if anyone changed one of those findings
since the previous scan (a status, a reset title or severity, archiving) or the
asset's exposure, or a finding has been deleted, the upload is processed in full
so the scanner's view is restored (a manually closed finding that is still
reported reopens, a reset field gets the scanner's value back).

`INGEST_SKIP_UNCHANGED` (default `true`) controls this; a per-upload
`force=true` (`xila upload --force`) always processes in full. Works the same
whether ingestion is sync or async.

### Backpressure & queue visibility

Accepting an upload we can't process for an hour is worse than refusing it. The
client believes it was ingested and gates on a backlog that was never updated.
Once `INGEST_MAX_QUEUE_DEPTH` pending jobs accumulate, uploads are rejected with
`429` and `Retry-After` (set it to `0` to accept without limit).

Workers claim jobs fairly. The org with the fewest jobs processing goes first
(its oldest job wins ties), and a project never has more than one job
processing: its other uploads wait while workers move on to other projects. So a
tenant that queues 100,000 reports doesn't hold up another tenant's single
upload. Admins can change the queue limit and the worker count per worker node
at runtime (`PUT /api/v1/ingest/settings`, or the Ingest queue card on the
home page); every node picks the change up on its next queue sample
(`INGEST_QUEUE_SAMPLE_INTERVAL`). `null` returns to the env value, and web-only
nodes (`INGEST_WORKERS=0`) never start workers.

`GET /api/v1/ingest/queue` (admin) reports `pending`, `processing`, `failed`,
and `oldest_wait_seconds`. Alert on the last one, since depth alone is
ambiguous: a steady 500 that workers are draining is healthy, while a steady 5 nobody
has touched in an hour is not. The same numbers are exported as OpenTelemetry
gauges (`xila.ingest.queue.depth`, `xila.ingest.queue.oldest_wait`) along with
worker throughput and latency (`xila.ingest.jobs`, `xila.ingest.job.duration`),
so you can see whether the queue drains faster than it fills.

### Payload storage (S3)

Async ingest holds each queued report's raw bytes in `scan_jobs.payload`
until a worker processes it. At very high volume (a burst of a million 1 MB
reports is a terabyte) that is a lot of bytea traffic through Postgres for
data nothing ever queries. `INGEST_PAYLOAD_STORE=s3` moves it to any
S3-compatible object storage instead (AWS S3, MinIO, Ceph, Cloudflare R2,
GCS's S3 interop): the upload handler stores the payload under
`<S3_PREFIX>/scan-jobs/<scan id>` and `scan_jobs` keeps only that key
(`payload_ref`), the worker fetches it, and it is deleted once the job
finishes. A job that exhausts its retries and is parked `failed` keeps its
object, so it stays inspectable, until the `LOG_RETENTION` sweep deletes it
alongside the row (the same thing `LOG_RETENTION` already did for
`scan_jobs.payload`). Requests go through `internal/netguard` like every other
configured destination. `S3_ACCESS_KEY_ID`/`S3_SECRET_ACCESS_KEY` set static
credentials; leaving both unset uses the standard AWS credential chain
(environment, shared config, EC2/ECS instance credentials, EKS IRSA), useful
when the pods already have workload identity. The bucket is checked
(`HeadBucket`) at startup, so a missing bucket or bad credentials fails boot
rather than the first upload. Skip-unchanged and the queue behave identically
either way; only where the bytes live between upload and processing changes.

Measured ingest throughput and list/portfolio latency at 1M+ findings, the Go
benchmarks for the dedup/auto-close/priority hot paths, and the harness that
reproduces both are in [docs/SCALE.md](docs/SCALE.md).

### Past 100M findings

Four settings keep large instances fast. `FINDING_ARCHIVE_AFTER` moves old
fixed findings out of every live query (they stay restorable until
`ARCHIVE_RETENTION`). `PORTFOLIO_FROM_SNAPSHOTS` serves the portfolio from the
hourly metric snapshots rather than scanning every finding per request.
`DB_READ_URL` sends portfolio, trend and report reads to a read replica, and
`DB_READ_STATEMENT_TIMEOUT` caps them in a pool of their own, so a heavy report
can't take connections ingest needs. `docs/SCALE.md` has the details.

## Deploying to production

Set `APP_ENV=production` and the app hardens its defaults and validates its
config at boot:

- Startup fails if `JWT_SECRET` is missing or left at the dev value.
- CORS is restricted to same-origin (the embedded SPA needs no cross-origin headers).
  Set `CORS_ALLOWED_ORIGINS` only if the UI is served from another host.
- Cookies get the `Secure` flag (`COOKIE_SECURE` defaults on).
- Remaining risky settings are logged as a `production hardening` warning at
  startup (insecure DB password, `sslmode=disable`, plaintext OTLP, non-https SSO
  redirect, `*` CORS, `OUTBOUND_ALLOW_LOOPBACK=true`). These are visible but non-fatal.
- Outbound requests are guarded. Every server-side request to a configured URL
  (issue trackers and connectors set by project owners, SSO issuers, webhooks,
  registry and advisory mirrors) goes through one client. It always refuses
  cloud-metadata and link-local addresses, and refuses loopback in production.
  The check runs on the resolved address at connect time, so DNS tricks and
  redirects don't bypass it. When an integration test fails, only instance admins
  see the remote's response; other users see the status. If no integration should
  reach your internal network, set `OUTBOUND_ALLOW_PRIVATE=false`.
- Accounts: password sign-in is throttled per IP and per account. Changing a
  password, "sign out everywhere", and deactivation revoke sessions immediately
  (JWTs carry a version checked on every request). With `SMTP_*` + `PUBLIC_URL`
  set, users can reset forgotten passwords themselves. Otherwise an admin gives
  them a single-use link.

Behind a load balancer, set `TRUSTED_PROXIES` so client IP and scheme come from
`X-Forwarded-*`. The connection pool and HTTP timeouts can be tuned through environment variables (`DB_MAX_CONNS`,
`DB_CONNECT_TIMEOUT`, `HTTP_READ_TIMEOUT`, `HTTP_BODY_LIMIT_MB`, …).

The `docker-compose.prod.yml` stack sets all of this up. It passes every setting
in `.env` to the app and fails at startup if `DB_PASSWORD`, `JWT_SECRET`,
`INTEGRATION_SECRET_KEY` or `PUBLIC_URL` is unset:

```bash
cp .env.example .env       # set DB_PASSWORD, JWT_SECRET, INTEGRATION_SECRET_KEY, PUBLIC_URL
make up-prod               # docker compose -f docker-compose.prod.yml up -d --build
```

Starting from `.env.example`, every feature that needs no credentials is on
(two-factor, MCP, metrics on the unpublished port 9090, advisory matching,
enrichment, exploit intel, registry metadata). Email, PSIRT publishing, the CRA
manufacturer identity, AI triage and the paid feeds need your values in `.env`.
It runs with `APP_ENV=production` and keeps Postgres off the host network. Production checklist: a strong `JWT_SECRET`,
`DB_SSLMODE=require` plus a real DB password (a managed Postgres is preferred), TLS
terminated in front of the app (so `Secure` cookies work), and
`OIDC_REDIRECT_URL` / `PUBLIC_URL` on `https://` if SSO is enabled. The image is distroless and
runs as non-root.

### Kubernetes (Helm)

A chart lives in [`deploy/helm/xila`](deploy/helm/xila/README.md):

```bash
helm install xila deploy/helm/xila -n xila --create-namespace   # bundled Postgres, generated secrets
kubectl -n xila port-forward svc/xila 8080:80
helm test xila -n xila
```

For production, disable the bundled database and point `database.*` at a managed
PostgreSQL 15+, enable `ingress`, and set `publicUrl` / `trustedProxies`. Any
setting in the configuration table can be passed through `config` (or
`secrets.extra` / `existingSecret` for secrets). Replicas scale freely: the
scheduled jobs run on one elected pod (below).

Retention. One daily leader job applies the `*_RETENTION` settings (table
above): stale branches and (opt-in) releases, old SBOM snapshots beyond the newest
N, old scan records, and the delivery log / failed ingest jobs. It does not delete
what the live views depend on (a version's current snapshot, a finding's last
scan, the latest scan of a target, the default version), so it shrinks history
(timelines, snapshot diffs), not current state. `GET /retention` shows the
policy. `POST /retention/run` applies it now and returns the counts (admin).

Archive instead of delete. `DELETE` on a project (owner), engagement, scan
or finding (editor) archives it: `archived_at` / `archived_by` are set and the
record drops out of every list, count, summary, metric snapshot, dedup election,
gate, SLA / CRA sweep, notification and the portfolio (one SQL fragment per
entity, `internal/archive`). A project's findings are archived through the
project. Nothing else is written, so restoring the project brings them back as they
were. Archiving a scan archives the findings it last reported that no other
live scan reported; restoring it brings them back. A scan that reports an archived
finding again makes it live. `?archived=true` on the project, scan, engagement
and finding lists shows the archived ones (owner; portfolio-wide lists narrow to
the projects you own), and `POST …/restore` (owner) brings one back within
`ARCHIVE_RETENTION` (410 after). The daily retention job then deletes them.
`DELETE …?purge=true` (instance admin) deletes one immediately.

Audit log. Every mutating request on the authenticated API (POST / PUT /
PATCH / DELETE, including ones authorization refused) and every sign-in event
(registration, password login success and failure, password reset, two-factor,
SSO logins) appends one entry: when; who (`user`, `service_account`,
`api_token` with the token id, `system`, or `anonymous` for a failed sign-in,
with the address it tried); the action and resource (from the route:
`projects.members.delete` on `members/<id>`) with its project / team / org;
method, path, client IP (honouring `TRUSTED_PROXIES`), status and outcome; and
`changes`, which holds the handler's `before`/`after` where it records them (e.g. a user's
admin flag), otherwise the request's JSON body. Passwords, tokens, secrets, keys,
MFA codes and webhook URLs are replaced by `[REDACTED]` (one policy,
`internal/audit/redact.go`). Non-JSON and large bodies (scanner reports) are
recorded only by type and size. Entries are written synchronously after the
handler but do not fail the request: a lost write is logged and counted in
`xila.audit.write_failures`. The table is append-only: a trigger refuses every
UPDATE and DELETE except the `AUDIT_RETENTION` purge. Admins search and export
it under Admin → Audit log (`GET /audit-log`, `/audit-log/export`).

Several instances, one set of scheduled jobs. Every instance serves the API
and drains the ingest queue, but the scheduled jobs (notification delivery,
summaries, exception and SLA sweeps, enrichment, OSV matching, issue sync, connector
pulls, metric snapshots, retention) run on one instance at a time: the holder of a PostgreSQL
advisory lock (`internal/leader`). When it stops, another instance takes over
(≈20 s after a clean shutdown; about a minute if its node is lost). This also applies to
`compose --scale`. **Use a direct connection or session-mode pooling, not
transaction-mode PgBouncer.** At startup an instance waits up to a minute for the
database instead of exiting.

### Releases

Pushing a tag `vX.Y.Z` (or `vX.Y.Z-rc.N`, published as a pre-release) runs
`.github/workflows/release.yml`. After the full CI gate passes, it publishes:

| Artifact | Where |
|----------|-------|
| Multi-arch image (amd64, arm64) with SBOM + provenance attestations | `ghcr.io/<owner>/xila-api:X.Y.Z`, `:X.Y`, `:latest` (final releases) |
| Helm chart, versioned like the app | `oci://ghcr.io/<owner>/charts/xila` (`helm install xila oci://ghcr.io/<owner>/charts/xila --version X.Y.Z`) |
| Server binaries with the UI embedded (Linux, macOS × amd64, arm64) | GitHub release |
| `xila` CLI (Linux, macOS, Windows × amd64, arm64) | GitHub release |
| SPDX SBOM of the source tree, `SHA256SUMS` | GitHub release |

Both binaries report their version (`xila-api version`, `xila version`), and the
server logs it at startup.

## Single sign-on (OIDC + SAML)

Xila signs people in with OpenID Connect and SAML 2.0. Any number of providers can
be active at once, alongside passwords or instead of them. SSO only establishes
identity: the result is the same JWT a password login gets, so RBAC is unchanged.

Providers. Instance admins manage them on the SSO page
(`/api/v1/sso/providers`): *Add provider* → OIDC or SAML → a preset (Google,
GitLab, Keycloak, Entra ID, Okta, generic). The preset prefills the issuer or
metadata URL pattern and the groups claim, and the URLs to register at the IdP are
shown (and copyable) before saving. *Test* dry-runs a draft or a saved provider
(OIDC discovery, where the issuer must match the discovery document's; SAML
metadata fetch and parse). It shows the endpoints found, the IdP signing
certificates with their expiry, and warnings (unsupported scope, groups claim not
advertised, expiring certificate). Each provider has an immutable slug that names
its routes (`/api/v1/auth/oidc/{slug}/login|callback`, `/api/v1/auth/saml/{slug}/metadata|login|acs`;
`login`, `callback`, `metadata`, `acs`, `oidc` and `saml` are reserved), a button
label and order, and its own login policy: `auto_create_users` (unset = the
instance's `SSO_AUTO_CREATE_USERS`) and `link_by_email`. Adding providers requires
`PUBLIC_URL` (every URL is built from it) and `INTEGRATION_SECRET_KEY`. The OIDC
client secret and an optional own SAML SP key are stored sealed with that key
(bound to the provider) and are write-only in the API (`has_client_secret`,
`has_sp_key`). A blank secret on edit keeps the stored one. Issuer and metadata
URLs must be https in production (http is allowed in development).

Providers configured by environment (`OIDC_*`, `SAML_*`, at most one of each)
keep working as before at their original URLs
(`/api/v1/auth/oidc/login|callback`, `/api/v1/auth/saml/metadata|login|acs`), so
existing IdP registrations need no change. They are listed read-only (`source:
environment`, id and slug `oidc` / `saml`), and editing or deleting them returns 409.

Changes apply immediately on every replica. Each login request re-reads its
provider row (one indexed query), so adding, disabling (its routes then return 404
and its button disappears), editing or deleting a provider takes effect on every
instance at its next request, with no restart or propagation delay. The expensive
parts (OIDC discovery, the SAML IdP metadata fetch) are cached per provider
version (`updated_at`). An edit rebuilds the cache on each replica's next use, and
it is refreshed hourly to pick up IdP certificate rotation (a failed refresh keeps
the last good one). A provider whose discovery or metadata fails is shown with its
error on the SSO page, left off the login page, and retried after a minute. It does
not affect other providers or boot. Deleting a provider deletes the group mappings
scoped to it. Its users keep their accounts and linked identities (identities are
keyed by issuer + subject, not by provider), so they can still sign in with a
password or through another provider with the same issuer.

Who is who. A login is keyed on the IdP's stable id for the person (OIDC
`iss` + `sub`, SAML IdP entity id + NameID), stored in `user_identities`, so an
email change at the IdP doesn't break it. The account adopts the new email if it is
verified and free; otherwise it keeps its own. An identity seen for the first time:

1. attaches to an existing account with the same email only if the IdP vouches
   for the email and the provider links by email. OIDC vouches with `email_verified: true`
   (an absent claim counts only with the provider's *trust email without email_verified* /
   `OIDC_TRUST_UNVERIFIED_EMAIL=true`); SAML always vouches. Linking by email is the provider's
   `link_by_email` (default on; `SAML_LINK_BY_EMAIL` for the environment SAML
   provider). The account must also not already be linked to a *different*
   subject at the same IdP (a recycled address is refused, not given the account);
2. otherwise gets a new passwordless account (the provider's `auto_create_users`,
   else `SSO_AUTO_CREATE_USERS`, default on; if off, the user gets a "no account" error until an
   admin adds them with `POST /users`). An email the IdP explicitly marks
   unverified never creates an account.

Two providers with the same issuer (for example, the environment one and a database one
for the same Keycloak realm) sign in the same identities. `user_identities` also
records which admin-managed provider an identity last signed in through. This is for display
only: the *linked accounts* count on the SSO page.

The first user of an empty instance, whether SSO or password, becomes the owner.
Failures redirect to `/login?error=<code>` (`sso_failed`, `sso_no_account`,
`sso_email_unverified`, `sso_identity_conflict`, `sso_no_email`). Details are
logged, not shown. Xila has no disabled-user state. To remove someone's access,
remove them at the IdP (so they can't get a new token) and remove their grants.

Roles from IdP groups. On the SSO page (`/api/v1/sso/group-mappings`),
map an IdP group (exact value) to instance admin, an org role (`admin`/`member`),
or a team/project role (`owner`/`editor`/`viewer`). A mapping applies to logins
through any provider, every provider of one kind (`provider: oidc|saml`;
mappings made before multi-provider support keep this meaning, covering the
environment and database providers of that kind), or one provider
(`provider_id`: its id, or `oidc`/`saml` for the environment one; deleted with
the provider). Group names only have meaning within one IdP, so with several
providers of a kind, scope mappings to the provider that sends the group. On
every SSO login, the user's SSO-made grants are synced to the groups of that
login, matched against the mappings in scope for its provider. Grants are added, re-roled
(the highest role wins when several groups hit one target), or removed. A user who
signs in through several providers therefore holds the SSO grants of their
*latest* login's provider. Only grants with `source = sso` are touched. A grant
made by hand (API/UI) is never changed, and the effective role is already the
highest grant. Instance admin from a mapping is revoked only if it came from SSO,
and **the owner is never demoted**. Leaving a group takes effect at the user's
next SSO login. Tokens issued earlier stay valid until `JWT_TTL`, but admin
and membership checks read the database on every request, so anything the login sync
revokes is removed immediately. If a login has no groups claim/attribute, the user gets no SSO grants.
An SSO-made team owner is revoked when they leave the group, even if they were the
team's last owner (org admins can still manage the team). The manual last-owner guard
is unchanged.

OIDC. Authorization-code flow with PKCE (S256), `state` and `nonce`, stored in
short-lived HttpOnly cookies named after and path-scoped to the provider, so a
login started at one provider cannot be completed at another provider's callback. At the
IdP, register a confidential web client with the provider's redirect URI
(`<PUBLIC_URL>/api/v1/auth/oidc/{slug}/callback`; `…/oidc/callback` for the
environment provider). The presets on the SSO page include these hints too. Google's
ID token has no groups claim, and GitLab sends direct memberships as
`groups_direct`:

- *Keycloak*: client authentication on, standard flow; issuer
  `https://kc.example.com/realms/<realm>`. Groups: add a "Group Membership" mapper
  (claim `groups`, full path → values like `/xila-admins`) or use realm roles with
  `OIDC_GROUPS_CLAIM=realm_access.roles`.
- *Okta*: OIDC web app; issuer `https://<org>.okta.com` (or an authorization
  server). Groups: add a `groups` claim (filter, e.g. regex `.*`) to the ID token;
  `OIDC_SCOPES="openid email profile groups"` if your server scopes it.
- *Entra ID*: app registration, web redirect URI as above; issuer
  `https://login.microsoftonline.com/<tenant>/v2.0`. Groups: *Token configuration →
  Add groups claim* (values are group object ids). Entra omits
  `email_verified`, so set `OIDC_TRUST_UNVERIFIED_EMAIL=true` if accounts should
  link by email.

SAML 2.0. Xila is the SP: SP-initiated login (HTTP-Redirect, signed
AuthnRequest) and the HTTP-POST ACS. The IdP must sign the assertion or the
response. Encrypted assertions are supported. Each response is checked for the
IdP signature, exactly one assertion (signature-wrapping hardening),
audience = SP entity id, recipient/destination = the ACS URL, validity window
(3-minute clock skew), `InResponseTo` = the request this browser started (tracked
in a signed, HttpOnly, `SameSite=None; Secure` cookie), and an assertion id not
seen before (stored in Postgres until expiry, so a replay fails on every replica).
Transient NameIDs are refused; configure a persistent or email NameID. Each SAML
provider is its own SP. Give the IdP these values (shown, copyable, on the SSO page):

| At the IdP | Database provider | Environment provider (`SAML_*`) |
| --- | --- | --- |
| Entity ID / Audience / Identifier | `<PUBLIC_URL>/api/v1/auth/saml/{slug}/metadata` (or its entity id override) | `<PUBLIC_URL>/api/v1/auth/saml/metadata` (or `SAML_ENTITY_ID`) |
| ACS / Reply / Single sign-on URL | `<PUBLIC_URL>/api/v1/auth/saml/{slug}/acs` | `<PUBLIC_URL>/api/v1/auth/saml/acs` |
| SP metadata (import) | `<PUBLIC_URL>/api/v1/auth/saml/{slug}/metadata` | `<PUBLIC_URL>/api/v1/auth/saml/metadata` |

The request-tracking cookie is named after the provider, path-scoped to it, and
MAC-bound to it, so it cannot complete another provider's login. The replay store
is shared (assertion ids are unique).

- *Keycloak*: Clients → import the SP metadata URL (leave client signature
  required on). NameID format `persistent` or `email`; add mappers "User Property
  email → `email`" and "Group list → `groups`" (full path off for plain names).
  `SAML_IDP_METADATA_URL=https://kc.example.com/realms/<realm>/protocol/saml/descriptor`.
- *Entra ID*: Enterprise application → Single sign-on → SAML; Identifier and
  Reply URL as above. Default claims send the email as
  `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` (detected
  automatically); *Add a group claim* and set
  `SAML_GROUPS_ATTRIBUTE=http://schemas.microsoft.com/ws/2008/06/identity/claims/groups`.
  `SAML_IDP_METADATA_URL` = the "App Federation Metadata Url".
- *Okta*: SAML 2.0 app; Single sign-on URL = ACS, Audience URI = entity id,
  Name ID format `EmailAddress` or `Persistent`; attribute statement `email` →
  `user.email`, group attribute statement `groups` (filter as needed).
  `SAML_IDP_METADATA_URL` = the app's "Metadata URL".

The SP key pair (request signing and assertion decryption) is the provider's own
when set (`SAML_SP_CERT`/`SAML_SP_KEY`, or *Own SP certificate* on the SSO page,
RSA). Otherwise a single shared key pair is used, generated once (RSA-2048,
self-signed, ten years) and stored sealed with `INTEGRATION_SECRET_KEY`, so all
replicas (and all providers without their own) present the same certificate. IdP
metadata is fetched on first use and refreshed hourly (certificate rotation). A
fetch failure leaves that provider off the login page and is retried, like an
OIDC discovery failure. The Artifact binding is not supported.

Single Logout. The SP metadata advertises `…/slo` (HTTP-Redirect and
HTTP-POST). Each SAML login records the NameID and SessionIndex it was made under
(`saml_sessions`, expiring with the JWT).
- *Signing out of Xila* is a local sign-out, so other devices stay signed in.
  If the latest sign-in was through a SAML IdP that advertises a
  SingleLogoutService, the browser is then sent there with a signed
  `LogoutRequest` (query-signed, Bindings §3.4.4.1). The IdP ends its session
  and, typically, the user's other applications. The `LogoutResponse` lands on
  the login page.
- *Signing out at the IdP* sends a `LogoutRequest` here. It must be signed by the
  IdP's metadata certificate, either in the query (`SigAlg`/`Signature`, Keycloak's
  default) or enveloped (POST). Unsigned, forged, expired or misaddressed requests
  are refused. The request ends every Xila session of the user it names (token-version
  bump: Xila has no narrower session to end, so all of that user's devices are
  signed out), or only the login with that SessionIndex when one is given. It
  is answered with a signed `LogoutResponse` in a binding the IdP advertises.
  Both directions are recorded in the audit log (`auth.sso_logout`).

Turning passwords off. `PASSWORD_LOGIN_ENABLED=false` hides the password form
(the login page keeps a small "Owner sign-in" link), closes registration once the
instance has a user, and refuses password login for everyone except the
instance owner. The owner login is the break-glass for when the IdP is down, and each
use is logged as a warning. API tokens keep working. Break-glass requires the owner account to have a
password, i.e. to have been created by registering (do that before turning
passwords off). An owner first created by an SSO login can set one on the
Account page or through a reset link from another admin.

### LDAP / Active Directory

`LDAP_ENABLED=true` signs people in against your directory through the normal
password form (email or username). Accounts with a local password sign in
locally. Everyone else is looked up with the service account (`LDAP_BIND_DN`,
`LDAP_USER_FILTER` with `{login}`, escaped), then bound as themselves with the
password they typed. An empty password is refused before it reaches the directory,
because many servers treat it as an anonymous bind and "succeed". The verified identity
(stable id from `entryUUID` / `objectGUID`, the `mail` attribute, `memberOf`
groups) goes through the same layer as OIDC and SAML: linked to a user (by email
with `LDAP_LINK_BY_EMAIL`), auto-created per `SSO_AUTO_CREATE_USERS`, refused when
deactivated, and groups mapped to roles on the SSO page with provider `ldap`
(a group matches by full DN or by CN, e.g. `xila-admins`). The password form stays
on the login page for directory accounts even with `PASSWORD_LOGIN_ENABLED=false`.
Use `ldaps://` or `ldap://` with StartTLS (production refuses plain `ldap://`
without it). Use `LDAP_CA_CERT` for a private CA.

### Two-factor sign-in (TOTP)

Anyone who signs in with a password (local or LDAP) can turn on two-factor on
the Account page: scan the QR code with an authenticator app, confirm a code,
and keep the 10 single-use recovery codes. Sign-in then requires the password
and a code. Each code works once, wrong codes are capped at 5 per account per
15 minutes, and a password-reset link doesn't skip the second step. Admins can
reset a user's two-factor (for a lost device) on the Users page, which also signs
them out everywhere. Secrets are sealed with `INTEGRATION_SECRET_KEY` (required for
two-factor). SSO sign-in relies on the identity provider's own two-factor.

### Feature switches

Admins can turn whole features off and on at runtime on the Features page
(`GET /features`, `PUT /features/{key}` with `{"enabled": false}`), without a
restart. All are on by default:

| Key | Feature | While off |
|---|---|---|
| `mfa` | Two-factor sign-in | Nobody is asked for a second factor, and enrollment is hidden. Enrollments are kept and apply again when it is turned back on. Owner only, from a signed-in session (not an API token). |
| `cra` | CRA Article 14 cases | No cases open and no deadline alerts are sent. The first sweep after turning it back on opens the cases that became due meanwhile, with their clocks starting then. |
| `psirt` | Advisory publishing | The admin API and the public CSAF directory (`/.well-known/csaf/…`, `/csaf/…`) answer 404. |
| `ai_triage` | AI triage | Also needs `AI_TRIAGE_ENABLED`. Without it the switch reads off and can't be turned on. |
| `mcp` | MCP server | Also needs `MCP_ENABLED`, with the same behavior. |
| `badges` | README badges | Badge images answer 404 (tokens are kept). |
| `custom_fields` | Custom fields | Definitions and values are kept but hidden. |
| `personal_notifications` | Assignee / watcher alerts | Events go to the admin-managed channels only. |
| `remediation` | Remediation actions | The ingest pass, the sweep, the ticket sync, and root causes stop. |
| `engagements` | Engagements | Manual findings can still be reported. |

A switched-off feature's routes answer 404 (public ones too), its background
work and ingest side effects stop, and the UI hides its pages and sections. Its
data is not deleted. Other replicas pick up a change within 5 seconds.
Every switch is recorded in the audit log with its before and after state.

## Operational notes

- Probes: `/health` (liveness) and `/ready` (readiness, pings the database).
- Hardening: protected routes require a Bearer token (JWTs are checked
  against the account's session version and active state on every request).
  Password sign-in, registration and reset are rate-limited per IP and per account
  (`AUTH_RATE_LIMIT_*`). Outbound integration requests are guarded
  (`OUTBOUND_*`). CORS and a 32 MB body limit are enabled. The DB pool is bounded
  with lifetime/idle limits.
- CI: `.github/workflows/ci.yml` runs `gofmt`/`vet`/`build` and the full test
  suite (`-race`) against a Postgres service container, builds the UI with a
  `svelte-check` ratchet (`pnpm check`: the error count may only go down), and
  lints the Helm chart. Tags run the same gate, then the release.

## Extending

- Add a domain (e.g. `internal/container/`) following the repository + service +
  handler pattern, then add its handler to `server.Handlers` and register routes.
- Add a scanner by implementing `scanner.Parser` and registering it in `main.go`.
- Add migrations under `internal/database/migrations/` using the
  `NNNNNN_name.up.sql` / `.down.sql` convention.

## License

Xila is licensed under the GNU Affero General Public License v3.0 only
([LICENSE](LICENSE), SPDX `AGPL-3.0-only`). You may use, self-host, modify and
redistribute it. If you modify it and let others use it over a network, you must
offer them the source of your version under the same license. Xila links to it
from every page, so set `SOURCE_URL` to your source. The API clients in
[`clients/`](clients/README.md) are Apache-2.0, so code that calls Xila through
them is not bound by the AGPL. Third-party data and attributions:
[NOTICE](NOTICE).

