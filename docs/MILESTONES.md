# Xila: Parity Milestones

Goal: every capability of DefectDojo + SecObserve + Dependency-Track in one
platform, on top of what Xila already does better (cross-tool dedup,
exploit/reachability priority, VEX-on-ingest, new-only gates, immutable SBOM
history, CSPM/KSPM compliance, one binary + Postgres).

Ordered by priority. Status: ⬜ not started · 🟨 in progress · ✅ done.
Each item lists its definition of done. An item is not done until that holds
end-to-end (migration → repo → service → handler → OpenAPI → UI → tests).

Sources for the parity targets:
[DefectDojo](https://docs.defectdojo.com/get_started/about/about_defectdojo/) ·
[SecObserve](https://secobserve.github.io/SecObserve/getting_started/features/) ·
[Dependency-Track](https://docs.dependencytrack.org/).

---

## M0: Correctness fix (blocker)

### ✅ 0.1 Scope auto-close to what the scan actually covered
`finding.CloseMissing` closed on `(project_id, scanner)` only. A Trivy scan of a
feature branch closed `main`'s findings, and a scan of image B closed image A's.

- A finding is closed only when the scan that last reported it had the same
  `asset_id` as the closing scan, and (since 3.1) only within the closing scan's
  project version. Pinned by `TestCloseMissingScopedToScanTarget`.
- The former known limit (one row per `(project, fingerprint)`, so the same
  issue on two branches shared one lifecycle) no longer applies. Findings are
  unique per `(version, fingerprint)` (3.1).

---

## M1: SLA (DefectDojo core)

### ✅ 1.1 SLA policy + due dates
- `internal/sla`: days-to-fix per severity, stored globally, per org, or per
  project. The most specific policy wins as a whole, falling back to the built-in
  7/30/90/120 days (no SLA for info). Saving or removing a policy re-dates the
  findings it governs in the same transaction.
- Per-finding `sla_days` / `sla_due_at` are maintained by the `findings_sla` trigger
  (migration 000027). They are re-resolved on insert and on severity change. The
  clock pauses in `risk_accepted` / `false_positive` / `wont_fix`, and the paused
  time is added back on reopen. Days are absolute 24-hour days, so DST does not
  move a deadline.
- `sla_status` = `on_track` / `due_soon` (last 25% of the window) / `breached` /
  `paused` / `met` / `missed` / `none`; `?sla=` filter and `?sort=sla_due`.
- UI: SLA column, filter, and sort on findings lists; deadline on the finding page;
  a project SLA tab; and an SLA page for instance and org policies.
- Changing a project's SLA requires project owner. Org policies require org admin,
  and the instance policy requires instance admin.

### ✅ 1.2 SLA reporting, alerts, gating
- Project summary + portfolio `sla`: breached (by severity), due soon, on track,
  paused; met / missed, compliance % and MTTR per severity over the last 90 days.
- Sweep (`SLA_SWEEP_INTERVAL`, `POST /sla/sweep`) sends `finding.sla_breach` and
  `finding.sla_due_soon`: one event per project, worst first, each finding once
  per deadline.
- Gate condition `block_sla_breach` (+ `xila gate --block-sla-breach`).

### ✅ 1.3 SLA scaled by business criticality
- Decision: it scales whatever policy is in force (instance, org or project)
  rather than replacing per-project overrides. One instance-wide admin switch.
- Migration `000035`: singleton `sla_settings` (`scale_by_criticality`, factor per
  criticality, defaults ×0.5 / ×0.75 / ×1 / ×1.5). `sla_scaled_days()` is the only
  place the rule lives (round, ≥1, ≤3650; no SLA stays none), and `sla_days_for`
  calls it. Saving re-windows the whole backlog. A trigger on
  `projects.business_criticality` re-windows a project when it's re-rated.
- `GET/PUT /sla/settings` (admin) with a criticality × severity matrix. Project
  policy responses carry `applied` (the scaled windows). UI: *Business
  criticality* card on `/sla`, scaled windows shown on the project SLA tab.
- Done: `TestCriticalityScalingMovesExistingDeadlines` (enable, re-rate,
  1-day floor, disable, API views match the findings).

---

## M2: SBOM history you can interrogate (Dependency-Track core+)

### ✅ 2.1 Vulnerable-or-not on every component view
- Every component row (global search, project inventory, one snapshot) carries
  `vuln_count`, `max_severity`, `kev`, `vulns`. `?vulnerable=true|false` filters.
- Rule (`sbom.VulnState`): an advisory matched that snapshot's purl, or a
  scanner reported that package version in the project in any status except
  `false_positive`. A remediated finding means the project moved off the version,
  not that the version got safer. Deduplicated by CVE, else advisory/rule id.
  (Changed from the plan's "active findings only", which would have wiped
  history as soon as an upgrade closed the findings.)
- UI: vulnerability column + filter on the Components page, the project's
  Components tab and each snapshot. "Who shipped it?" lookup by CVE.

### ✅ 2.2 Point-in-time vulnerability state per snapshot
- `sbom_vulns (sbom_id, purl, vuln_id, cves, severity, summary, fixed_version,
  first_seen_at, last_seen_at)`: vulnmatch now evaluates every snapshot and
  replaces each one's matches per run, so withdrawn advisories drop out. Only the
  current snapshot per artifact produces findings.
- Each upload triggers a background match for its project (disable with
  `VULNMATCH_ENABLED=false`). Overlapping runs for one project are reconciled under
  a per-project advisory lock. A run whose snapshot was superseded mid-flight
  leaves the findings to the newer run. We found this live: without the lock, a slow run over
  the previous release re-opened findings the new release had closed.
- `GET /sboms/{id}/vulnerabilities`; `GET /vulnerabilities/{id}/sboms` (CVE or
  advisory id) → per artifact: every snapshot, introduced in, fixed in, still
  affected. UI: snapshot Vulnerabilities tab, `/vulnerabilities/{id}` page.

### ✅ 2.3 SBOM diff
- `GET /sboms/{id}/diff?base=` (default: previous snapshot of the artifact; base
  must be in the same project) → added / removed / upgraded / downgraded /
  changed, unchanged count, per-package fixed / introduced vulnerabilities, and the
  snapshot-wide vulns fixed / introduced. Version ordering across ecosystems is
  best-effort (`sbom.CompareVersions`); undecidable moves are `changed`.
- UI: snapshot Changes tab with base picker, prev/next snapshot navigation.
- Verified live against real OSV data with hand-built npm CycloneDX releases
  (not Syft output).

### ✅ 2.4 Dependency graph
- `sbom_components.bom_ref`, `sboms.root_ref`, `sbom_dependencies`; CycloneDX
  `dependencies` and SPDX relationships (DEPENDS_ON, *_DEPENDENCY_OF, DESCRIBES)
  persisted. `GET /sboms/{id}/graph` (nodes with vulnerability state + edges;
  synthesized root; placeholder nodes for undeclared refs) and
  `GET /sboms/{id}/graph/paths?ref=|component_id=` (≤20 shortest root→package
  routes, cycle-safe).
- UI: snapshot Graph tab. It is a collapsible dependency tree rather than a
  force-directed drawing, which stays readable at thousands of nodes and adds no new dependency.
  It has severity badges, "leads to vulnerable" markers, "only paths to vulnerable
  packages", package search, and a side panel with every route to the selected
  package. The finding page shows "Pulled in via …" for its component.
- SPDX graphs are covered by parser and graph tests; the browser check used
  CycloneDX.

---

## M3: Model & workflow parity

### ✅ 3.1 Branches / versions as first-class
DT project versions, SecObserve branches, DefectDojo engagements.
- Migration `000029`: `project_versions` (name, kind `branch|release`,
  `is_default`, one default per project); `version_id` NOT NULL on scans, SBOMs
  and findings; findings unique per `(version_id, fingerprint)`. Resolution happens
  in SQL (`project_version()` + fill triggers), so no write path needed new
  parameters. The first version a project uses becomes its default.
- Ingest `?branch=`/`?release=` (CLI `--branch`/`--release`). Auto-close, dedup,
  reachability, license findings and OSV matching are per version. Summaries,
  portfolio, compliance, SLA/new-critical alerts, digests and an unqualified gate
  read only default versions. `gate?branch=` gates a branch (unknown → 404).
- `GET /projects/{id}/versions`, `PATCH|DELETE …/versions/{id}` (owner).
  `BRANCH_RETENTION` prunes stale non-default branches daily (releases are kept).
- UI: project Branches tab, version filter on findings, branch columns on
  scans/SBOMs, "All branches" toggle in the inbox.
- Done: `TestBranchesHaveIndependentLifecycles` (same CVE on `main` and
  `feature/x`, independent close/triage, portfolio counts only `main`);
  `TestMatchAppliesEachVersionSeparately`; smoke + RBAC.
- Legacy data: everything was backfilled onto one default version (named after
  the most-scanned branch), so pre-3.1 scans of other branches show as default.

### ✅ 3.2 Analyst workflow on findings
- Migration `000033`: `findings.assignee_id`, `finding_comments`,
  `finding_attachments` (bytea, ≤10 MiB), and `finding_events`, written by trigger on
  every status/severity/assignee change. Events are attributed via transaction-local
  `xila.actor`/`xila.note`, or `system` for automatic writers.
- Routes: assignee, assignees of a project, comments, attachments (downloads
  forced to files, active types served as octet-stream), history, and
  `POST /findings/bulk` by `ids` or `filter` (≤5000; per-project authorization;
  unauthorized returns "not found").
- UI: finding Activity timeline + comment box, assignee picker, attachments;
  inbox Owner column, *Assigned to me* filter, bulk bar (status / take / unassign)
  with *Select all matching* to apply to the whole filter.
- Done: `TestHistoryRecordsEveryWriter`, `TestApplyMatchesSingleTriage`,
  `TestCommentsAndAttachments`, `TestAnalystWorkflow` (cross-project bulk
  authorization, filter scope, assignee rules, download headers, history).

### ✅ 3.3 Auto-triage maturity
- ✅ Dry-run / preview: `POST /triage-rules/preview` (draft) and
  `/triage-rules/{id}/preview` → the findings it would change.
- ✅ Per-rule hit counts and last-hit time (migration `000030`).
- ✅ Conditions `min_epss`, `kev`, `project_criticality`.
- ✅ Four-eyes approval for rule changes (`TRIAGE_RULES_REQUIRE_APPROVAL`).
- ✅ Approval for manual assessments (`ASSESSMENT_REQUIRES_APPROVAL`, migration
  `000034`): analysts' status/severity changes (single or bulk) become pending
  `finding_assessments` (one per finding). A *different* project owner or
  admin approves them at `/approvals`, and history records requester and approver.
  Approval applies the requested target state even if the finding has changed since.

### ✅ 3.4 Issue trackers
- Migration `000031`: `issue_trackers` (one per project; token AES-256-GCM
  encrypted with `INTEGRATION_SECRET_KEY`, project id as AAD) + `finding_issues`.
- Jira (REST v2), GitHub, GitLab: create on demand or automatically at/above
  `min_severity` (≤50 per tracker per run), link stored on the finding, two-way
  sync on `ISSUE_SYNC_INTERVAL` (closed issue → `remediated`, reopened → `open`).
  A reopened issue does not overturn an exception; it is closed again.
- UI: project Issues tab; issue link or create button on the finding page.

### ✅ 3.5 Notification channels
- Email (SMTP: `SMTP_*`, STARTTLS/TLS), Microsoft Teams (MessageCard),
  Mattermost, alongside webhook and Slack (migration `000032`). The channel test
  sends to that channel only and reports delivery failure as `502`.

---

## M4: Reporting & interchange

### ✅ 4.1 Metrics history & trends
- Migration `000036`: `metric_snapshots`, one row per UTC day × scope (portfolio,
  org, team, project). All figures are summable (open by severity, new, closed, risk,
  SLA breached / met / missed, MTTR sums). Default versions only, no duplicates.
- `METRICS_SNAPSHOT_INTERVAL` (1h; re-snapshots today and yesterday). The first run
  reconstructs 90 days from finding timestamps (`reconstructed`). `POST
  /metrics/snapshot` (admin). Trends are available for portfolio (non-admins: sum of visible
  projects), org, team and project, up to 365 days.
- UI: dependency-free SVG `TrendChart` on the dashboard and a project Trends
  tab. Requires Postgres 15+ (`UNIQUE NULLS NOT DISTINCT`).
- Done: `TestSnapshotPastDay`, `TestSnapshotTodayMatchesLiveViews`,
  `TestRunBackfillsOnce`, `TestMetricsTrendScoping`.

### ✅ 4.2 Exports & reports
- CSV / XLSX (stdlib SpreadsheetML writer) for findings (inbox + project) and
  components (search, project, snapshot). Exports share the list endpoints' filters and
  SQL, with a 100k-row cap signaled by `X-Truncated` and CSV formula-injection escaping.
- Printable HTML project and portfolio reports (risk, severity, SLA, top 20,
  compliance, branches covered). PDF via the browser's print. Strict CSP.
- Done: `TestExportsAndReports` (rows equal the list, RBAC, escaping, report
  numbers equal `/portfolio`).

### ✅ 4.3 VEX & BOM export
- `GET /projects/{id}/vex/export?format=openvex|cyclonedx|csaf` per version:
  triage → VEX status (FP → not_affected with the stored justification only,
  remediated → fixed, accepted/confirmed/won't fix → affected, open →
  under_investigation). The most cautious verdict wins per (vuln, product).
- `GET /sboms/{id}/export?format=cyclonedx`: CycloneDX 1.6 with dependencies and
  vulnerabilities, plus analysis from the snapshot version's triage.
- Done: OpenVEX / CycloneDX VEX re-import round-trip (8 triage cases), BOM
  re-upload yields the same inventory and edges, CSAF VEX profile checks.

### ✅ 4.4 Import formats
- DefectDojo generic findings JSON and SecObserve (REST observation list + its
  import format). Triage they carry is applied to newly created findings only
  (`remote_triage` metadata + the `RemoteTriage` pass), not over local triage.
- 27 new native parsers: Snyk, pip-audit, Safety (v2), cargo-audit, Retire.js,
  bundler-audit, Semgrep, Bandit, gosec, Brakeman, detect-secrets, ggshield,
  Checkov, tfsec, Terrascan, ScoutSuite, Clair, Anchore, Docker Scout, Polaris,
  kube-bench, Burp, Nikto, Nmap, Wapiti (+ the two import formats). Fixtures are real samples,
  and each is also uploaded over HTTP (`TestSmokeAppSecScanners`,
  `TestSmokeInfraScanners`). See also `TestImportedTriageNeverOverridesLocal`.
- Pull connectors (migration `000037`, `internal/connector`): Dependency-Track
  project or DefectDojo product/engagement → one synthetic scan per pull
  (auto-close included). Incomplete or failed fetches apply nothing.
  `CONNECTOR_PULL_INTERVAL` (6h). Tokens are stored via the shared `internal/secretbox`.
- Not done: Safety v3 `scan` JSON (no CVE/severity in it), Docker Scout native
  JSON (SARIF is parsed instead). Compliance mappings for kube-bench / ScoutSuite
  check ids are a follow-up.

---

## M5: Component intelligence (Dependency-Track depth)

### ✅ 5.1 Outdated components
- `internal/pkgmeta` (migration `000039`): npm, PyPI, Maven, Go, Cargo, NuGet,
  RubyGems, Packagist clients with per-ecosystem version ordering (SemVer,
  PEP 440, Maven, RubyGems, Composer). "latest" is the newest stable non-yanked
  release. Mirrors via `PKGMETA_<ECO>_URL`; polite rate limits and backoff.
- Leader cron (`PKGMETA_INTERVAL`, `PKGMETA_TTL`) over the current inventory, plus
  a fetch of new packages on upload. Components carry `latest_version`, `outdated`,
  `versions_behind`, `version_published_at`; `?outdated=` filter; UI badges.
  Unknown is not treated as "up to date". Limits: Maven has no release dates; Go
  dates only the latest version.

### ✅ 5.2 Policy engine
- `internal/policy` (migration `000040`): global and per-project policies, `any|all`
  over 15 condition subjects (severity, vulnerability id, KEV, EPSS, CWE, license,
  license group, unresolved license, outdated, versions behind, age, missing hash,
  coordinates/version range, purl glob, package type). `fail|warn|info` map to
  high/medium/low findings with scanner `policy`, which auto-close when resolved.
- Preview (dry-run), violations per policy, project tab, `policy.violation`
  notification. Policies are re-evaluated on upload, after matching/registry data,
  on edit, and every `POLICY_EVAL_INTERVAL`.
- `LICENSE_DENYLIST` removed: a seeded global "Strong copyleft licenses" (`warn`)
  policy replaces it, matched on parsed SPDX expressions (LGPL is no longer caught;
  `MIT OR GPL-3.0` complies). Existing `license-policy` findings are migrated in
  place, keeping triage and exception history (tested).

### ✅ 5.3 License data
- SPDX License List 3.29.0 and ScanCode LicenseDB categories are embedded
  (`make licenses` refreshes them). SPDX expression parser (Annex D, fuzz-seeded).
  At ingest, components get a normalized expression, ids, categories and a resolved
  flag (backfilled once for old rows). License catalog and license groups
  (custom, or built-in `category:<Category>`), `?license=` / `?license_category=`
  filters, `/licenses` UI.

### ✅ 5.4 Vulnerability sources
- `VULNMATCH_SOURCES`: `osv` (online), `osv-local` (mirror imported from OSV
  ecosystem zips by upload or scheduled sync, for air-gapped installs), `github`
  (GitHub Advisory Database), `private` (internal OSV-format advisories, CRUD and
  import, `/advisories` UI). One merged advisory per id/aliases, all as scanner
  `osv`. A failed source does not auto-close findings (partial runs only add).
- NVD API 2.0 enrichment (`NVD_ENABLED`, `NVD_API_KEY`): CVSS vector and version
  on findings; scanner scores take precedence. Cached in `nvd_cves`.

### ✅ 5.5 Services & data flow
- CycloneDX 1.2–1.6 `services` stored per snapshot (migration `000042`):
  endpoints, authentication, trust boundary / trust zone, data flows with
  classification (legacy and 1.5+ shapes). Unauthenticated external endpoints
  and boundary-crossing flows are flagged. Services appear in the diff, the
  graph and the BOM export, and in the snapshot Services tab. Follow-up: policy
  conditions on services.

---

## M6: Enterprise & DefectDojo extras

- ✅ 6.1 Enterprise login. ✅ SAML 2.0 SP (crewjam/saml; signed assertions,
  replay protection, SP-initiated, optional IdP-initiated) alongside OIDC (now with
  PKCE). Identities are stored in `user_identities` (linked by verified email, with a
  JIT provisioning toggle). IdP group mappings to instance-admin / org / team /
  project roles sync on every login and leave manual grants untouched (migration
  `000043`). Password login can be disabled (owner break-glass). Verified against a
  real Keycloak (OIDC and SAML, group revocation, replay and tampering rejected).
  ✅ LDAP / AD bind login (`LDAP_*`, group → role mappings, M7). ⬜ SAML Single Logout.
- ⬜ 6.2 Instance audit log (who changed what, across all resources) → tracked as 8.2.
- ✅ 6.3 Pentest/engagement management: engagements (scans as tests), manual
  findings, finding templates, engagement reports (M7 P3).
- ⬜ 6.4 Security checklists / benchmarks (OWASP ASVS) per project → folded into 8.17.

---

## M7: Parity review follow-through

Gaps found by the DefectDojo / SecObserve / Dependency-Track parity review, split
into five phases. Each phase was verified end to end: full `-race` suite on a fresh
database, `pnpm build` plus the svelte-check ratchet, `helm lint --strict`, and a
live UI check.

### ✅ P1 Hardening
- Postgres-backed rate limiting for login / reset / MFA (`internal/ratelimit`,
  migration `000045`), shared across replicas, with a per-account reset bucket.
- SSRF guard on every outbound client (`internal/netguard`;
  `OUTBOUND_ALLOW_PRIVATE` / `_LOOPBACK` / `OUTBOUND_ALLOWED_HOSTS`). Remote error
  bodies are shown to admins only.
- Account lifecycle (migration `000046`): self-service password change, session
  revocation (JWT `tv` claim checked per request), password reset by mail or
  admin link, and deactivating, reactivating or deleting users.
- Release pipeline: SHA-pinned `release.yml`, multi-arch image built natively
  via `$BUILDPLATFORM`, `version` subcommands, and the svelte-check ratchet in CI.
- Durable notification outbox (migration `000047`): `Notify` enqueues, and the
  leader dispatches with leases and backoff. Pending items are listed at
  `GET /notifications/pending`.

### ✅ P2 Triage depth & identity
- CPE matching via the NVD CPE API (`VULNMATCH_SOURCES=nvd`): SBOM
  components without a purl are matched by CPE. One match key is used everywhere.
- Full-text search and tags on findings (migration `000048`): `q`
  (websearch syntax, relevance-ranked), `tag`, bulk tag edits, tag history.
- Per-channel rules and summaries (migration `000049`): minimum severity,
  event selection, daily / weekly summaries. Replaces the global digest.
- Retention (`internal/retention`): stale branch / release pruning, SBOM
  history caps, old scans and logs. Rules that delete analysis default to off.
- Ingestion health (migration `000050`): stale projects, volume drops, and
  failed scans / jobs / connectors are reported as anomalies with alerts and a home banner.
- LDAP / AD login and TOTP 2FA (migrations `000051`–`000052`): one directory
  via `LDAP_*` with group mappings. TOTP with recovery codes for password
  sign-in, with admin reset.
- CEL expressions (cel.dev/cel-go) as a policy subject and a triage-rule
  condition (migration `000053`). Unknown facts do not match.

### ✅ P3 DefectDojo workflow
- Engagements (migration `000054`): time-boxed work per project. Scans
  uploaded with `engagement_id` become its tests (a composite FK keeps them in the
  project). Includes stats and `?engagement_id=` on finding lists and exports.
- Manual findings (`POST /projects/{id}/findings`): scanner `manual`, added
  without auto-close, and history credits the reporter. The write-up is editable
  (`PATCH /findings/{id}/details`). Finding templates prefill them.
- Report templates (migration `000055`): brand, logo, accent colour,
  classification, intro/footer, section order, minimum severity, finding count.
  Includes a per-finding write-up section and engagement reports (`?engagement_id=`).
- 20 DefectDojo parsers, tested on real DefectDojo samples: hadolint, KICS, ESLint,
  yarn audit (v1/berry), njsscan, Bearer, MobSF, SonarQube, Checkmarx, Veracode,
  Mend, JFrog Xray, AWS Inspector2, AWS Security Hub, Nessus/Tenable, OpenVAS,
  Qualys, Acunetix (+360), Invicti, testssl.sh. 62 native parsers total.
- Dedup fix found along the way (migration `000057`): a CVE finding without a package is
  grouped by location, so one CVE on two hosts is two findings.

### ✅ P4 Differentiators
- Component integrity: SBOM hashes are compared with the registry's published digests
  (npm, PyPI, crates.io, RubyGems), giving `verified` / `mismatch` / unknown
  (migration `000059`). Available as a filter, policy subject `integrity`, CEL, and a UI badge.
- Fix plan (`/fix-plan`, `/projects/{id}/fix-plan`): upgrades ranked by
  priority removed, using the smallest version that fixes every finding on a package version.
- CI templates: GitHub Action `ci/github/scan` and GitLab
  `ci/gitlab/xila-scan.gitlab-ci.yml` run Trivy/Grype/OSV/Semgrep/Gitleaks/Checkov
  from pinned images and gate once. See `docs/CI.md`.
- EU CRA pack (migration `000060`): Annex I framework with `kev` / `sla` /
  `sbom` / `vex` match types and manual controls, plus a printable evidence report.
- Keyboard triage and inline edit on the findings tables (`?` for keys). Every
  exception status asks for a reason.
- README badges (migration `000056`): token-gated public SVGs (findings,
  gate, SLA).
- Exploit intel (migration `000058`): ExploitDB, Metasploit, and Nuclei feed
  `exploit_maturity` (poc / weaponized), which feeds priority. Available as a filter, refs, and in the UI.

### ✅ P5 UI type safety
svelte-check is at 0 errors (down from 1175). `request()` and every API method are typed
via JSDoc, `$state` and `$props` are typed, and unknown errors go through `errorMessage(err)` and `instanceof
ApiError` instead of being read directly. There are no suppressions. The CI ratchet
(`web/.svelte-check-baseline` = 0) keeps the count at zero.

---

## M8: Parity review 2 (November 2026)

A second comparison against current releases: DefectDojo Pro 3.5
([changelog](https://docs.defectdojo.com/releases/pro/changelog/),
[10 new features](https://defectdojo.com/blog/10-new-defectdojo-features-changing-how-teams-manage-vulnerability-risk),
[October newsletter](https://defectdojo.com/newsletter/october-2026)),
Dependency-Track 5.2 ([5.1](https://dependencytrack.org/news/dependency-track-5-1/),
[5.2](https://dependencytrack.org/news/dependency-track-5-2/),
[changes in v5](https://dependencytrack.github.io/docs/next/concepts/changes-in-v5/))
and SecObserve 1.64 ([features](https://secobserve.github.io/SecObserve/getting_started/features/),
[releases](https://github.com/SecObserve/SecObserve/releases)).

Already at parity or ahead, so not listed: component integrity (DT v5), CEL
policies (DT v5), ingestion health (DD), threat intelligence (EPSS, KEV, public
exploits), cross-tool correlation (DD), the transactional notification outbox
(DT v5), retention (DT v5), egress control (DT 5.2), expiring API tokens, full-text
search (SecObserve 1.64), CI templates, the CRA Annex I pack, branch security
gates, and CSAF / OpenVEX / CycloneDX VEX export. Items still open in M6 stay there:
6.2 audit log (promoted to 8.2 below), 6.4 ASVS (folded into 8.17), and SAML
Single Logout.

### ✅ 8.0 Security gates on this repository
grype (dependencies and the built image), opengrep (SAST), KICS (IaC) and
gitleaks (secrets: staged changes, working tree, and full history in CI) run
as pre-commit hooks and in `.github/workflows/security.yml` on every push, pull
request, release and nightly run. A build fails on a High/Critical with a fix, any opengrep
finding, or a KICS finding of Low or above. The first run fixed:
- 370 grype matches: Go 1.26.1 → 1.26.11, plus x/net, x/crypto, grpc,
  go-jose, goxmldsig, compress, fasthttp/brotli, otel, vite, devalue, nanoid,
  postcss and cookie;
- a GitHub Actions script injection in the root `action.yml`;
- docker-compose hardening (localhost-bound ports, dropped capabilities,
  no-new-privileges, healthchecks via a new `xila-api healthcheck` subcommand).

The Xila Scan action and the GitLab template gained `opengrep` and `kics`. See
`docs/SECURITY_SCANNING.md`.

Toolchains (November 2026): Go 1.26 → 1.27 (`go 1.27.0`, `toolchain go1.27.4`)
and Node 22 → 26 (LTS since 2026-10-28) for the UI build, updated in `go.mod`, the
Dockerfile, both workflows and the GitLab template. SvelteKit stays on 2.x for now.
A trial migration to 3.0 is noted under M9.

### Tier 1: high value, shipped by a competitor this year

- ✅ 8.1 Service accounts + workload identity federation (DT 5.2). CI jobs
  exchange their platform's OIDC identity token (GitHub Actions, GitLab CI,
  Kubernetes) for a short-lived Xila session (OAuth 2.0 token exchange, RFC 8693),
  so pipelines store no Xila secret.
  *Done when:*
  - Service accounts exist as non-human users with roles and their own expiring
    keys. Suspending one ends its keys and sessions.
  - Admin-defined trusted issuers, plus bindings by claim (repository, branch,
    environment) to a service account and project.
  - `cmd/xila` and both CI templates authenticate without a token input.
  - The audit trail names the service account.
  ✅ `internal/serviceaccount`, `internal/federation` (migration 061): service accounts are `kind='service'` users; RFC 8693 `POST /auth/token`; the CLI and CI templates exchange GitHub / GitLab OIDC tokens when no `XILA_TOKEN` is set.
- ✅ 8.2 Instance audit log (DT 5.2, DD 3.5; was 6.2). Every mutation records
  who (a user, service account or token), what, before → after, and where from,
  across all resources, not just findings.
  *Done when:* the log is append-only, admin-searchable, CSV-exportable, covered
  by retention, and has a test that every mutating route writes an entry.
  ✅ `internal/audit` (063): middleware on every mutating secured route plus sign-in events; redaction in one place; append-only trigger; `AUDIT_RETENTION`; Admin → Audit Log.
- ✅ 8.3 CRA Article 14 reporting (DD 3.4; the CRA's obligation to report
  actively exploited vulnerabilities has applied since 11 September 2026).
  *Done when:*
  - A finding that becomes actively exploited (KEV, weaponized exploit) in a
    product shipped to the EU opens a reporting case with the CRA clock: early
    warning within 24 h, notification within 72 h, final report within 14 days.
  - Deadline alerts go out through the outbox.
  - The case exports a payload for the ENISA single reporting platform.
  - The case status appears in the CRA evidence report.
  ✅ `internal/cra` cases (064): auto-opened on KEV / weaponized exploits for `cra_in_scope` projects; +24 h / +72 h / 14-day clocks; outbox alerts; draft ENISA payload export.
- ✅ 8.4 More KEV catalogs (DT 5.1): ENISA EU KEV (on by default) and VulnCheck
  KEV (opt-in, with a token) beside CISA. A catalog assertion matches through
  aliases, so a CISA entry for a CVE also flags the GHSA record of the same flaw.
  *Done when:* each catalog's source is stored per finding and shown in the UI,
  and policies, gates, triage rules and CEL can read it.
  ✅ (065) CISA + ENISA EUVD + VulnCheck; `kev_sources` on findings, gates, policies, CEL and in the UI; a failed catalog keeps its last list.
- ✅ 8.5 Risk acceptances as first-class objects (DD "Risk Acceptances 2.0").
  One acceptance covers many findings, with an owner, a justification, an expiry
  and a request → review → approve lifecycle. Findings stay counted until it is
  approved.
  *Done when:*
  - A per-finding ledger keeps the history after a finding leaves the acceptance.
  - When an acceptance expires, its findings reopen and their SLA restarts.
  - It replaces today's per-finding exception fields as a clean cutover.
  ✅ `internal/finding/acceptance.go` (067): acceptances with a ledger, four-eyes approval (`RISK_ACCEPTANCE_REQUIRES_APPROVAL`, on in production) and expiry that reopens findings; old exception data converted by the migration.
- ✅ 8.6 Remediation work items (DD "Remediation Center"). Generalise the fix
  plan beyond packages: group open findings by the change that resolves them (a
  package upgrade, a base-image bump, an IaC rule, a code location) into tracked
  actions, each with an owner, a due date, a status and the findings it closes.
  *Done when:* an action closes when all its findings are remediated, and it can
  be pushed to the issue tracker as a single ticket.
  ✅ `internal/remediation` (068): package / base-image / IaC / code / config actions from one grouping (`fixplan.Changes`, which the fix plan reads too); auto-close; one ticket per action with two-way sync.
- ✅ 8.7 Asset exposure and relationships (DD rebuilt asset model, Asset
  Exposure). Assets record internet exposure (manually or from scanner context)
  and typed relationships (`built_from` base image, `deployed_as`, `depends_on`).
  *Done when:*
  - Exposure multiplies priority the way reachability does, with the same rule:
    unknown never discounts.
  - A shared base image shows its blast radius across the assets built from it.
  ✅ (062) `exposure` (internet 1.25×, isolated 0.75×, unknown 1.0×) in every priority writer; inference from Prowler / ScoutSuite / Security Hub / DAST; relations and `GET /assets/{id}/blast-radius`.
- ✅ 8.8 Signed webhooks (DT 5.2). The generic webhook channel signs its
  bodies with HMAC-SHA256 over the timestamp and body, using a per-channel secret
  (encrypted with `secretbox`, write-only).
  *Done when:* the docs include a verification snippet and a test rejects a
  replayed or tampered body.
  ✅ (066) `X-Xila-Signature: v1=…`, `X-Xila-Timestamp`, `X-Xila-Delivery`; secret sealed with secretbox and write-only; `notify.VerifySignature` reference verifier.

### Tier 2: rounds out parity

- ✅ 8.9 Interchange.
  - CSAF VEX import (SecObserve, DD) next to OpenVEX and CycloneDX.
  - A CycloneDX 1.7 export option. 1.7 imports already ingest (DT 5.1).
  - VEX exports name the affected component, not only the project (DT 5.1).
  ✅ CSAF 2.0 VEX import (`internal/vex/csaf.go`: product ids resolve through the product tree and relationships to purls; tested on a Red Hat CSAF VEX file, CC BY 4.0); `?spec=1.7` on the CycloneDX BOM and VEX exports; VEX exports already named the component purl; round-trip tests cover OpenVEX, CycloneDX 1.6 and 1.7, and CSAF.
- ✅ 8.10 Notification filter expressions (DT v5): an optional CEL filter per
  channel over the event payload, reusing `internal/expr`, beside the
  severity and event filters.
  ✅ (069) `filter` on channels, validated on save; reads `event`, `event.project` and `event.finding`; a failing filter skips only its own channel.
- ✅ 8.11 Policy scope by project tags (DT 5.2): include or exclude projects
  by tag, so "every project except `internal-tool`" doesn't need per-project
  lists.
  ✅ (070) `include_tags` / `exclude_tags` on component policies, evaluated in Go and SQL; a project-tag edit re-evaluates the project. Gate and SLA policies keep their own scoping.
- ✅ 8.12 Project hierarchy / collection projects (DT): parent projects that
  roll up their children's metrics, inventory and policy violations. RBAC
  inherits down the tree.
  ✅ `internal/projecttree` (073): `parent_id` + `is_collection` on projects (same org, cycles refused in SQL); grants inherit down the tree (`membership.ProjectGrantsSQL`), so the permission audit agrees; summary, findings, components, policies and trends roll a project up with its descendants (`?include_children=true`); `GET /projects/{id}/children`; tree view on the home page, breadcrumbs and a roll-up toggle on the project page.
- ✅ 8.13 Archive instead of delete (DD 3.5): projects, engagements, scans and
  findings can be archived. Archived records drop out of lists, metrics, dedup and
  gates, and can be restored within a retention window before they are purged.
  ✅ `internal/archive` (074): `DELETE` on projects, engagements, scans and findings archives (`archived_at/by`); every list, count, metric, gate, compliance and portfolio query excludes archived rows (`archive.Finding/Project/…` fragments); `POST …/restore` (owner); `?archived=true` lists; the retention sweep purges after `ARCHIVE_RETENTION` (30 days); UI archive/restore on the home, project and finding pages.
- ✅ 8.14 Typed custom fields (DD) on projects, assets and findings: text,
  number, date, enum and user types. Filterable, exported, readable and writable
  by triage rules and CEL, and recorded in history.
  ✅ `internal/customfield` (075): admin-defined text/number/date/enum/user fields on projects, assets and findings in a validated `custom` jsonb; `?cf.<key>[.gte|…]=` filters on the lists and export columns; CEL `finding.custom` / `project.custom`; triage action `set_custom_field`; history via a trigger; Admin → Custom fields, editors on each record, a findings-list filter.
- ✅ 8.15 Personal notifications (SecObserve 1.60): users subscribe to events
  for findings assigned to them or projects they watch, by email, Slack or Teams.
  ✅ (072) personal channels (owner-scoped rows in the same outbox), `user_notification_prefs`, `project_watches`, `finding.assigned`; access checked at routing and again at send (`ProjectGrantsSQL`); webhook URL sealed and write-only; Account → My notifications and a project Watch button.
- ✅ 8.16 PSIRT publishing (DD PSIRT 2.0): publish CSAF 2.0 security
  advisories for your own products from private advisories plus affected and
  fixed versions. Feed rules score, tag and mute incoming advisories before they
  are matched against inventory.
  ✅ `internal/psirt` (076): advisories about your own products (draft → published → revised), CSAF 2.0 JSON (product tree from project versions, CVSS, remediations) with the CSAF distribution files (`index.txt`, `changes.csv`, `/.well-known/csaf/provider-metadata.json`) when `PSIRT_PUBLIC=true`; Admin → Our Advisories.
- ✅ 8.17 More compliance packs (DD 3.4): OWASP ASVS 5 (was 6.4), PCI DSS 4.0,
  ISO 27001 Annex A, SOC 2 and NIS2. These are mapping data in the CRA style,
  marking requirements a scan can't judge as manual, each with an evidence
  report.
  ✅ Migrations 078–082: OWASP ASVS 5.0, PCI DSS 4.0.1, ISO/IEC 27001:2022 Annex A, SOC 2 TSC, NIS2 Art. 21(2) (CWE / rule / category / severity mappings, the rest `manual`); `control_attestations` (attest manual controls with note, evidence URL, expiry); `internal/evidence`: one printable evidence report per framework (`/projects/{id}/compliance/{framework}/report`, replaces `/cra-report`, Art. 14 section for eu-cra).
- ✅ 8.18 Permission audit (DD 3.5.100): for each user, everything they can
  reach and the grant that gives it (direct, team, org admin, SSO mapping).
  Filterable and CSV-exportable.
  ✅ `internal/access`: `GET /permissions` (+ export) and `GET /projects/{id}/access`, built on `membership.ProjectGrantsSQL`, the same rows `RoleOnProject` authorizes with (a randomized test checks they agree); names the SSO mappings behind synced grants.
- ✅ 8.19 Prometheus metrics (DT v5): a `/metrics` endpoint (optionally on a
  separate management port) exposing ingest queue, outbox, sweeps, feeds and
  HTTP metrics, next to the existing OpenTelemetry export.
  ✅ `METRICS_ENABLED` / `METRICS_ADDR` / `METRICS_TOKEN`: the OTel Prometheus exporter on the same MeterProvider; job runs, durations and last success for every background job; outbox and queue gauges; HTTP by route template, with the Host header dropped from labels; Helm port and ServiceMonitor.
- ✅ 8.20 MCP server (SecObserve `secobserve-mcp`): tools for AI agents to
  search and triage findings, upload scans and SBOMs, read the fix plan and
  generate VEX. They run under the caller's token and RBAC.
  ✅ `internal/mcp` (`MCP_ENABLED`): Streamable HTTP JSON-RPC at `POST /api/v1/mcp` with 10 tools, each run as an in-process API sub-request with the caller's token (authz, project-token confinement and audit unchanged; audit `changes.via = mcp:<tool>`); `xila mcp` stdio bridge.
- ✅ 8.21 Opt-in AI-assisted triage (DD Sensei / Triage Engine AI steps): a
  bring-your-own model proposes a false-positive verdict, an exploitability
  assessment or a fix. A proposal is not applied until a person (or an
  explicit rule) approves it, and every proposal is recorded.
  ✅ `internal/aitriage` (083, `AI_TRIAGE_ENABLED`): openai-compatible / anthropic providers via netguard; proposals are recorded and not applied until a person accepts (through the normal `withActor`, assessment or risk-acceptance paths); exact prompt preview, secret redaction, per-project opt-out and rate limit; strict output parsing. There is deliberately no auto-apply rule action.
- ✅ 8.22 AI inventory / ML-BOM (DD AI inventory beta): ingest CycloneDX
  ML-BOM components (models, datasets, AI services) with policy subjects for
  them, so unapproved models become findings.
  ✅ (084) CycloneDX ML-BOM models, datasets and AI services stored with `kind` + model-card facts; `?kind=` filters and export columns; policy subjects `component.kind`, `model.name/supplier/license/task`, `dataset.name`; AI inventory view; fixtures from CycloneDX's specification repo (Apache-2.0).
- ✅ 8.23 More data sources: VulnerableCode (SecObserve), JVN (DT 5.1) and
  ScanCode.io component import (SecObserve).
  ✅ `VULNMATCH_SOURCES` gains `vulnerablecode` (API) and `jvn` (077, JVN iPedia mirror; used for CVE alias enrichment only, not as a standalone source); admin feed rules (`/feed-rules`) mute, re-rate or tag advisories per source before they become findings.
- ✅ 8.24 Finding page polish (DD 3.4.300, SecObserve):
  - inline edit of title, severity, assignee and tags with conflict detection;
  - a planned remediation date;
  - `file:line` deep links into the repository at the scanned commit.
  ✅ (071) `PATCH /findings/{id}/fields`: sticky title/severity overrides (the upsert and triage rules respect them), planned date, `If-Match` → 412 on fields/status/assignee/tags/write-up; every severity writer now recomputes the full priority; `source_url` deep links for GitHub/GitLab/Bitbucket/Azure DevOps/Gitea.
- ✅ 8.25 Internationalised UI (DT: 15 languages, DD: 27): extract the UI
  strings and ship English and German first.

✅ English + German (`web/src/lib/i18n/`, ~1,100 keys): shell, sign-in, reset, dashboard, account, notifications, findings list and finding page; locale-aware dates/numbers and `<html lang>`; pages switch language only when fully translated (`TRANSLATED_ROUTES`). Project pages, fix plan, remediation and admin pages stay English for now. `pnpm check` runs a key/placeholder/plural parity check.
### Deliberately not pursued
MySQL support (SecObserve), a sandbox copy of the instance (DD), CodeCharta
export (SecObserve), and Lucene-style fuzzy CPE matching (DT dropped it in v5;
Xila uses NVD CPE matching).

## M9: Loose ends of M8 and the roadmap (November 2026)

- ✅ 9.1 German UI, every page. All 33 routes are in `TRANSLATED_ROUTES`
  (project pages and their tabs, fix plan, remediation, SBOM and vulnerability
  pages, every portfolio and admin page). About 2,800 keys. Displayed enum values go
  through `labelOf`, dates and numbers through the locale formatters. Shared CRA labels
  read the page locale non-reactively (`$lib/cra.js`). This is safe because the layout
  re-mounts the page on a language switch.
- ✅ 9.2 GitHub check runs with inline annotations. `xila upload|gate --check`
  (action input `check`) creates a check run named after the gate, matched by name and head
  SHA and updated in place. Annotations cover the findings this scan introduced
  (failure for critical/high/KEV), batched at the Checks API's limit of 50 per request and
  capped at 200. Requires `permissions: checks: write`. A 403 produces a warning and does not change
  the exit code.
- ✅ 9.3 Gate depth (085): `baseline_branch` (and `?baseline=` / `--baseline`)
  counts a finding as new only when no open finding with the same fingerprint exists on
  the baseline branch. An unknown baseline returns 404 rather than passing silently.
  `max_risk_score` uses the project summary's own risk formula.
- ✅ 9.4 Scale (087): a load-test harness (`cmd/xila-loadtest`: seeds 1M
  findings, measures HTTP latency and ingest throughput, runs EXPLAIN; refuses any database that
  already has users) and Go benchmarks for the ingest hot paths. At 1M findings it
  found and fixed: compliance as an OR-ed join (28.7 s → 0.35 s per project; the
  rule is now stated as per-type equi-joins and pinned to the old one by a test),
  `/portfolio` (31 s → 2.8 s: per-project matching, fact-only joins, concurrent
  aggregates), unindexed default list order (1.6 s → 6 ms), and the stock
  `random_page_cost` mis-planning the summary (374 → 121 ms; bundled Postgres now
  runs with 1.1). Ingest: about 810 findings/s through the full sync pipeline; index
  cost was too small to measure. Details and remaining limits are in `docs/SCALE.md`.
- ✅ 9.5 SAML Single Logout (086): sign-out sends a query-signed
  `LogoutRequest` to the IdP (sign-out itself stays local to the browser). An IdP's
  `LogoutRequest` (query-signed or enveloped, verified against its metadata
  certificate) ends that user's sessions through a token-version bump and is answered in a
  binding the IdP advertises. `saml_sessions` records NameID and SessionIndex per
  login. Audit action: `auth.sso_logout`.
- ✅ 9.6 API consumers: every operation has an `operationId`
  (`internal/tools/opids`, enforced by a test). Core schemas carry examples taken
  from real responses, and a test fails when an example field is not a documented
  property (it found 9 undocumented response fields). Generated clients are in
  `clients/` (Go via oapi-codegen from a mechanical 3.0 view, TypeScript via
  openapi-typescript + openapi-fetch); see `make clients` and CI `clients-check`.
- ✅ 9.7 Parsers: Nancy, CloudSploit, Arachni, SpotBugs, Fortify (FPR or FVDL),
  Steampipe/Powerpipe benchmarks (including summary-only exports, from a real MIT
  sample). Syft JSON is an SBOM format, not a scanner (`sbom.Parse`).
- ✅ 9.8 SvelteKit 3 (November 2026): config lives in `vite.config.js`, `$lib` is
  `#lib` (package.json `imports`), `$app/stores` is `$app/state`, shallow routing
  uses `goto(…, { shallow: true, replace: true })`, TypeScript 6. The codemod
  (`sv migrate sveltekit-3`) was used only for the config, tsconfig and import
  rewrites: its printer reformats whole files and moves JSDoc casts
  (`(e.target).checked` → `(e.target.checked)`, snippet parameters), so the rest
  was done as text edits. The `cookie` override is gone (kit 3 depends on cookie
  v2). This also clears the two Low advisories fixed only in 3.0.0.
- ✅ 9.9 UI hygiene: svelte-check at 0 errors and 0 warnings.
- ✅ 9.10 Onboarding: `xila-api demo-seed` (idempotent; refuses production
  without `--force`; creates the first admin only on an empty instance, with a
  random password printed once), a getting-started card on an empty home page, and
  `docs/QUICKSTART.md`. ⬜ External penetration test: required before GA; needs an
  outside firm.

## M10: Secrets backends

Today secrets come from the environment, a `.env` file, or `NAME_FILE` (mounted
files from Docker/Kubernetes secrets, Vault Agent, the Secrets Store CSI driver
or External Secrets Operator).

- ⬜ 10.1 Native secrets managers: let any secret setting be a reference that Xila
  resolves at startup, for example `aws-sm://name#key`, `gcp-sm://projects/p/secrets/s`,
  `vault://kv/data/xila#jwt` and `azure-kv://vault/secret`. Each backend uses its
  platform's credential chain (IAM role / IRSA, workload identity, Vault
  Kubernetes or AppRole auth, managed identity). Decide per backend whether to use
  the official SDK or plain HTTP (the GCP client pulls in gRPC), test against
  emulators or `httptest` fakes, and keep a failed lookup a startup error.
- ⬜ 10.2 Rotation: re-read rotatable secrets (database password, API tokens)
  without a restart; `JWT_SECRET` and `INTEGRATION_SECRET_KEY` need a key ring
  first, since rotating them today ends sessions or makes stored secrets unreadable.

## M11: Ingest at scale (1,000 to 1,000,000 repositories at once)

Measured in `docs/SCALE.md` (Parallel ingest): one node ingests about 9,400
findings/s with 16 parallel uploaders. A burst from 1,000 repositories is minutes
of work; a burst from 1,000,000 is about a billion findings and needs the later
items. Server-side `Retry-After` and queue backpressure already exist.

For 1,000 repositories (one node):

- ⬜ 11.1 CLI retries: `xila upload` retries 429/502/503/504 and connection errors
  with exponential backoff and jitter, honouring `Retry-After`, up to a time
  budget. Today it fails on the first 429.
- ⬜ 11.2 Asynchronous ingest by default in the production compose file and Helm
  values, with the queue depth sized for the install.
- ⬜ 11.3 `ingest-bench --concurrency N`, so the parallel measurement is one
  command.

For 100,000 and more (several nodes):

- ⬜ 11.4 Skip unchanged scans: when a report's content hash matches the previous
  scan for the same project, branch, scanner and target, record the scan and
  refresh `last_seen_at` without running the pipeline. Most CI reruns report
  exactly what they did last time.
- ⬜ 11.5 Web and worker roles: allow `INGEST_WORKERS=0` (today it is clamped to 1)
  so API nodes only accept uploads and worker nodes scale on queue age. Document
  a KEDA recipe on `xila_ingest_queue_oldest_wait_seconds` and PgBouncer for more
  than about 5 nodes.
- ⬜ 11.6 Fair queueing: claim jobs round-robin per organization (and at most one
  in flight per project), so one tenant's burst can't starve the others.
- ⬜ 11.7 Live tuning: change the queue depth limit and worker count without a
  restart (Dependency-Track 5 has this).

For 1,000,000 (bursts of a billion findings):

- ⬜ 11.8 Reports outside Postgres: store raw uploads in S3-compatible object
  storage and queue only a reference. A million 1 MB reports is a terabyte of
  queue traffic in the database today.
- ⬜ 11.9 Data lifecycle past 100M findings: serve the portfolio from metric
  snapshots, archive or partition closed findings, cap read queries with a
  statement timeout, move reporting to a read replica.
- ⬜ 11.10 Multi-node load test: 10M findings, 3 API nodes, 1,000-scan bursts;
  record the results in `docs/SCALE.md`.

## M12: Parity review 3 (November 2026)

Compared with DefectDojo Pro 3.5.103, Dependency-Track 5.2.1 and SecObserve
1.64.0 (sources and evidence in the review notes of this milestone's PR). Only
gaps that are still open are listed; each was checked against the code.

Tier 1:

- ⬜ 12.1 Cross-tool dedup without a CVE (SecObserve): group findings across
  scanners by file and line, or by title and component, so SAST, secrets and DAST
  duplicates collapse like CVE findings do. Today `correlation_key` is NULL for
  any finding without a CVE.
- ⬜ 12.2 Upload-only role (SecObserve): a project grant that can upload scans
  and SBOMs and nothing else, for CI tokens. Today CI needs `editor`, which can
  also triage.
- ⬜ 12.3 Cross-project root causes (DefectDojo Pro): one work item per shared
  cause (CVE, component version) across every project, beyond the per-project
  remediation actions.
- ⬜ 12.4 No-code parser (DefectDojo Pro "Universal Parser"): map fields of any
  CSV, JSON or XML report to findings from the UI.
- ⬜ 12.5 Vulnerability policies (Dependency-Track 5): CEL rules on a component and
  vulnerability pair that set an analysis or rating atomically at ingest, with a
  validity window, priority, and GitOps policy bundles.
- ⬜ 12.6 More pull connectors: Snyk, GitHub code scanning and Dependabot alerts,
  GitLab vulnerability reports, Wiz, Tenable (DefectDojo Pro has 140+; Xila pulls
  from Dependency-Track and DefectDojo only).

Tier 2:

- ⬜ 12.7 More issue trackers: Azure DevOps, Linear, ServiceNow.
- ⬜ 12.8 Custom roles and user groups, and SCIM provisioning.
- ⬜ 12.9 Security gate caps for every severity (medium, low, unknown), not only
  critical and high.
- ⬜ 12.10 Links out to NVD, GitHub Advisories and deps.dev from findings and
  components.
- ⬜ 12.11 KEV ransomware-use flag (`knownRansomwareCampaignUse`) on findings.
- ⬜ 12.12 A "My work" page: assigned findings, approvals, expiring acceptances
  and AI proposals in one queue.
- ⬜ 12.13 Kafka notification publisher.
- ⬜ 12.14 Strict CycloneDX schema validation on upload, with field paths in errors.
- ⬜ 12.15 Per-project priority weights.
- ⬜ 12.16 Smaller items: computed custom fields, triage rule chaining, splitting
  a multi-host infrastructure scan per asset, re-authentication before creating
  API tokens, CryptoLyzer and DrHeader parsers.

Deliberately not pursued: FedRAMP POA&M and OSCAL export (US federal niche),
threat modeling, AI-generated fix pull requests, active cloud scanning (Xila
ingests scanner output and doesn't scan), pushing findings to other platforms.

