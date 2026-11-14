# Xila: 90-Day Roadmap

> Feature-parity work against DefectDojo, SecObserve and Dependency-Track is
> tracked in [MILESTONES.md](MILESTONES.md).

Vision. One platform to find, prioritize, and fix security issues across
code, dependencies, and configuration, with the noise removed. We unify what
teams currently buy as four tools:

| Reference | What we take from it |
| --------- | -------------------- |
| DefectDojo | Vulnerability aggregation, dedup, triage lifecycle |
| Dependency-Track | SBOM history, component inventory, "who ships package X" |
| SonarQube | SAST intake and quality/security gates on PRs |
| Aikido | Dev-first workflow and noise reduction / prioritization (EPSS, KEV, reachability) |

Strategy in one line: win the adoption loop. *Get data in easily, cut the
noise, then prove and enforce value in the SDLC.* We sequence the quarter along
that loop and do not build our own scanners yet. Instead, we ingest and
normalize the best OSS scanners. That is the fastest path to breadth without
overextending.

---

## Where we are today (baseline)

Already shipped (boilerplate → early product):

- Ingestion and lifecycle (DefectDojo core): persistent, deduplicated findings;
  reopen-on-reappearance; auto-close when a scanner stops reporting; triage
  states. One parser (Trivy) via a pluggable `scanner.Parser` registry.
- SBOM (Dependency-Track core): CycloneDX and SPDX; immutable historical
  snapshots; cross-project component search.
- Correlation (differentiator): each finding is linked to the SBOM component
  that introduced it.
- License policy → findings. Risk score weighted by business criticality.
- Platform: Go/Fiber + Postgres, OpenTelemetry, JWT auth, pagination, CI, a
  three-tier test suite, and a single-bundle distroless image (SvelteKit +
  daisyUI UI embedded in the API binary).

Gaps vs. the four references: single scanner and manual upload; no
SCM/CI integration; no exploit-aware prioritization; single-user auth (no
orgs/RBAC/SSO); no gates; no notifications; thin dashboards.

---

## Foundation sprint (Weeks 1–2, before Milestone 1)

These are expensive to retrofit, so they go first to avoid rework:

- Team-scoped RBAC: ✅ *shipped.* Per-team roles (`owner`/`editor`/`viewer`)
  in `team_members` plus a global admin (the first user bootstraps). A central
  `authz.Middleware` denies by default and resolves each route to its owning
  team. Portfolio-wide lists are filtered to the caller's teams.
- Organizations: ✅ *shipped.* `Organization → Team → Project`. Org roles
  (`admin`/`member`) live in `org_members`. Teams belong to an org, and org admins get
  owner-equivalent access to every team in their org. Existing installs are
  migrated into a "Default" organization.
- SSO (OIDC): ✅ *shipped (starter).* Optional OpenID Connect login
  (`internal/oidc`, off by default), alongside password auth. It links by
  verified email and mints the normal JWT, so RBAC is unchanged. *Follow-ups:*
  per-org SSO providers (now that Org exists), SCIM/JIT group→role mapping, and
  SAML for enterprise buyers. Per-project notification-channel management by team
  editors (currently admin-only) is still open.
- API tokens / service accounts: non-human credentials for CI ingestion
  (a prerequisite for everything in Milestone 1).
- Async ingestion: ✅ *shipped.* `INGEST_ASYNC=true` makes uploads persist
  their payload and a `processing` scan, then return `202`. A worker pool drains a
  durable Postgres `SKIP LOCKED` queue (`scan/queue.go`) off the request path,
  with stale-lock reclaim and retries. It scales with `INGEST_WORKERS`, is safe with multiple
  instances, and needs no new infrastructure. The `xila` CLI polls the scan to completion before gating.
  Findings are written with pipelined batch upserts (`finding.UpsertBatch`),
  so a report's latency isn't a multiple of the round-trip time. Dedup only
  writes rows that change (it used to rewrite every finding in the
  project on every scan) and runs under a per-project advisory lock. Hot paths are covered
  by partial indexes on the active backlog (`000023_hot_indexes`), and every
  pooled connection has a `statement_timeout`.
  The post-ingest tail (auto-triage and dedup) is scoped to the scan rather than
  the whole project, so ingest cost tracks the size of the upload instead of the
  project's accumulated history. A full recompute remains the backfill path for
  rule changes.
  The queue is observable and sheds load. Depth and oldest wait are exported as OTel
  gauges and served by `GET /ingest/queue`. Uploads past `INGEST_MAX_QUEUE_DEPTH` get `429 + Retry-After`
  instead of being accepted into a backlog we can't
  drain.
  *Follow-ups:* partition `findings` once a single project's backlog outgrows one
  table, and add per-org rate limits on ingestion.

*Exit:* an org with roles, a CI token that can push scans, and ingestion that
scales past a single request.

---

## Milestone 1: "Get everything in" (Month 1)

Goal: a team wires Xila into their pipeline once and sees all their findings,
deduped across tools, with no manual uploads.

| Epic | Why | Definition of done |
| ---- | --- | ------------------ |
| SARIF parser | One format covers Semgrep, CodeQL, and many SAST/DAST/IaC tools, which multiplies coverage | SARIF from Semgrep + CodeQL ingests as SAST findings |
| +3 native parsers (Grype/OSV, Gitleaks, Checkov/tfsec): ✅ shipped, with more than planned. 9 native parsers added: Grype, OSV-Scanner, npm audit, Dependency-Check, govulncheck, Gitleaks, TruffleHog, ZAP, Nuclei. They cover SCA, secrets and (newly) DAST. Two carry signals no other parser provides: govulncheck's call-graph reachability (whether the vulnerable function is called) and TruffleHog's verification (whether the leaked credential is live). | Each maps to the normalized model + category |
| GitHub Action `xila-scan` | The adoption mechanism: run scanners + upload on every push | Action ingests ≥3 tools into a project on push |
| Thin CLI (`xila upload`) | CI-agnostic path (GitLab, Jenkins) | Documented, uses API token |

Outcome: findings from 4–5 tool types flow in automatically and deduplicate.

---

## Milestone 2: "Cut the noise & prioritize" (Month 2)

Goal: turn thousands of raw findings into a ranked, trustworthy backlog. This
is the Aikido-style differentiator and where we earn trust.

| Epic | Why | Definition of done |
| ---- | --- | ------------------ |
| Enrichment service (EPSS, CISA KEV, CVSS via OSV.dev/NVD) | Exploitability, not just severity, drives priority | Findings show EPSS %, KEV flag, CVSS; nightly refresh |
| Continuous SBOM monitoring (OSV): ✅ *shipped.* `internal/vulnmatch` matches every SBOM snapshot against OSV.dev on upload and on a schedule (`VULNMATCH_*`). Each snapshot keeps its own matches, so history stays answerable (see `docs/MILESTONES.md` M2). The current snapshots' hits are recorded as an `osv` scan, so a stored SBOM keeps producing current risk: newly disclosed CVEs appear without a re-scan, and upgraded dependencies auto-close. Reuses the whole pipeline (dedup, auto-triage, EPSS/KEV priority, gates, alerts). *Follow-ups:* advisory-driven "new CVE affects you" notification, and OSV mirroring for air-gapped installs. | A stored SBOM is a live asset, not a static file |
| Reachability v1 (heuristics): ✅ *shipped.* The SBOM's own dependency graph (CycloneDX `dependencies`+`scope`, SPDX relationships) gives each finding `dep_direct`/`dep_depth`/`dep_scope`. Priority is discounted for transitive (×0.8), optional (×0.5) and dev-only (×0.25) dependencies. Unknown never discounts, and discounting never suppresses. `?reachable=true` filters, and triage rules can condition on scope/transitivity. Re-scored whenever a new SBOM lands. *Follow-ups:* call-graph reachability by ingesting it from a tool that emits it (we don't do program analysis), and per-ecosystem confidence in the depth signal. | "Direct only" / "runtime only" filters |
| Xila Priority score | Blend severity × EPSS × KEV × criticality × reachability | Findings sortable by one defensible number |
| Cross-tool dedup: ✅ *shipped.* Findings are grouped by a scanner-agnostic correlation key (min CVE + package). A primary is elected per group, and duplicates (`duplicate_of`) are hidden from lists/counts/risk/alerts/triage, recomputed on every ingest. Per-scanner provenance and lifecycle are preserved; primaries are badged with a tool count (`?include_duplicates`, `/findings/{id}/duplicates`). Scoped to CVE-bearing findings. *Follow-ups:* fuzzy identity for non-CVE findings, and a "merged view" that unions metadata across the group. | Dedup key spans scanners, not just one |
| VEX ingestion: ✅ *shipped.* `internal/vex` stores OpenVEX / CycloneDX VEX statements per project and re-applies them on every ingest. `not_affected`/`fixed` suppress the finding (as a sticky triage state, with the justification in its audit trail); `affected` confirms it. An analysis is made once instead of being re-derived on every scan. *Follow-ups:* VEX export (publish your own analysis downstream), and org-wide statements. | An analysed CVE does not return to the queue |
| Triage workflow: ✅ *shipped* (M3, see `docs/MILESTONES.md` 3.2). Assignee, comments, attachments, a trigger-written per-finding history, and bulk status/severity/assignee edits by selection or filter. Suppressions with expiry are covered by the existing exceptions and auto-triage rules. | Analysts can clear a backlog quickly |
| Auto-triage rules: ✅ *shipped.* `internal/triage`: persistent *conditions → action* rules (suppress / accept / won't-fix / downgrade) applied automatically on every ingest and to the backlog. First match wins; rules are admin-managed, global or per-project, and apply uniformly across appsec / SCA / CSPM / KSPM. *Follow-ups:* rule hit-counts/metrics, bulk manual triage, cross-tool dedup, and a reachability signal to feed conditions. | |

*Outcome:* the default view is a short, exploit-aware list: "fix these 12,"
not "here are 4,000."

---

## Backlog (agreed, not started)

Ordered by leverage, kept here so the next session doesn't have to re-derive it:

1. ~~PR comments from the GitHub Action~~: ✅ *done.* `xila upload --comment`
   posts the gate verdict and the findings the PR introduces (with KEV/EPSS and
   reachability flags, and the fix version) as a sticky comment, edited in place
   on each push. Best-effort: it does not change the build's exit code. It needed a new
   `GET /findings?scan_id=…&new=true` filter, which the UI can also use.
2. ~~Parser breadth as a contributor surface~~: ✅ *done.* Native parsers for
   Grype, OSV-Scanner, npm audit, OWASP Dependency-Check, govulncheck, Gitleaks,
   TruffleHog, ZAP and Nuclei, on top of Trivy, generic SARIF and the CSPM/KSPM set.
   `docs/PARSERS.md` documents the interface, the non-obvious rules, and a
   "wanted" list for contributors. *Next:* Snyk, tfsec/Terrascan, pip-audit,
   detect-secrets, Clair, kube-bench.
3. Asset exposure as a priority signal: an `exposure` flag on assets
   (internet-facing vs internal) used as a multiplier. It approximates what an attack-path graph provides at about 1% of the cost, using a table we already have.
4. ASPM table stakes: Jira/ServiceNow sync (another `notify` channel type),
   SLA/due dates and breach counts (✅ *done*, see `docs/MILESTONES.md` M1), and an audit
   log. Nobody buys *for* these, but enterprises won't buy *without* them.

5. ~~API documentation~~: ✅ *done.* OpenAPI 3.1 spec embedded in the binary
   (`internal/apidoc/openapi.yaml`), served at `/api/v1/openapi.{json,yaml}` and
   rendered by the UI at `/docs`. A drift test walks Fiber's route table and fails
   the build if the spec and the API disagree in either direction. *Follow-ups:*
   request/response examples per operation, and a generated Go/TS client.

Deliberately out of scope: agentless cloud scanning and attack-path graphs
(Orca/Wiz's moat; it would break the "one binary + Postgres" property), and any
in-house scanner.

## Milestone 3: "Prove & enforce" (Month 3)

Goal: make Xila part of the SDLC decision and the reporting loop.

| Epic | Why | Definition of done |
| ---- | --- | ------------------ |
| Security Gates: ✅ *shipped.* `internal/gate`: per-project and global-default policies (`max_critical`/`max_high`/`block_kev`/`max_epss`/`block_license`) evaluated against the deduped, triaged backlog. `POST /projects/{id}/gate` returns 200 pass / 422 fail with violations and stats; optional inline policy; Gate UI tab. *Follow-ups:* gate on *new* (diff between scans), a `xila` CLI and GitHub Action, and more conditions (risk score, SLA breach). | Gate result returned to CI as pass/fail |
| CI client + GitHub Action: ✅ *shipped.* `cmd/xila` (stdlib CLI: `upload`/`gate`, non-zero exit fails the build) plus a composite `action.yml`. The gate takes 3 lines of CI YAML. *Follow-ups below (PR checks and inline comments, new-only gating).* | - | - |
| GitHub App: PR checks + comments | Meet devs where they work; block risky merges | PR introducing a KEV vuln fails the check with an inline comment |
| "New vs. total": ✅ *shipped.* `new_only` gate mode (policy flag / `xila gate --new`) fails only on newly introduced findings, meaning those seen in one scan so far (`first_scan_id = last_scan_id`), so PRs aren't blocked by pre-existing debt. Composes with dedup. *Follow-ups:* baseline-branch diffing (against a named ref rather than "seen once"). | New-code findings computed per PR |
| Notifications (Slack, email, Jira issue creation): ✅ *shipped* (M1/M3). Slack, webhook, Teams, Mattermost, SMTP email, SLA breach/due-soon alerts, and Jira/GitHub/GitLab issue creation with two-way sync. | Close the loop to humans; SLA breach alerts | New-critical → Slack; aging → SLA alert |
| Dashboards & trends: ✅ *shipped* (M4). Daily metric snapshots with a 90-day backfill, portfolio / org / team / project trends, CSV/XLSX exports, and printable project and portfolio reports. | Exec/PM value: MTTR, SLA compliance, 90-day trend (needs metric snapshots) | Portfolio trend + per-team + exportable report |
| SSO / OIDC login: ✅ *shipped*. OIDC (PKCE) and SAML 2.0, IdP group → role sync, JIT provisioning, optional password-login shutdown. | Enterprise entry requirement | Login via an OIDC provider |

*Outcome:* a PR that introduces a critical or known-exploited vuln is stopped with an
inline explanation, the team gets a Slack ping, and leadership sees the trend.

---

## Cross-cutting (every milestone)

- Dogfood: Xila scans Xila in CI. A security product should set the example.
- Scale: findings will reach millions, so we need indexing, partitioning, and load tests.
- Platform security: authz tests, secret handling, and a pen-test before GA.
- Onboarding: seed data, docs, and a 5-minute "first finding" path.

## Explicitly out of scope this quarter (scope control)

First-party/hosted scanning engines, DAST engine, cloud/CSPM, container-registry
scanning, AI autofix PRs, and a full ASPM asset graph. These are planned for the next two
quarters. For now we integrate best-of-breed scanners and compete on
aggregation, prioritization, and workflow.

## KPIs we steer by

- Activation: % of projects with automated (CI) ingestion within 7 days.
- Time to first finding.
- Noise: findings per project before vs. after enrichment; % suppressed; FP rate.
- Value: gate checks run per week; MTTR; SLA compliance.

## Top risks & mitigations

| Risk | Mitigation |
| ---- | ---------- |
| Trying to be four products at once | Sequence intake → prioritize → enforce; ingest scanners rather than build them |
| Cross-tool dedup is hard | Standardize on SARIF and a robust normalization/dedup key; invest early |
| Enrichment data freshness/licensing (NVD limits) | Prefer OSV.dev, EPSS, and KEV feeds; cache aggressively |
| Multi-tenancy retrofitted late | Do RBAC/orgs in the Foundation sprint |
| Scale surprises | Async ingestion, indexes, and load testing from M1 |

## Team & critical path

Assumes ~4 engineers (2 backend, 1 frontend, 1 integrations), plus part-time design,
PM, and a security advisor. If the team is smaller, the critical path is: SARIF + GitHub Action
(M1) → EPSS/KEV + Priority score (M2) → Gates + PR checks (M3). Those three alone make
a credible, differentiated product.

