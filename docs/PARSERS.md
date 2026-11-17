# Adding a scanner

Xila does not scan anything itself. It ingests what your tools already produce
and normalizes it into one deduplicated, prioritized backlog. Support for a
new tool is one file, which makes it a good first contribution to this project.

Everything downstream (dedup, auto-triage, EPSS/KEV priority, reachability,
compliance mapping, CI gates, alerts) works on the normalized model. You don't
need to touch any of it.

## What you write

A parser is three methods:

```go
type Parser interface {
	Scanner() string                        // "gitleaks": the stable API identifier
	PrimaryCategory() domain.Category       // the scan-level category
	Parse(io.Reader) ([]ParsedFinding, error)
}
```

Put it in `internal/scanner/<tool>.go`, register it in `scanner.NewRegistry(...)`
in both `cmd/api/main.go` and `internal/server/smoke_test.go`, add a preset to
`web/src/lib/scanners.js`, and write a test with a real sample report.

## Filling in ParsedFinding

Only `Title` and `Severity` are required, but the fields you populate
determine how much the platform can do with the finding:

| Field | Why it matters |
| ----- | -------------- |
| `RuleID` | Feeds compliance mapping (`match_type='rule'`) and is the stable identity of the check. |
| `CVE` | Feeds cross-tool dedup and EPSS/KEV enrichment. Without it, the same vulnerability from two tools counts twice. |
| `Package` / `PackageVersion` / `Purl` | Feeds dedup, SBOM correlation, and reachability (is this dependency shipped at all?). |
| `CWE` | Feeds compliance mapping (`match_type='cwe'`, tool-agnostic). This is how a Semgrep finding maps to OWASP A03. |
| `FixedVersion` | The remediation. Include it if the tool knows it. |
| `FilePath` / `Line` | Where a human goes to look. For DAST, use the URL the finding was proven on. |
| `Metadata` | Anything tool-specific worth keeping (commit, confidence, verification status, etc.). |

Extract the CVE even when it isn't the tool's primary ID. Grype reports
`GHSA-jfh8-…` and lists `CVE-2021-44228` under `relatedVulnerabilities`. Dedup
groups on the CVE, so `cvesFrom(ids...)` pulls it out. Without this, you get
duplicates instead of a unified backlog.

## Shared helpers (use them)

Every tool spells severity differently. Don't re-invent the mapping:

- `normalizeSeverity(s)` handles `critical`/`important`/`moderate`/`negligible`/
  `note`/`warning`/… Unrecognized values become medium, not info: a finding we
  can't rank must stay visible.
- `severityFromCVSS(score)` is for tools that give a score but no rating.
- `cweFrom("CWE-79")`, `cvesFrom(ids...)`, `floatPtr`, `intPtr`.
- `decodeJSONLines(r, fn)` is for tools that stream one JSON object per line
  (TruffleHog, Nuclei, govulncheck).
- `cvesInText(texts...)` extracts CVEs named only in prose (an RHSA title, a Nikto
  message, a reference link), deduplicated.
- `mergeSameLocation(findings)` is for tools whose check id is generic (Nikto's
  "uncommon header", Wapiti's categories). Several observations of one check at
  one location share an ingest fingerprint and would overwrite each other, so fold
  them into one finding first.

## Rules that aren't obvious

Map only what failed. A passed check is not a finding. Posture tools
(Prowler, Kubescape) report every control they evaluated. Emit only the failures,
or the real ones get buried.

Don't invent a severity gradient the tool doesn't have. Gitleaks emits no
severity, so every leaked credential is `high`: the secret is in the history
and must be rotated either way. Faking precision is worse than admitting you have
none.

**Reject malformed input.** A parser that returns zero findings on a garbage
upload makes a broken pipeline look green for months. There's a test for this.

Don't duplicate an advisory across packages. npm audit lists a package as
vulnerable "via" a dependency; the advisory belongs to the dependency. Emitting it
on both creates the noise this platform exists to remove.

## Prefer native JSON to SARIF

We already accept generic SARIF (`?format=sarif`), which covers Semgrep,
CodeQL, Checkov, Hadolint, KICS and many others. But SARIF is lossy: it
drops PURLs, fix versions, CVSS, and tool-specific evidence. If a tool has a
native JSON format that carries those, write the native parser. It gives you dedup,
reachability and enrichment that the SARIF path can't.

## A test is not optional

Paste a real report fragment from the tool (trimmed, not invented) and assert
the mapping. The test is the spec: it shows the next person that the format
didn't drift. See `internal/scanner/parsers_test.go`. Every parser has one, and
they document what the tool actually emits.

```bash
go test ./internal/scanner/    # fast, no database needed
```

## Currently supported

| Tool | Format | Category |
| ---- | ------ | -------- |
| Trivy | native JSON | SCA / secrets / IaC / container |
| Grype | native JSON | SCA |
| OSV-Scanner | native JSON | SCA |
| npm audit | native JSON (v2) | SCA |
| OWASP Dependency-Check | native JSON | SCA |
| govulncheck | JSON stream | SCA (call-graph reachability) |
| Gitleaks | native JSON | secrets |
| TruffleHog | JSONL | secrets (verified = live credential) |
| OWASP ZAP | native JSON | DAST |
| Nuclei | JSONL | DAST |
| Prowler | native JSON | cloud (CSPM) |
| Kubescape / kubeaudit | native JSON | Kubernetes (KSPM) |
| Checkov (`checkov`) | native JSON (single or multi-framework list) | IaC (SCA/secrets frameworks mapped too) |
| tfsec (`tfsec`) | native JSON (current + legacy schema) | IaC |
| Terrascan (`terrascan`) | native JSON | IaC |
| ScoutSuite (`scoutsuite`) | results `.js` / JSON (one finding per flagged resource) | cloud (CSPM) |
| Clair (`clair`) | v4 / clairctl VulnerabilityReport JSON, clair-scanner JSON | container |
| Anchore Enterprise (`anchore`) | `anchorectl image vulnerabilities -o json` / API JSON | container |
| Docker Scout (`docker-scout`) | `docker scout cves --format sarif` (reads Scout's PURL/fix/CVSS extensions) | container |
| Polaris (`polaris`) | audit JSON | Kubernetes (KSPM) |
| kube-bench (`kube-bench`) | `--json` (FAIL = medium, WARN = low; rule = CIS check no.) | Kubernetes (KSPM) |
| Burp Suite (`burp`) | XML issue export | DAST |
| Nikto (`nikto`) | JSON or XML (sniffed; no severity → low) | DAST |
| Wapiti (`wapiti`) | JSON | DAST |
| Nmap (`nmap`) | XML: open ports (info), `vulners` CVEs, `--script vuln` hits | DAST (network) |
| Snyk Open Source (`snyk`) | `snyk test --json`, single object or `--all-projects` array (license issues → license) | SCA |
| pip-audit (`pip-audit`) | `--format json` (current `{"dependencies":…}` and pre-2.5 bare array; no severity → medium) | SCA |
| Safety (`safety`) | `safety check --output json` (2.x schema; policy ignores → risk accepted). `safety scan` JSON is rejected because it has no CVE/severity | SCA |
| cargo-audit (`cargo-audit`) | `--json` (severity from the RustSec CVSS v3 vector; unmaintained/unsound/notice warnings → low) | SCA |
| Retire.js (`retirejs`) | `--outputformat json` (v2 `{"data":…}` and v1 array) | SCA (vendored JS) |
| bundler-audit (`bundler-audit`) | `check --format json` | SCA |
| Semgrep (`semgrep`) | native `--json` (incl. Supply Chain `sca_info`; `nosemgrep` → false positive) | SAST / SCA |
| Bandit (`bandit`) | `-f json` | SAST |
| gosec (`gosec`) | `-fmt json` (`#nosec` with `-track-suppressions` → false positive + justification) | SAST |
| Brakeman (`brakeman`) | `-f json` (confidence is its only ranking → high/medium/low; `ignored_warnings` → false positive) | SAST |
| detect-secrets (`detect-secrets`) | baseline JSON (one finding per line; audited `is_secret` carried) | secrets |
| GitGuardian ggshield (`ggshield`) | `secret scan … --json` (one finding per incident+file; valid → critical) | secrets |
| Hadolint (`hadolint`) | `-f json` (error → medium, warning → low; info/style skipped) | IaC |
| KICS (`kics`) | results JSON (one finding per query × file location; INFO/TRACE skipped) | IaC |
| ESLint (`eslint`) | `-f json` (severity 2 → medium, 1 → low) | SAST |
| yarn audit (`yarn-audit`) | Yarn 1 NDJSON, Yarn 2/3 `npm audit` JSON, Yarn 4 NDJSON (an `error` event fails the upload) | SCA |
| njsscan (`njsscan`) | `--json` | SAST |
| Bearer CLI (`bearer`) | `--format json` | SAST |
| MobSF (`mobsf`) | `report_json` (Android/iOS: manifest, code, binary, certificate) and mobsfscan JSON | SAST (mobile) |
| SonarQube (`sonarqube`) | issues / hotspots API JSON, security only (VULNERABILITY, hotspots, SECURITY impact); FALSE-POSITIVE / WONTFIX / SAFE carried | SAST (Dependency-Check plugin issues → SCA) |
| Checkmarx CxSAST (`checkmarx`) | detailed XML (one finding per query × sink; Not Exploitable → false positive) | SAST |
| Veracode (`veracode`) | detailed XML (static + dynamic flaws, SCA CVEs; accepted mitigations carried) | SAST / DAST / SCA |
| Mend (`mend`) | platform API 3.0, legacy, and CLI JSON (sniffed; IGNORED → risk accepted) | SCA |
| JFrog Xray (`jfrog-xray`) | Unified vulnerabilities JSON (package = the vulnerable component) | SCA |
| AWS Inspector2 (`aws-inspector2`) | `list-findings` JSON (ECR → container, EC2/Lambda → SCA, code → SAST; SUPPRESSED → risk accepted) | cloud |
| AWS Security Hub (`aws-security-hub`) | ASFF `get-findings` JSON (PASSED / ARCHIVED / RESOLVED skipped; SUPPRESSED → risk accepted) | cloud |
| Tenable Nessus (`nessus`) | `.nessus` XML or Tenable / Tenable.sc CSV (sniffed; severity 0 skipped) | DAST (network) |
| OpenVAS / Greenbone (`openvas`) | XML report (Log/Debug skipped) | DAST (network) |
| Qualys VM (`qualys`) | scan report XML or CSV (sniffed; information-gathered skipped) | DAST (network) |
| Acunetix (`acunetix`) | classic XML or Acunetix 360 JSON (sniffed; false positives carried) | DAST |
| Invicti / Netsparker (`invicti`) | JSON (FalsePositive / AcceptedRisk / Ignored carried) | DAST |
| testssl.sh (`testssl`) | `--csvfile` (OK/INFO/WARN skipped; a FATAL-only report fails the upload) | DAST (TLS) |
| DefectDojo Generic Findings Import (`defectdojo-generic`) | `{"findings":[…]}` JSON | any (inferred per finding) |
| SecObserve (`secobserve`) | REST observation list `GET /api/observations/` (page or concatenated `results`), or SecObserve's import format | any (parser type) |
| Nancy (`nancy`) | `nancy sleuth --output=json` (OSS Index match against a Go module list; `Excluded` entries skipped) | SCA (Go) |
| Steampipe / Powerpipe (`steampipe`) | compliance-mod benchmark JSON (`steampipe check … --export json` / `powerpipe benchmark run … --output json`; alarm/error controls, a control that failed to execute gets one finding) | cloud (CSPM) |
| CloudSploit (`cloudsploit`) | native JSON results array (FAIL entries; no severity → medium) | cloud (CSPM) |
| Arachni (`arachni`) | `arachni_reporter --reporter json` JSON report (every issue is a finding; there are no "passed" entries) | DAST |
| SpotBugs (`spotbugs`) | native XML (`-xml -output`; priority 1/2/3 → high/medium/low; CWE from a FindSecBugs-annotated `BugPattern`) | SAST |
| Fortify (`fortify`) | `audit.fvdl`, bare or zipped inside the `.fpr` results archive (severity from the engine's impact×likelihood model when `EngineData` is present, else the rule/instance severity) | SAST |
| CodeQL, … | SARIF | SAST / IaC |

### Import formats and carried triage

Some uploads carry a decision made elsewhere: DefectDojo `false_p` / `risk_accepted`
/ `out_of_scope` / `verified`, a SecObserve assessment (`current_status`, risk-acceptance
expiry), a Safety policy ignore, an audited detect-secrets baseline, a justified `#nosec`,
or Brakeman's ignore file. These record the verdict in finding metadata (`remote_triage`,
`remote_triage_reason`, optional `remote_triage_expires`), the same keys the pull
connectors use. The last ingest pass (`connector.RemoteTriage`) applies it **only to
findings that scan created and that are still open**. Re-uploading an export does not
overturn an existing finding's local triage, and an acceptance that has already lapsed
is not applied. Mitigated, resolved, and duplicate entries in an export are skipped (they are history,
not work). SecObserve has no machine-readable file export (CSV/Excel only), so pull its
REST observation list. To keep the original tool identity, upload with
`?scanner=<tool>&format=defectdojo-generic` (or `format=secobserve`).

## No-code parsers

Not every tool is worth a Go file. An instance admin can map a CSV, JSON or
XML report onto findings from the UI (**Custom Parsers**, admin-only) or
`POST /custom-parsers`: a scanner name (a lowercase slug that must not collide
with a built-in parser's name), a category, the format, a record selector
(where the repeated records live, json: a dotted path to the array, or `$`
for a top-level array; xml: an element path; csv: unused, the header row
already defines each record), and a mapping per `ParsedFinding` field. Each
mapping is a record path/column, a static value, a `"{path} in {path2}"`
template over other paths in the record, or (severity only) a value map from
the tool's raw text to our vocabulary (e.g. `{"4": "critical"}`), falling back
to `normalizeSeverity` otherwise. `POST /custom-parsers/dry-run` previews a
(saved or draft) definition against a pasted sample without storing anything.

Once saved, upload with `?scanner=<name>` like any built-in tool, the
ingest path falls back to the no-code definition when the static registry has
no match, so dedup, triage, priority, gates and alerts all work unchanged. The
resolved parser is cached and re-read by the definition's `updated_at`, so an
edit on one node takes effect on every replica's very next upload, not after
a restart. Deleting a definition keeps its findings, they stay under that
scanner name as history, like removing support for a built-in parser would.

This is the same compiler + mapping engine as a built-in parser
(`internal/scanner/custom.go`): it reuses `normalizeSeverity`, `cweFrom`,
`cvesInText` and `mergeSameLocation` rather than re-deriving them, and its XML
reader never resolves external entities (no XXE), like every XML parser in
this repo.

## Syft

Syft (`syft <target> -o json`) is an SBOM generator, not a vulnerability scanner.
It reports packages, not findings, so it isn't a `scanner.Parser`. Its native
JSON format is accepted by `sbom.Parse` (`internal/sbom/syft.go`), alongside
CycloneDX, SPDX and ScanCode.io. Upload it through the SBOM endpoints and it
gets the same history, license resolution and OSV matching as a CycloneDX or
SPDX SBOM. Grype, which matches a Syft SBOM against advisories, is the
scanner; see `grype.go`.

