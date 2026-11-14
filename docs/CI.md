# Scanning in CI

Two ready-made templates run the scanners for you, upload every report to Xila
and enforce the security gate once at the end:

| Template | Path |
|---|---|
| GitHub composite action "Xila Scan" | `ci/github/scan/action.yml` |
| GitLab CI include | `ci/gitlab/xila-scan.gitlab-ci.yml` |

Each scanner runs from its official container image at a pinned tag. A scanner
that exits non-zero because it *found* something never fails the job — the
**gate** decides (exit 1 on policy violations). A scanner that produces no
report at all is an error.

If you already produce reports yourself, the repo-root action (`uses:
xilasec/xila-api@<ref>`, see the README section "Break the build in CI") only
uploads one report.

## Scanners

| Template scanner | Image | Report | `xila upload --scanner` |
|---|---|---|---|
| `trivy-fs` / `.xila-trivy` | `aquasec/trivy:0.58.1` (`fs`) | JSON | `trivy` |
| `trivy-image` / `.xila-trivy` + `XILA_TRIVY_IMAGE` | `aquasec/trivy:0.58.1` (`image`) | JSON | `trivy` |
| `grype` / `.xila-grype` | `anchore/grype:v0.86.1` (GitLab: `-debug`, which has a shell) | JSON | `grype` |
| `osv-scanner` (GitHub only) | `ghcr.io/google/osv-scanner:v1.9.2` | JSON | `osv-scanner` |
| `semgrep` / `.xila-semgrep` | `semgrep/semgrep:1.99.0` (`--config auto`) | SARIF | `semgrep --format sarif` |
| `gitleaks` / `.xila-gitleaks` | `zricethezav/gitleaks:v8.21.2` (`detect`) | JSON | `gitleaks` |
| `checkov` / `.xila-checkov` | `bridgecrew/checkov:3.2.334` | JSON | `checkov` |
| `opengrep` / `.xila-opengrep` | release binary v1.33.1 (checksum-pinned) | JSON (semgrep format) | `opengrep --format semgrep` |
| `kics` / `.xila-kics` | `checkmarx/kics:v2.2.1` (digest-pinned) | JSON | `kics` |

Findings are tracked **per branch**: uploads and the gate use the PR / MR source
branch (GitHub `github.head_ref || github.ref_name`, GitLab
`CI_MERGE_REQUEST_SOURCE_BRANCH_NAME` else `CI_COMMIT_REF_NAME`) plus the commit
SHA, so a pull request never closes or changes the default branch's findings.

## Secrets

The recommended setup stores **no Xila secret at all**: see
[Keyless: workload identity federation](#keyless-workload-identity-federation).
If you use an API token instead, never put it in YAML. Create a
**project-scoped Xila API token** (or a service-account key) and store it as:

- GitHub: a repository (or organization) **secret** `XILA_TOKEN`; the URL and
  project id can be secrets or **variables** (`vars.XILA_URL`, `vars.XILA_PROJECT`).
- GitLab: **Settings › CI/CD › Variables** — `XILA_TOKEN` *masked* (and
  *protected* if only protected branches should upload), `XILA_URL`, `XILA_PROJECT`.

## Keyless: workload identity federation

With no `token` input / `XILA_TOKEN`, the CLI exchanges the job's own OIDC
identity token for a short-lived Xila session (OAuth 2.0 token exchange,
RFC 8693, at `POST /api/v1/auth/token`). Nothing long-lived is stored in the CI
system, and nothing leaks if a log does.

A Xila admin sets it up once, under **Admin › Service accounts**:

1. **Service account** — e.g. `ci-web`. Grant it a role like anyone else, by its
   email `ci-web@service-accounts.invalid`, on the project's (or team's) members
   page: `editor` is enough to upload and gate.
2. **Trusted issuer** — the platform's OIDC issuer and the audience your jobs
   request:
   - GitHub Actions: `https://token.actions.githubusercontent.com`
   - GitLab.com: `https://gitlab.com` (self-managed: your GitLab URL)
   - Audience: by convention the Xila URL — the templates request it by default.
3. **Binding** — claim conditions → the service account, optionally confined to
   one project. Every condition must hold; values are exact or globs (`*` within
   one `/` segment, `**` across). At least one condition must pin *which*
   workload (`repository`, `repository_owner`, `project_path`, `sub`, …): GitHub
   and GitLab.com sign tokens for every repository on the platform, so a
   binding on `ref` alone would admit anyone's pipeline. Examples:

   | Platform | Conditions |
   |---|---|
   | GitHub, main branch only | `repository=acme/web`, `ref=refs/heads/main` |
   | GitHub, any branch, protected environment | `repository=acme/web`, `environment=production` |
   | GitLab, protected refs | `project_path=acme/web`, `ref_protected=true` |
   | Kubernetes | `sub=system:serviceaccount:ci:scanner` |

GitHub Actions — the job needs `id-token: write`:

```yaml
permissions:
  contents: read
  id-token: write       # lets the job request its OIDC token
  pull-requests: write

    steps:
      - uses: xilasec/xila-api/ci/github/scan@main
        with:
          url: ${{ vars.XILA_URL }}
          project: ${{ vars.XILA_PROJECT }}
          # no token: the job's OIDC token (audience = url) is exchanged
```

GitLab CI — leave `XILA_TOKEN` unset. `.xila-upload` and `.xila-gate` already
declare `id_tokens: XILA_ID_TOKEN` with `aud: $XILA_OIDC_AUDIENCE` (default
`$XILA_URL`).

Anywhere else, pass the identity token explicitly: `xila upload --oidc-token
"$TOKEN" …` (or `XILA_OIDC_TOKEN`). A refused exchange exits `2` with the
server's reason (`no binding matches the token's claims`, `the token's issuer is
not trusted`, …). The session lasts `FEDERATION_TOKEN_TTL` (15 minutes by
default, at most 1 hour); suspending the service account ends it at once.

## GitHub Actions

```yaml
name: Xila scan
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read        # checkout
  pull-requests: write  # the PR comment (drop it with comment: false)

jobs:
  xila:
    runs-on: ubuntu-latest   # needs Docker: Linux runners only
    steps:
      - uses: actions/checkout@v5
        with:
          fetch-depth: 0     # gitleaks scans the git history
      - uses: xilasec/xila-api/ci/github/scan@main   # pin a tag or commit SHA
        with:
          url: ${{ vars.XILA_URL }}
          token: ${{ secrets.XILA_TOKEN }}
          project: ${{ vars.XILA_PROJECT }}
          scanners: trivy-fs,gitleaks,semgrep,grype,osv-scanner,checkov
          new-only: ${{ github.event_name == 'pull_request' }}
```

Scanning a built image: add `trivy-image` to `scanners` and set `image:` (the
Docker socket is mounted, so a locally built tag works).

| Input | Default | Meaning |
|---|---|---|
| `url`, `project` | — (required) | Xila instance, project id |
| `token` | `""` | API token; empty = keyless federation (needs `id-token: write`) |
| `oidc-audience` | the `url` input | audience requested for the GitHub OIDC token |
| `scanners` | `trivy-fs,gitleaks,semgrep` | comma list of the scanners above |
| `image` | `""` | image reference for `trivy-image` |
| `path` | `.` | directory to scan, relative to the workspace |
| `gate` | `true` | wait for processing, then run `xila gate` once |
| `new-only` | `false` | gate only on findings this change introduces |
| `comment` | `true` | PR comment (edited in place; needs `pull-requests: write`) |
| `check` | `false` | GitHub check run with inline annotations (edited in place; needs `checks: write`) |
| `github-token` | `${{ github.token }}` | token that writes the comment / check run |
| `version` | `latest` | xila CLI ref for `go install` |

The PR comment is posted by the last upload, so it lists the new findings of the
last scanner in the list and no gate verdict; the gate's verdict is the job's
status. The check run (if enabled) is posted by the `Xila security gate` step
instead, so its conclusion always matches the gate verdict — it just has no
scan to pin annotations to in this multi-scanner flow (the single-scanner
repo-root `action.yml` posts a check run per upload, with annotations). A
complete worked file is `ci/github/example-workflow.yml`.

## GitLab CI

```yaml
include:
  - remote: https://raw.githubusercontent.com/xilasec/xila-api/main/ci/gitlab/xila-scan.gitlab-ci.yml

trivy:
  extends: .xila-trivy
gitleaks:
  extends: .xila-gitleaks
semgrep:
  extends: .xila-semgrep
grype:
  extends: .xila-grype
checkov:
  extends: .xila-checkov

xila-upload:
  extends: .xila-upload
  needs: [trivy, gitleaks, semgrep, grype, checkov]   # pulls their reports

xila-gate:
  extends: .xila-gate
  needs: [xila-upload]
  variables:
    XILA_NEW_ONLY: "true"   # e.g. on merge requests
```

Pin the include to a tag or commit instead of `main` for reproducible pipelines.
All jobs default to `stage: test`; ordering comes from `needs:`, so override
`stage:` freely. `.xila-upload` uploads every report found in `xila-reports/`
and keeps the built CLI as an artifact that `.xila-gate` reuses.

| Variable | Default | Meaning |
|---|---|---|
| `XILA_URL`, `XILA_PROJECT` | — (CI/CD variables) | Xila instance, project id |
| `XILA_TOKEN` | unset | API token; unset = keyless federation with the job's `XILA_ID_TOKEN` |
| `XILA_OIDC_AUDIENCE` | `$XILA_URL` | audience of the `XILA_ID_TOKEN` the upload and gate jobs request |
| `XILA_GATE` | `true` | wait for processing; `.xila-gate` is a no-op when not `true` |
| `XILA_NEW_ONLY` | `false` | gate only on findings this change introduces |
| `XILA_VERSION` | `latest` | xila CLI ref for `go install` |
| `XILA_SCAN_PATH` | `.` | directory to scan |
| `XILA_TRIVY_IMAGE` | unset | makes `.xila-trivy` run `trivy image` on this reference |

## Required permissions

- **Xila**: a service account bound to the job (keyless), or an API token,
  with `editor` on the project (a project-scoped token or binding is enough).
- **GitHub**: `contents: read`; `id-token: write` for keyless federation;
  `pull-requests: write` only for the comment; `checks: write` only for the
  check run.
- **Runner**: Docker (GitHub: the action runs `docker run`, so Linux runners);
  GitLab: any Docker executor.
