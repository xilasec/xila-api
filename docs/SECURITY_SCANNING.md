# Security scanning of this repository

Four scanners gate every change. One script, `scripts/security-scan.sh`,
defines them, so a local pass means a CI pass.

| Scanner | Looks at | Fails on | Config |
|---|---|---|---|
| grype | `go.mod`/`go.sum`, `web/pnpm-lock.yaml`, and (in CI) the built image: Go stdlib + distroless base | High or Critical with a fix available | `.grype.yaml` |
| opengrep | Go, JS/Svelte, YAML (workflows), shell, Dockerfile (`--config auto`) | any finding | `.semgrepignore` |
| KICS | Dockerfile, docker-compose, Helm chart, GitHub workflows, CI templates | Low and above | flags in the script |
| gitleaks | secrets: staged changes (pre-commit), the working tree (`make security`), every commit (CI) | any finding | `.gitleaks.toml` |

## Where they run

- **Before each commit:** `make hooks` installs the pre-commit hooks
  (`.pre-commit-config.yaml`). Each hook runs only when relevant files
  are staged: grype for lockfiles, opengrep for staged sources, KICS for IaC.
  gitleaks checks the staged changes of every commit.
  Run every hook by hand with `pre-commit run --all-files`.
- **On demand:** `make security` runs all four over the whole repo.
- **In CI:** `.github/workflows/security.yml` runs on every push to `main`,
  every pull request, every release (the release workflow requires it), and
  nightly. There, gitleaks scans the full history, so a secret that was committed and
  later deleted is still caught. The nightly run means a CVE published today fails the next run
  even if the code has not changed.

Hooks can be skipped (`git commit --no-verify`); CI can't. Treat the hooks as
fast feedback and CI as the enforcement point.

## The Security tab

In CI each scanner also writes a SARIF report (`SARIF_DIR`), and the workflow
uploads it to GitHub code scanning under its own category (`grype-dependencies`,
`grype-image`, `opengrep`, `gitleaks`, `kics`), next to CodeQL. Before upload,
`scripts/security-scan.sh` drops what the gate already accepts, so the tab
shows the same verdict as the build:

- Results suppressed in source (`nosemgrep: <rule> -- why`). GitHub ignores
  SARIF's `suppressions` field and would otherwise list them as open alerts.
- KICS informational results, which sit below the Low gate.

grype keeps its non-blocking results (unfixed or below High): they are real
exposure, just not a reason to fail the build. A `.grype.yaml` ignore never
reaches the report. Fork pull requests can't write security events, so they
skip the upload.

## Installing the tools

- **grype:** <https://github.com/anchore/grype#installation>. If it is not installed, the
  script runs the pinned `anchore/grype` image through docker or podman.
- **opengrep:** `curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash`
  (CI pins v1.33.1 by checksum). There is no official image, so it must be
  installed.
- **gitleaks:** <https://github.com/gitleaks/gitleaks#installing>. If it is not installed,
  the script runs the pinned `zricethezav/gitleaks` image (by digest).
- **KICS:** nothing to install. The script runs the pinned `checkmarx/kics`
  image (by digest), or a local `kics` binary if present.
- **pre-commit:** `pipx install pre-commit` (or `pip install pre-commit`).

## When a scan fails

1. Fix it. Upgrade the dependency (grype prints the fixed version), change
   the code, or harden the config. This is the default.
2. A false positive or an accepted risk needs a written reason in the
   repository, not a weaker gate:
   - opengrep: `// nosemgrep: <rule-id> -- why`, on the line the finding
     points at.
   - KICS: `# kics-scan ignore-line` above the flagged line, with a comment
     saying why.
   - gitleaks: `gitleaks:allow` in a comment on the line, with the reason (e.g. a
     fake test key). **Never allowlist a real secret: rotate it, then
     remove it (also from history if it was pushed).**
   - grype: an `ignore:` entry in `.grype.yaml` with the vulnerability id, a
     reason, and when to revisit.

   Every existing suppression includes its reason. `grep -rn "nosemgrep\|kics-scan\|gitleaks:allow"`
   lists them.
3. No fix exists yet (grype only): the gate doesn't fail (`only-fixed`).
   The finding stays visible in the output and fails the first nightly run
   after a fix ships.

