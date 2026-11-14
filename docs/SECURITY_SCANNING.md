# Security scanning of this repository

Four scanners gate every change. One script, `scripts/security-scan.sh`,
defines them, so a local pass means a CI pass.

| Scanner | Looks at | Fails on | Config |
|---|---|---|---|
| **grype** | `go.mod`/`go.sum`, `web/pnpm-lock.yaml`, and (in CI) the built image: Go stdlib + distroless base | High or Critical **with a fix available** | `.grype.yaml` |
| **opengrep** | Go, JS/Svelte, YAML (workflows), shell, Dockerfile (`--config auto`) | any finding | `.semgrepignore` |
| **KICS** | Dockerfile, docker-compose, Helm chart, GitHub workflows, CI templates | Low and above | flags in the script |
| **gitleaks** | secrets: staged changes (pre-commit), the working tree (`make security`), every commit (CI) | any finding | `.gitleaks.toml` |

## Where they run

- **Before each commit:** `make hooks` installs the pre-commit hooks
  (`.pre-commit-config.yaml`). Each hook runs only when files it cares about
  are staged: grype for lockfiles, opengrep for staged sources, KICS for IaC;
  gitleaks checks every commit's staged changes.
  Run every hook by hand with `pre-commit run --all-files`.
- **On demand:** `make security` runs all four over the whole repo.
- **In CI:** `.github/workflows/security.yml` runs on every push to `main`,
  every pull request, every release (the release workflow needs it), and
  nightly. gitleaks scans the full history there, so a secret committed and
  later deleted is still caught. The nightly run matters: a CVE published today fails tomorrow's run
  even if nobody touched the code.

Hooks can be skipped (`git commit --no-verify`); CI can't. Treat the hooks as
fast feedback and CI as the enforcement point.

## Installing the tools

- **grype:** <https://github.com/anchore/grype#installation>. Without it, the
  script runs the pinned `anchore/grype` image through docker or podman.
- **opengrep:** `curl -fsSL https://raw.githubusercontent.com/opengrep/opengrep/main/install.sh | bash`
  (CI pins v1.33.1 by checksum). It has no official image, so it must be
  installed.
- **gitleaks:** <https://github.com/gitleaks/gitleaks#installing>. Without it,
  the script runs the pinned `zricethezav/gitleaks` image (by digest).
- **KICS:** nothing to install. The script runs the pinned `checkmarx/kics`
  image (by digest), or a local `kics` binary if present.
- **pre-commit:** `pipx install pre-commit` (or `pip install pre-commit`).

## When a scan fails

1. **Fix it.** Upgrade the dependency (grype prints the fixed version), change
   the code, or harden the config. That is the default.
2. **A false positive or an accepted risk** needs a written reason in the
   repository, never a weaker gate:
   - opengrep: `// nosemgrep: <rule-id> -- why`, on the line the finding
     points at.
   - KICS: `# kics-scan ignore-line` above the flagged line, with a comment
     saying why.
   - gitleaks: `gitleaks:allow` in a comment on the line, with why (e.g. a
     fake test key). A **real** secret is never allowlisted: rotate it, then
     remove it (and from history if it was pushed).
   - grype: an `ignore:` entry in `.grype.yaml` with the vulnerability id, a
     reason, and when to revisit.

   Every existing suppression carries its reason; `grep -rn "nosemgrep\|kics-scan\|gitleaks:allow"`
   lists them.
3. **No fix exists yet** (grype only): the gate doesn't fail (`only-fixed`).
   The finding stays visible in the output and fails the first nightly run
   after a fix ships.
