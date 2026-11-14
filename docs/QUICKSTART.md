# Quickstart: your first finding in 5 minutes

There are two ways to see Xila work: seed a demo project, or upload a real scan
of your own project. Both start the same way.

## 1. Start the stack

```bash
make up          # docker compose up --build -d: API (all features on) + Postgres + OTel collector + Jaeger + Mailpit
```

The app (UI + API) is at <http://localhost:8080>. The first account you
register becomes the instance owner (admin, and the only account that can
transfer ownership).

## 2a. The fast way: seed a demo project

This command populates a demo org/team/project with real sample scanner reports
and an SBOM. It uses the same ingestion pipeline as a real upload, so dedup,
priority and compliance posture are all real:

```bash
docker compose exec api xila-api demo-seed
```

```
Demo project ready.
URL:      http://localhost:8080
Login:    admin@demo.local
Password: <printed once; change it after signing in>
```

Sign in and open the Demo App project. It has findings from a Trivy
container-image scan (on `main`), a Semgrep SAST scan (on
`feature/login-fix`), and an SBOM with license data. Running `demo-seed` again
is a no-op. It only creates what's missing.

`demo-seed` refuses to run against `APP_ENV=production`, because the seeded
org/team/project/findings could be mistaken for a real tenant's data. Pass
`--force` to run it there anyway.

## 2b. The real way: upload your own scan

1. Register, then create a team and a project (home page, or `POST
   /api/v1/teams` / `POST /api/v1/projects`).
2. Create an API token: go to API keys (`/tokens`) in the UI and scope it
   to your project.
3. Run a scanner and upload its report. All 60+ supported scanners work the
   same way. Here is Trivy:

   ```bash
   trivy fs --format json . > trivy.json
   curl -X POST "http://localhost:8080/api/v1/projects/<project-id>/scans?scanner=trivy" \
     -H "Authorization: Bearer <api-token>" \
     -H "Content-Type: application/json" \
     --data-binary @trivy.json
   ```

   Or use the bundled CLI, which handles the upload and can gate your CI on the
   result in the same step:

   ```bash
   xila upload --project <project-id> --scanner trivy trivy.json
   ```

4. Open the project. Findings are deduplicated, priority-ranked (exploit
   maturity, KEV, reachability) and ready to triage right away. There is no
   background job to wait for.

See the README's ["Break the build in CI"](../README.md#break-the-build-in-ci)
section for wiring this into a pull request gate, and
[`docs/PARSERS.md`](PARSERS.md) for the full list of supported scanners.

