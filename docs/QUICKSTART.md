# Quickstart: your first finding in 5 minutes

Two ways to see Xila work: seed a demo project instantly, or upload a real scan
of your own project. Both start the same way.

## 1. Start the stack

```bash
make up          # docker compose up --build -d: API + Postgres + OTel collector + Jaeger
```

The app (UI + API) is at <http://localhost:8080>. The first account you
register becomes the instance **owner** (admin, and the only account that can
transfer ownership).

## 2a. The fast way: seed a demo project

Populate a demo org/team/project with real sample scanner reports and an SBOM
— through the exact same ingestion pipeline a real upload goes through, so
dedup, priority and compliance posture are all real — in one command:

```bash
docker compose exec api xila-api demo-seed
```

```
Demo project ready.
URL:      http://localhost:8080
Login:    admin@demo.local
Password: <printed once — change it after signing in>
```

Sign in and open the **Demo App** project: it already has findings from a
Trivy container-image scan (on `main`), a Semgrep SAST scan (on
`feature/login-fix`), and an SBOM with license data. Running `demo-seed` again
is a no-op — it only creates what's missing.

`demo-seed` refuses to run against `APP_ENV=production` (the seeded org/team/
project/findings are realistic enough to be mistaken for a real tenant's
data); pass `--force` if you really want it there.

## 2b. The real way: upload your own scan

1. **Register**, then create a team and a project (home page, or `POST
   /api/v1/teams` / `POST /api/v1/projects`).
2. **Create an API token** — go to **API keys** (`/tokens`) in the UI, scope it
   to your project.
3. **Run a scanner and upload its report.** Any of the 60+ supported scanners
   works the same way; here's Trivy:

   ```bash
   trivy fs --format json . > trivy.json
   curl -X POST "http://localhost:8080/api/v1/projects/<project-id>/scans?scanner=trivy" \
     -H "Authorization: Bearer <api-token>" \
     -H "Content-Type: application/json" \
     --data-binary @trivy.json
   ```

   Or with the bundled CLI (handles the upload, and can gate your CI on the
   result in the same step):

   ```bash
   xila upload --project <project-id> --scanner trivy trivy.json
   ```

4. **Open the project.** Findings are deduplicated, priority-ranked (exploit
   maturity, KEV, reachability) and ready to triage immediately — no delay,
   no background job to wait for.

See the README's ["Break the build in CI"](../README.md#break-the-build-in-ci)
section for wiring this into a pull request gate, and
[`docs/PARSERS.md`](PARSERS.md) for the full list of supported scanners.
