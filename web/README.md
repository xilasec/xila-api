# Xila Web

A small, single-page frontend for the Xila API — **SvelteKit + Tailwind v4 +
daisyUI**, served as static files (SPA) that talk to the Go API.

## Run

```bash
cd web
pnpm install
pnpm dev                  # http://localhost:5173
```

No `.env` needed: the dev server proxies `/api` to the Go server on `:8080`
(override the target with `VITE_API_PROXY`). Just have the API running —
`make up` at the repo root brings up the API + Postgres.

## Build

```bash
pnpm build                # static site in ./build (any static host / nginx)
pnpm preview              # preview the production build
```

### One bundle (UI embedded in the API binary)

From the repo root, `make bundle` builds this SPA and compiles a single Go binary
(`-tags embedfrontend`) that serves the UI and the API on one port. The Docker
image does the same, so `make up` needs no separate web container. In the bundle
the UI calls the API same-origin (`/api/v1`); `VITE_API_URL` is only needed for
the standalone dev server.

## What's here

| Route | Purpose |
| ----- | ------- |
| `/login` | Sign in / register (JWT stored in `localStorage`) |
| `/` | Project portfolio — risk score per project, create teams/projects |
| `/projects/[id]` | Risk summary + tabs: **Findings** (filterable), **Scans**, **SBOMs**, **Components**; upload scans & SBOMs inline |
| `/findings/[id]` | Finding detail, status triage, and the **SBOM component(s) that introduced it** |
| `/components` | Global "which projects ship this package?" search |

## Layout

```
src/lib/api.js          fetch client (JWT, pagination envelope, raw uploads)
src/lib/stores.js       token + toast stores
src/lib/format.js       badge colors, date/severity helpers
src/lib/components/     Badge, State (loading/error/empty)
src/routes/             pages (SPA, ssr disabled)
```

Configure the backend URL with `VITE_API_URL` (see `.env.example`). Themes are
daisyUI `winter` (light) / `night` (dark), toggled from the navbar.
