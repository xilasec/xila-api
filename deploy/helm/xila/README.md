# Xila Helm chart

Deploys Xila (UI + API in one image) on Kubernetes ≥ 1.25, with either a bundled
single-instance PostgreSQL (evaluation) or your own PostgreSQL 15+ (production).

## Image

The chart pulls `ghcr.io/xilasec/xila-api:<appVersion>`. Build and push it from
the repository root (the Dockerfile builds the UI and embeds it):

```bash
docker build -t ghcr.io/<you>/xila-api:0.1.0 .
docker push ghcr.io/<you>/xila-api:0.1.0
# then: --set image.repository=ghcr.io/<you>/xila-api
```

## Quick start (bundled PostgreSQL)

```bash
helm install xila deploy/helm/xila -n xila --create-namespace
kubectl -n xila port-forward svc/xila 8080:80      # http://localhost:8080
helm test xila -n xila
```

**The first account registered becomes the instance owner.** Register yours
before exposing the service.

`JWT_SECRET`, `INTEGRATION_SECRET_KEY` and the database password are generated on
install, kept across upgrades, and **kept on uninstall** (`helm.sh/resource-policy:
keep`) so a reinstall against the same data still works. Back up
`INTEGRATION_SECRET_KEY`: without it, stored issue-tracker and connector tokens,
and the secrets of SSO providers added on the SSO page, can't be decrypted.

## Production

```yaml
# values-prod.yaml
publicUrl: https://xila.example.com
trustedProxies: ["10.0.0.0/8"]          # your ingress controller / LB
postgresql:
  enabled: false
database:
  host: xila.abcd.eu-west-1.rds.amazonaws.com
  name: xila
  user: xila
  passwordSecret: { name: xila-db, key: password }
  sslmode: require                      # or verify-full
ingress:
  enabled: true
  className: nginx
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: 32m   # scan/SBOM uploads
  hosts:
    - host: xila.example.com
      paths: [{ path: /, pathType: Prefix }]
  tls:
    - secretName: xila-tls
      hosts: [xila.example.com]
existingSecret: xila-app               # JWT_SECRET, INTEGRATION_SECRET_KEY, SMTP_PASSWORD…
config:
  OIDC_ENABLED: "true"
  OIDC_ISSUER: https://login.example.com
  OIDC_CLIENT_ID: xila
  OIDC_REDIRECT_URL: https://xila.example.com/api/v1/auth/oidc/callback
  SMTP_HOST: smtp.example.com
  SMTP_FROM: Xila <xila@example.com>
networkPolicy:
  enabled: true
```

```bash
helm upgrade --install xila deploy/helm/xila -n xila -f values-prod.yaml
```

SSO providers can be added, tested and switched off at runtime on the **SSO**
page (needs `publicUrl` and `INTEGRATION_SECRET_KEY`); changes reach every
replica at its next login request, no rollout. The `OIDC_*` / `SAML_*` config
above is optional and defines one more provider of each kind, read-only in the UI.

The database user needs to create tables (migrations run at startup). Connect
directly or through a **session-mode** pooler: Xila uses session-level advisory
locks, which transaction-mode PgBouncer breaks.

## How it runs

- **Scaling.** Replicas (`replicaCount`, or `autoscaling`) are safe: the scheduled
  jobs — digest, exception and SLA sweeps, enrichment, OSV matching, issue sync,
  connector pulls, metric snapshots, branch pruning — run on exactly **one** pod,
  elected with a PostgreSQL advisory lock. If that pod dies another takes over
  (≈20 s after a clean shutdown; within about a minute if a node is lost). Async
  ingest workers (`config.INGEST_ASYNC: "true"`) run on every pod.
- **Migrations** run when a pod starts, serialized by golang-migrate's own lock.
  Rolling updates keep `maxUnavailable: 0`: the new pod migrates and becomes ready
  before an old one stops, so old pods briefly run against the new schema —
  Xila's migrations are written to be additive for that reason.
- **Startup.** A pod waits up to a minute for the database instead of crash-looping
  (a fresh install starts both at once). The startup probe allows 5 minutes for
  large migrations.
- **Probes.** `/health` (liveness: the process), `/ready` (readiness: pings the
  database).
- **Security.** Non-root (65532), read-only root filesystem (`/tmp` is an
  emptyDir), all capabilities dropped, `RuntimeDefault` seccomp, no service-account
  token. `networkPolicy.enabled` admits traffic to the app port (from
  `networkPolicy.ingressFrom`, or anywhere) and to the bundled PostgreSQL only from
  this release's app pods.
- **Config changes** (`config`, `secrets`) roll the pods (checksum annotations).

## Values

| Key | Default | |
| --- | --- | --- |
| `image.repository` / `image.tag` | `ghcr.io/xilasec/xila-api` / appVersion | |
| `replicaCount` | `2` | ignored when `autoscaling.enabled` |
| `appEnv` | `production` | `development` relaxes hardening |
| `publicUrl` | first ingress host | links back to Xila (issues, VEX ids) |
| `corsAllowedOrigins` / `trustedProxies` | `[]` | |
| `config` | `{}` | **any** env setting from the main README's configuration table; wins over the chart's own keys |
| `secrets.jwtSecret` / `secrets.integrationSecretKey` | generated | |
| `secrets.extra` | `{}` | other secret env (`SMTP_PASSWORD`, `OIDC_CLIENT_SECRET`, `SAML_SP_CERT` / `SAML_SP_KEY`) |
| `existingSecret` | `""` | your own Secret instead of `secrets` |
| `database.*` | | external PostgreSQL (`host`, `port`, `name`, `user`, `password` or `passwordSecret`, `sslmode`, `maxConns`, `minConns`) |
| `postgresql.enabled` | `true` | bundled `postgres:18-alpine` StatefulSet, `persistence.size` 8Gi |
| `otel.enabled` / `otel.endpoint` | `false` | OTLP/gRPC collector `host:port` |
| `metrics.enabled` / `metrics.port` | `false` / `9090` | Prometheus `/metrics` on its own port (Service port `metrics`, never routed by the Ingress) |
| `metrics.serviceMonitor.*` | disabled | Prometheus Operator `ServiceMonitor` (`interval`, `scrapeTimeout`, `labels`, `bearerTokenSecret` for `METRICS_TOKEN`) |
| `ingress.*` | disabled | standard `networking.k8s.io/v1` Ingress |
| `autoscaling.*` | disabled | CPU-based HPA |
| `podDisruptionBudget.*` | `maxUnavailable: 1` | when more than one replica can run |
| `networkPolicy.*` | disabled | |
| `resources` | 100m / 128Mi, limit 512Mi | |
| `podSecurityContext` / `securityContext` | hardened | |
| `extraEnv` / `extraEnvFrom` / `extraVolumes` / `extraVolumeMounts` | | |

See [`values.yaml`](values.yaml) for every key.
