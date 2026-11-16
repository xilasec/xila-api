# Scaling proof

M9 item 4: before this, nothing measured ingest throughput or list/portfolio latency.
This document covers the load-test harness, the Go benchmarks for the hot
write paths, the dataset and hardware used, and the before/after numbers that
justified (or ruled out) new indexes.

## Hardware & dataset

- Measured on: 12th Gen Intel Core i5-12600K (16 threads), 16 GiB RAM,
  PostgreSQL 16.15, local SSD-backed storage. This is a single developer machine, not
  a production-sized server, so the numbers below describe *relative*
  cost (sequential scan vs. index, before vs. after) more than absolute
  production latency.
- Postgres runs on stock settings (`shared_buffers` 128 MB, `work_mem` 4 MB,
  `random_page_cost` 4) unless a column says otherwise. The 1.3 GB
  database exceeds `shared_buffers`, so reads come through the OS page cache.
- Dataset: 1,010,000 findings across 605 projects (5 "monorepo" projects at
  100,000 findings each and 600 smaller projects at 850 each, to match a real portfolio's
  shape rather than one flat table), 150 teams, 30 orgs, 120,000 SBOM components.
  Findings are assigned round-robin across 3 scanners (trivy/grype/osv) over a shared
  CVE+package pool sized to each project, so about 1/3 of each project's findings
  collide across tools. These collisions are what `Deduplicate` groups.
- Built with `internal/loadtest` + `cmd/xila-loadtest`. Data is seeded directly
  through the product's own repositories (so `project_version`, the SLA/dedup
  triggers, etc. run the same way they do for a real upload), and the findings themselves are bulk-loaded
  with `COPY`.

## Running it yourself

```bash
export GOTOOLCHAIN=go1.27.4
go build -o /tmp/xila-loadtest ./cmd/xila-loadtest/
go build -o /tmp/xila-api ./cmd/api/

# A disposable database: this seeds ~1M rows, so never point it at real data.
psql -h 127.0.0.1 -p 5432 -U xila -d postgres \
  -c "DROP DATABASE IF EXISTS xila_scale" -c "CREATE DATABASE xila_scale"

# Seed (~1,010,000 findings; takes several minutes). Smaller runs:
# add --big-projects/--big-findings/--small-projects/--small-findings/etc.
/tmp/xila-loadtest seed --dsn "postgres://xila:xila@127.0.0.1:5432/xila_scale?sslmode=disable"
#   admin login + the id of each big ("monorepo") project are printed at the end.

# Run the server against that database (pick a free port, never 8080/8088).
APP_ENV=development HTTP_HOST=127.0.0.1 HTTP_PORT=18099 \
DB_HOST=127.0.0.1 DB_PORT=5432 DB_USER=xila DB_PASSWORD=xila DB_NAME=xila_scale DB_SSLMODE=disable \
JWT_SECRET=scale-test-secret INGEST_ASYNC=false \
/tmp/xila-api &

# List/portfolio/component latency (p50/p95/p99), using one of the big project ids:
/tmp/xila-loadtest http-bench --base-url http://127.0.0.1:18099 --project <big-project-id>

# Ingest throughput through the real scan service (HTTP upload, same path CI uses):
/tmp/xila-loadtest ingest-bench --base-url http://127.0.0.1:18099 --project <big-project-id> \
  --scans 20 --findings-per-scan 1000

# EXPLAIN (ANALYZE, BUFFERS) one of the query shapes below:
/tmp/xila-loadtest explain --dsn "postgres://xila:xila@127.0.0.1:5432/xila_scale?sslmode=disable" \
  --query list-priority-active --project <big-project-id>
```

Go benchmarks are gated on `TEST_DATABASE_URL`, like every other DB test in the
repo. They use small, synthetic datasets, not the 1M-row harness above:

```bash
export TEST_DATABASE_URL="postgres://xila:xila@127.0.0.1:5432/xila?sslmode=disable"
go test ./internal/finding/ -run '^$' -bench . -benchtime=3x
go test ./internal/domain/  -run '^$' -bench .
```

## Latency at 1M findings

Median (p50) of 9 requests after one warm-up, through the HTTP API, on a quiet
database. No background job was running: the leader's start-up jobs (policy
evaluation and the 90-day metric backfill) are heavy at this size, so we waited
for them to finish. Big project = 100,000 findings. Postgres on stock settings unless noted.

| Endpoint | Before M9 | After M9 | After, `random_page_cost = 1.1` |
|---|---|---|---|
| `GET /portfolio` | 31,037 ms | 3,377 ms | 2,788 ms |
| `GET /projects/{big}/compliance` (8 frameworks) | 28,709 ms | 428 ms | 348 ms |
| `GET /findings?limit=100` (portfolio-wide) | 1,681 ms | 8.7 ms | 6.1 ms |
| `GET /projects/{big}/findings` (default order) | 143 ms | 8.5 ms | 6.3 ms |
| `GET /projects/{big}/summary` | 117–337 ms¹ | 374 ms | 121 ms |
| `GET /projects/{big}/findings?status=open&sort=priority` | 3.2 ms | 5.8 ms | - |
| `GET /projects/{big}/findings?q=…` (full-text) | 3.9 ms | 7.8 ms | - |
| `GET /components?q=…` | 18.6 ms | 24.4 ms | 22.2 ms |

¹ The summary's plan flips between an index scan (~110 ms) and a whole-table scan
(~300 ms) depending on statistics. See the last row of the next table.

(Differences of a few milliseconds at the single-digit scale are run-to-run noise.)

## What the measurements found, and what changed

| Finding | Cause (`EXPLAIN ANALYZE`) | Change |
|---|---|---|
| Compliance took ~3.6 s per framework per 100k-finding project | `FindingMatchSQL` was one OR-ed join condition (cwe / rule / category / severity / kev / sla), so Postgres tested every mapping × every open finding | The rule is now `compliance.FindingMatchesSQL`: one equi-join per match type over the open findings, read once. The rule itself is unchanged; `TestFindingMatchesIsTheRule` compares it pair-for-pair with the original formulation. |
| The project page evaluated 8 frameworks separately | 8 × (scan + match) of the same findings | `EvaluateAll` scores every framework in one query, matching only their mappings |
| Portfolio compliance still took 3.5 s | KEV/SLA branches produced 3.3M (finding, control) pairs that were reduced to 6k (project, control) pairs. The outer query joined every (project, control) with all its mappings (2.4M rows) to check the few `sbom`/`vex` ones | `ProjectFailingControlsSQL` (same branch table, per-project projection); join only `FactMappingsSQL`. `TestPortfolioComplianceMatchesEvaluate` checks that portfolio = mean of `Evaluate` |
| `/portfolio` ran 7 aggregates sequentially, each scanning the findings | - | They run concurrently (disjoint fields of the result); one request holds up to 7 pool connections |
| Default findings lists sorted every finding to return a page | `ORDER BY last_seen_at DESC` had no index: parallel seq scan + top-N sort (217 ms project, 292 ms portfolio) | Migration 087: `(project_id, last_seen_at DESC)` and `(last_seen_at DESC)` → 0.8 ms / 0.4 ms. 29 MB + 18 MB at 1M rows, < 1 s each to build |
| The summary sometimes scanned the whole table | Stock `random_page_cost = 4` (tuned for spinning disks) makes a 10%-selective bitmap scan look more expensive than a seq scan; measured 300 ms vs 110 ms (47 ms with 1.1) | The bundled Postgres (compose, Helm `postgresql.extraArgs`) runs with `random_page_cost=1.1`. **If you run your own Postgres on SSDs, set it there too.** |

Not changed: partitioning. Every hot query is per project or per version and is
now indexed. The remaining cost is the portfolio's full scans of the open
findings (≈570 ms each at 586k open findings), which partitioning would not
avoid. If `/portfolio` performance matters at this size, the next step is to serve
it from the daily metric snapshots instead of live aggregates.

## Go benchmark results

Synthetic fixtures (`internal/finding/bench_db_test.go`, `-benchtime=3x`), same
machine, after migration 087. They guard the per-scan cost of the write path,
which every upload pays, rather than the 1M-row dataset.

| Benchmark | Fixture | Time per op |
|---|---|---|
| `UpsertBatch` | 1,000 findings per scan | 482 ms (2,073 findings/s) |
| `CloseMissing` | 500 findings, half gone in the next scan | 17.9 ms |
| `DeduplicateScan` (every ingest) | 200 findings into a 20,000 backlog | 80 ms |
| `Deduplicate` (full backfill) | 20,000 findings | 213 ms |
| `List` default order | 20,000 findings | 1.7 ms |
| `List` priority, open | 20,000 findings | 7.5 ms |
| `List` severity + scanner | 20,000 findings | 3.3 ms |
| `List` full-text search | 20,000 findings | 4.6 ms |
| `domain.Priority` | pure | 2.9–3.5 ns |

## Ingest throughput (1M-row dataset)

20 scans × 1,000 findings uploaded over HTTP to the 100k-finding project (sync
ingest: parse → upsert → auto-close → triage → dedup → priority → gates). Each run
used its own branch:

| | Findings/s | Per-scan p50 | p95 |
|---|---|---|---|
| With migration 087's indexes | 806 | 1,226 ms | 1,356 ms |
| Without them | 811 | 1,235 ms | 1,285 ms |

The two list indexes add no measurable write cost. `findings` updates were
already mostly non-HOT (88% at seed time) because upserts change other indexed
columns.

## Parallel ingest (November 2026)

One API process, synchronous ingest, `DB_MAX_CONNS=60`, Postgres 16 with default
settings (`shared_buffers` 128 MB) on the same 16-core machine. Each uploader
sends 5 scans of 1,000 findings to its own project (16 projects of 5,000
findings), the shape of many repositories uploading at once:

| Parallel uploaders | Findings/s (all uploaders) | Per-scan p50 | p95 (worst uploader) |
|---|---|---|---|
| 1 | 1,531 | 655 ms | 682 ms |
| 2 | 2,896 | 685 ms | 710 ms |
| 4 | 5,605 | 701 ms | 722 ms |
| 8 | 7,786 | 993 ms | 1,062 ms |
| 16 | 9,414 | 1,659 ms | 1,772 ms |

Throughput scales almost linearly to 4 uploaders and flattens past 8: the
machine (API, Postgres and the load generator share 16 cores) saturates, not a
lock. Uploads to different projects don't contend; uploads to one project
serialize on its dedup lock by design. Reproduce with one command:

```bash
/tmp/xila-loadtest ingest-bench --base-url http://127.0.0.1:18099 \
  --projects <id1>,<id2>,… --concurrency 16 --scans 5 --findings-per-scan 1000
```

With `INGEST_ASYNC=true` (8 workers) the same 16 uploaders reached 8,427
findings/s end to end. With 1 worker and `INGEST_MAX_QUEUE_DEPTH=5`, 60 parallel
`xila upload --wait` runs all succeeded: the 30 that arrived after the queue
filled got `429`, waited the `Retry-After` 30 s and went through on the retry.

What this means for bursts (a scan of about 1,000 findings each):

- 1,000 repositories at once is about 1M findings: roughly 2 minutes of work for
  one node like this. With `INGEST_ASYNC=true` every upload is accepted in
  seconds and the queue drains in minutes; with synchronous ingest most of the
  1,000 requests would wait minutes for a connection and many CI clients would
  time out.
- 1,000,000 repositories at once is about 1B findings: roughly 30 node-hours at
  this rate, and about 1 TB of raw reports waiting in the queue. That needs the
  work in milestone M11 (horizontal workers, reports outside Postgres, skipping
  unchanged scans, fair queueing per tenant).

## Web and worker nodes

Every node serves the API and, with `INGEST_ASYNC=true`, drains the queue with
`INGEST_WORKERS` workers. To scale the two separately, run nodes that only
accept uploads (`INGEST_WORKERS=0`, behind the load balancer) and worker nodes
(`INGEST_WORKERS` > 0, no traffic needed) against the same database. Uploads
land in the shared Postgres queue and any worker claims them
(`FOR UPDATE SKIP LOCKED`). Checked: a scan uploaded to a web-only node stayed
`processing` until a worker node started, then completed within a second.

In Kubernetes, `ingest.workerDeployment.enabled=true` in the Helm chart does
this, and `ingest.workerDeployment.keda` scales the workers on
`xila_ingest_queue_oldest_wait_seconds` (smoothed over 2 minutes). Scale on
queue age rather than depth: one large report and a hundred small ones look
the same in depth but not in how long uploads wait.

Connections: each node opens up to `DB_MAX_CONNS` (default 20). Past about 5
nodes, put PgBouncer (transaction pooling) in front of Postgres and lower
`DB_MAX_CONNS` per node, so the total stays below Postgres `max_connections`.

## Fair queueing and live tuning

The claim picks, in one statement, the org with the fewest jobs processing
and that org's oldest job whose project has nothing processing; a partial
unique index allows one processing job per project, so a burst against one
project uses one worker and the others move on. Orgs with pending work are
found by a loose index scan (one probe per org), and each org is looked into
at most 64 jobs deep, so the cost depends on the number of orgs with work
queued, not on queue depth. With 100,000 pending jobs in 20 orgs the claim
runs in a few milliseconds (`TestClaimQueryScalesToDeepQueue`); 2,000 jobs of
one org don't delay another org's single upload past the second claim
(`TestClaimFairUnderDeepBacklog`).

`PUT /ingest/settings` changes the 429 threshold and the workers per worker
node at runtime; each node applies it on its next queue sample. If the
settings can't be read, a node keeps what it has rather than falling back to
the env values.
