.DEFAULT_GOAL := help
.PHONY: help tidy run build bundle test test-integration docker-build up down purge logs licenses security hooks clients clients-check

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

tidy: ## Resolve and pin dependencies
	go mod tidy

run: ## Run the API locally (needs a reachable Postgres + OTLP endpoint)
	go run ./cmd/api

build: ## Compile the API-only binary into ./bin
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/xila-api ./cmd/api

cli: ## Build the xila CI client into ./bin
	go build -o bin/xila ./cmd/xila

licenses: ## Refresh the embedded SPDX License List + ScanCode categories (network)
	go generate ./internal/license

bundle: ## Build the SPA and compile one binary that serves UI + API
	cd web && pnpm install && pnpm build
	CGO_ENABLED=0 go build -tags embedfrontend -trimpath -ldflags="-s -w" -o bin/xila-api ./cmd/api

test: ## Run unit tests (DB-backed tests skip without TEST_DATABASE_URL)
	go test ./...

test-integration: ## Run all tests against a real Postgres (needs a disposable DB)
	@test -n "$(TEST_DATABASE_URL)" || { echo "set TEST_DATABASE_URL, e.g. postgres://xila:xila@localhost:5432/xila?sslmode=disable"; exit 1; }
	go test -p 1 -timeout 30m ./...

OAPI_CODEGEN = github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.1
OPENAPI_TS = openapi-typescript@7.13.0

clients: ## Regenerate the Go + TypeScript API clients from the OpenAPI spec
	go run ./internal/tools/opids -check
	go run ./internal/tools/openapi30 -o clients/go/openapi30.yaml
	cd clients/go && GOFLAGS= go run $(OAPI_CODEGEN) -config oapi-codegen.yaml openapi30.yaml && rm openapi30.yaml && GOFLAGS= go mod tidy
	cd clients/typescript && npx --yes $(OPENAPI_TS) ../../internal/apidoc/openapi.yaml -o src/schema.d.ts

clients-check: clients ## Fail if the committed clients are out of date with the spec
	@git diff --quiet -- clients || { echo "clients/ is out of date: run make clients and commit"; git --no-pager diff --stat -- clients; exit 1; }

security: ## Run grype + opengrep + KICS + gitleaks exactly as CI does
	scripts/security-scan.sh all

hooks: ## Install the pre-commit security hooks (grype, opengrep, KICS, gitleaks)
	pre-commit install

docker-build: ## Build the distroless image
	docker build -t xila-api:latest .

up: ## Start the full stack (api, postgres, collector, jaeger)
	docker compose up --build -d

down: ## Stop the stack (Postgres data is kept)
	docker compose down

purge: ## Stop the stack AND delete all data (drops the Postgres volume)
	docker compose down -v

logs: ## Tail the API logs
	docker compose logs -f api

PROD_COMPOSE = docker compose -f docker-compose.prod.yml

up-prod: ## Start the hardened production stack (needs DB_PASSWORD + JWT_SECRET in .env/env)
	$(PROD_COMPOSE) up --build -d

down-prod: ## Stop the production stack (Postgres data is kept)
	$(PROD_COMPOSE) down

logs-prod: ## Tail the production API logs
	$(PROD_COMPOSE) logs -f api
