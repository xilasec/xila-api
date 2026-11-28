# syntax=docker/dockerfile:1@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183

# Multi-arch without emulation: the web and Go stages run on the build
# machine's platform ($BUILDPLATFORM) and Go cross-compiles for $TARGETARCH;
# only the final distroless layer is per-platform.
#
# Every image is pinned by digest (the tag stays for readers and Dependabot,
# which updates both): a tag can be re-pointed upstream, a digest can't, so a
# release can't silently pick up different bytes.

# ---- web build: compile the SvelteKit SPA to static files ----
FROM --platform=$BUILDPLATFORM node:26-alpine@sha256:6bd9ab43c0ec0190ca7b2d193906cb8b7edf6e7f4afa43ddeccd6452710bffb5 AS web
WORKDIR /web
# Exact version: the pnpm the lockfile is written with (pnpm-lock.yaml v9 / pnpm 11).
RUN npm install -g pnpm@11.11.0
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
# kics-scan ignore-line (versions are pinned by pnpm-lock.yaml; --frozen-lockfile enforces it)
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

# ---- go build: embed the SPA into a single static binary ----
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ARG TARGETOS=linux
ARG TARGETARCH
ARG VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/build ./web/build
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -tags embedfrontend -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/xila-api ./cmd/api

# ---- runtime: one image serves UI + API on :8080 ----
FROM gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5
LABEL org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.source="https://github.com/xilasec/xila-api"
COPY --from=build /out/xila-api /xila-api
EXPOSE 8080
USER nonroot:nonroot
# Distroless has no shell or curl: the binary probes its own /health.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/xila-api", "healthcheck"]
ENTRYPOINT ["/xila-api"]
