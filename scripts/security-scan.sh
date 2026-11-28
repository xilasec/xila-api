#!/usr/bin/env bash
# Security scans with one definition shared by pre-commit, `make security` and
# CI, so a local pass means a CI pass.
#
#   scripts/security-scan.sh grype           dependencies (go.mod, pnpm-lock): fail on High+ with a fix
#   scripts/security-scan.sh opengrep [f…]   SAST over the given files (default: the whole repo)
#   scripts/security-scan.sh kics            IaC: Dockerfile, compose, Helm chart, workflows; fail on Low+
#   scripts/security-scan.sh gitleaks [mode] secrets; any finding fails. mode: (none) the working tree,
#                                            --staged what is about to be committed, --history every commit
#   scripts/security-scan.sh image <ref>     a built container image (Go stdlib + base OS): fail on High+ with a fix
#   scripts/security-scan.sh all             grype + opengrep + kics + gitleaks (working tree)
#
# Tools: a local binary is used when present; otherwise the pinned container
# image (grype, kics, gitleaks) runs through docker or podman. opengrep has no official
# image — install it (see docs/SECURITY_SCANNING.md).
set -euo pipefail

# Pinned versions — bump here (and in .github/workflows/security.yml).
GRYPE_IMAGE="anchore/grype:v0.110.0"
KICS_IMAGE="checkmarx/kics:v2.2.1@sha256:49ccc54b6ae7f5d5fc95e96f8f95c18c57f3bba047ab611a03d80792bdff6757"
GITLEAKS_IMAGE="zricethezav/gitleaks:v8.30.1@sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb"
OPENGREP_CONFIG="${OPENGREP_CONFIG:-auto}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# When SARIF_DIR is set (CI), each tool also writes <SARIF_DIR>/<tool>.sarif
# for upload to GitHub code scanning. This never changes the gate pass/fail;
# the local/pre-commit flow leaves it unset.
SARIF_DIR="${SARIF_DIR:-}"
[[ -n "$SARIF_DIR" ]] && mkdir -p "$SARIF_DIR"

engine() {
	if command -v docker >/dev/null 2>&1; then echo docker
	elif command -v podman >/dev/null 2>&1; then echo podman
	else echo "error: need $1 installed, or docker/podman to run its image" >&2; exit 2
	fi
}

run_grype() { # grype <target> [sarif-name]
	local lo=() mo=() co=()
	if [[ -n "$SARIF_DIR" ]]; then
		local nm="${2:-grype}.sarif"
		lo=(-o "sarif=$SARIF_DIR/$nm" -o table)
		mo=(-v "$SARIF_DIR:/sarif")
		co=(-o "sarif=/sarif/$nm" -o table)
	fi
	if command -v grype >/dev/null 2>&1; then
		grype "$1" --config .grype.yaml "${lo[@]}"
	else
		local target="$1" e
		e=$(engine grype)
		[[ "$target" == dir:. ]] && target=dir:/src
		"$e" run --rm -v "$ROOT:/src:ro" -v "${XDG_CACHE_HOME:-$HOME/.cache}/grype:/.cache/grype" \
			"${mo[@]}" -w /src "$GRYPE_IMAGE" "$target" --config /src/.grype.yaml "${co[@]}"
	fi
}

cmd_grype() {
	echo "▶ grype: dependencies (fails on High/Critical with a fix)"
	run_grype dir:. grype-dependencies
}

cmd_image() {
	local ref="${1:?usage: security-scan.sh image <image-ref>}"
	echo "▶ grype: image $ref (fails on High/Critical with a fix)"
	local lo=() mo=() co=()
	if [[ -n "$SARIF_DIR" ]]; then
		lo=(-o "sarif=$SARIF_DIR/grype-image.sarif" -o table)
		mo=(-v "$SARIF_DIR:/sarif")
		co=(-o "sarif=/sarif/grype-image.sarif" -o table)
	fi
	if command -v grype >/dev/null 2>&1; then
		grype "$ref" --config .grype.yaml "${lo[@]}"
	else
		local e; e=$(engine grype)
		"$e" run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$ROOT:/src:ro" \
			"${mo[@]}" "$GRYPE_IMAGE" "$ref" --config /src/.grype.yaml "${co[@]}"
	fi
}

cmd_opengrep() {
	if ! command -v opengrep >/dev/null 2>&1; then
		echo "error: opengrep is not installed — see docs/SECURITY_SCANNING.md" >&2
		exit 2
	fi
	local targets=("$@")
	[[ ${#targets[@]} -eq 0 ]] && targets=(.)
	echo "▶ opengrep: SAST (config: $OPENGREP_CONFIG; any finding fails)"
	local so=()
	[[ -n "$SARIF_DIR" ]] && so=(--sarif --output "$SARIF_DIR/opengrep.sarif")
	opengrep scan --config "$OPENGREP_CONFIG" --error --quiet --disable-version-check "${so[@]}" "${targets[@]}"
}

cmd_kics() {
	echo "▶ kics: infrastructure as code (fails on Low and above)"
	local out; out=$(mktemp -d); chmod 777 "$out"
	local args=(scan --no-progress --disable-secrets --report-formats json,sarif
		--fail-on critical,high,medium,low --ignore-on-exit errors)
	local status=0
	if command -v kics >/dev/null 2>&1; then
		kics "${args[@]}" -p "$ROOT" -o "$out" \
			--exclude-paths "$ROOT/web/node_modules,$ROOT/web/build,$ROOT/internal/scanner/testdata" || status=$?
	else
		local e; e=$(engine kics)
		"$e" run --rm -v "$ROOT:/src:ro" -v "$out:/out" "$KICS_IMAGE" "${args[@]}" -p /src -o /out \
			--exclude-paths /src/web/node_modules,/src/web/build,/src/internal/scanner/testdata >/dev/null || status=$?
	fi
	if [[ -f "$out/results.json" ]]; then
		jq -r '.queries[] | select(.severity != "INFO" and .severity != "TRACE")
			| .severity as $s | .query_name as $q | .files[]
			| "  \($s)  \($q)  \(.file_name | sub("^.*/src/"; "") ):\(.line)"' "$out/results.json"
	fi
	[[ -n "$SARIF_DIR" && -f "$out/results.sarif" ]] && cp "$out/results.sarif" "$SARIF_DIR/kics.sarif"
	rm -rf "$out"
	return "$status"
}

cmd_gitleaks() {
	local args
	case "${1:-}" in
		"") echo "▶ gitleaks: secrets in the working tree"; args=(dir .) ;;
		--staged) echo "▶ gitleaks: secrets in staged changes"; args=(git --staged .) ;;
		--history) echo "▶ gitleaks: secrets in every commit"; args=(git .) ;;
		*) echo "usage: $0 gitleaks [--staged|--history]" >&2; exit 2 ;;
	esac
	args+=(--config .gitleaks.toml --redact --no-banner --exit-code 1)
	local lrep=() mrep=() crep=()
	if [[ -n "$SARIF_DIR" ]]; then
		lrep=(--report-format sarif --report-path "$SARIF_DIR/gitleaks.sarif")
		mrep=(-v "$SARIF_DIR:/sarif")
		crep=(--report-format sarif --report-path /sarif/gitleaks.sarif)
	fi
	if command -v gitleaks >/dev/null 2>&1; then
		gitleaks "${args[@]}" "${lrep[@]}"
	else
		local e; e=$(engine gitleaks)
		"$e" run --rm -v "$ROOT:/repo" "${mrep[@]}" -w /repo "$GITLEAKS_IMAGE" "${args[@]}" "${crep[@]}"
	fi
}

case "${1:-all}" in
	grype) cmd_grype ;;
	image) shift; cmd_image "$@" ;;
	opengrep) shift; cmd_opengrep "$@" ;;
	kics) cmd_kics ;;
	gitleaks) shift; cmd_gitleaks "$@" ;;
	all) cmd_grype; cmd_opengrep; cmd_kics; cmd_gitleaks; echo "✔ all security scans passed" ;;
	*) echo "usage: $0 {grype|opengrep [files…]|kics|gitleaks [--staged|--history]|image <ref>|all}" >&2; exit 2 ;;
esac
