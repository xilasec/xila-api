# Code quality

Go static analysis runs through golangci-lint v2, configured in `.golangci.yml`.
The whole repository is held at zero findings, so a new finding is always about
the change that introduced it.

```bash
make lint       # the same run CI does
make lint-fix   # apply the safe auto-fixes, then gofmt + goimports
make vuln       # govulncheck: known vulnerabilities the code actually reaches
```

The same pinned golangci-lint runs in three places: `make lint`, the
pre-commit hook (`make hooks`), and the CI `lint` job. CI also runs `govulncheck`
(the `vuln` job) next to the grype scans in the security workflow.

## What is checked

- Correctness: govet, staticcheck, errcheck (type assertions included in
  production code), errorlint, nilerr, ineffassign, unused, forcetypeassert.
- Security and resources: gosec, bodyclose, noctx, sqlclosecheck,
  rowserrcheck, fatcontext, containedctx, bidichk, asciicheck.
- Style and naming: revive (a focused rule set), gocritic, godot, misspell,
  dupword, predeclared, errname, whitespace, unconvert, usestdlibvars.
- Modernization: modernize, intrange, perfsprint, exptostd.
- Tests: thelper (helpers call `t.Helper()` first), usetesting, testifylint.
- Complexity ceilings: gocyclo (30), nestif (10), funlen (250 lines / 150
  statements), dupl. These stop new code from growing past them; they are not a
  reason to refactor working code.
- Formatting: gofmt and goimports (local imports grouped last).

## Deliberately off

| Linter or check | Why |
| --- | --- |
| paralleltest | Integration tests share one Postgres and `TRUNCATE` between tests (`go test -p 1`); `t.Parallel` would make them race. |
| wsl_v5, gofumpt | Blank-line and formatting style beyond gofmt; the house style is gofmt. |
| goconst | Repeated SQL fragments and test literals read better inline. |
| staticcheck QF\* | Editor quick-fix suggestions (De Morgan, tagged switch) that gopls offers inline; not defects. |
| errorlint `errorf` | The codebase classifies with a sentinel and flattens the cause on purpose: `fmt.Errorf("%w: %v", ErrInvalid, err)`. Handlers map the sentinel to a status; a remote's or library's error must not become matchable. Plain wrapping uses `%w`. |
| gocritic singleCaseSwitch, ifElseChain | Style preferences with real counter-cases. |
| noctx in `cmd/` and dev tools | noctx guards server code, where a cancelled request must stop its outbound calls. The CLIs bound each request with an `http.Client` timeout. |

`exhaustive` is opt-in per switch: most switches handle a subset of an enum and
let the code after the switch be the default. Mark a switch that must name every
value with `//exhaustive:enforce`.

In tests, a failed type assertion on decoded JSON panics and fails the test with
a stack trace, which is the check; production code must use the comma-ok form.

## Suppressing a finding

Fix the cause first. When a finding is a deliberate exception, suppress it on
the line (or the declaration) with the linter and the reason:

```go
return nil //nolint:nilerr // save-time check only: the dialer re-checks at connect time
```

`nolintlint` rejects a bare `//nolint`, one without a reason, and one that no
longer suppresses anything. Never suppress gosec, bodyclose or sqlclosecheck
without saying exactly why the code is safe.
