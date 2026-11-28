# Changelog

## [0.1.1](https://github.com/xilasec/xila-api/compare/v0.1.0...v0.1.1) (2026-11-28)


### Bug fixes

* **ci:** a release build must start on the tag's commit ([#53](https://github.com/xilasec/xila-api/issues/53)) ([e3dbc85](https://github.com/xilasec/xila-api/commit/e3dbc8576e5dba8c03b3a374d1ac1a138c3f8524))
* **ci:** log the release job in to the registry; let a failed release be retried ([#51](https://github.com/xilasec/xila-api/issues/51)) ([d6a74dd](https://github.com/xilasec/xila-api/commit/d6a74dda6a2d179f0c2a486e30659a5ae25a1f26))

## 0.1.0 (2026-11-28)

The first release. Xila unifies scanner and SBOM output into deduplicated
findings with a lifecycle, exploit-aware priority, compliance posture and
cross-project rollups, in one Go binary with PostgreSQL.

### Highlights

* Ingestion: 60+ native scanner parsers plus SARIF and a no-code parser, CycloneDX (JSON and XML) and SPDX SBOMs, and pull connectors (Dependency-Track, DefectDojo, Snyk, GitHub, GitLab, Wiz, Tenable, AWS Security Hub, Microsoft Defender, Qualys, Trivy Operator).
* Findings: cross-tool deduplication, branches and versions, triage with structured VEX analysis, risk acceptances with approval and extensions, SLAs, and priority from severity, EPSS, KEV, exploit maturity, reachability and asset exposure.
* Supply chain: SBOM history with diff, dependency graph and vulnerability timeline; advisory matching (OSV, GitHub, a local mirror, private advisories, NVD by CPE); malicious-package detection; package freshness; license data and terms; component and vulnerability policies in CEL; VEX import and export; SBOMs kept as uploaded; third-party notices.
* Governance: compliance frameworks, the portfolio view, EU CRA Article 14 cases, CI security gates with PR comments and check runs, issue-tracker sync, notifications and an in-app inbox.
* Platform: organizations, teams, projects and roles, OIDC / SAML / LDAP single sign-on and SCIM, two-factor, service accounts with workload identity federation, the audit log, an MCP server for AI agents, and signed, immutable releases with provenance and SBOM attestations.

### Features since v0.1.0-rc.1

* M13: VEX analysis on triage and assessment approval per project ([#33](https://github.com/xilasec/xila-api/issues/33)), rule side actions and project-owned rules ([#34](https://github.com/xilasec/xila-api/issues/34)), internal components and private registries ([#35](https://github.com/xilasec/xila-api/issues/35)), notification events and stored gate state ([#36](https://github.com/xilasec/xila-api/issues/36)), idle session timeout and an MCP personal-data filter ([#37](https://github.com/xilasec/xila-api/issues/37)), issue-tracker comments, templates and webhooks ([#38](https://github.com/xilasec/xila-api/issues/38))
* Malicious packages and risk acceptance extensions ([#44](https://github.com/xilasec/xila-api/issues/44))
* SBOM originals, component attribution, license terms and notices ([#45](https://github.com/xilasec/xila-api/issues/45))
* Automatic, immutable releases with signed provenance and SBOM attestations ([#46](https://github.com/xilasec/xila-api/issues/46), [#48](https://github.com/xilasec/xila-api/issues/48))

### Bug fixes

* The database URL escapes its parts: a password containing `/`, `@`, `#` or `?` no longer breaks startup ([4f7418d](https://github.com/xilasec/xila-api/commit/4f7418d1ec654d68241ba55e3d9b5ffc84aebc9b))
* Path ids are copied, so a handler that hands one to a goroutine can't read another request's id (the race fixed in [#38](https://github.com/xilasec/xila-api/issues/38))
* The release workflow grants its security scans what they need ([#47](https://github.com/xilasec/xila-api/issues/47))
