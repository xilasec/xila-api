-- More pull connectors (M12 12.6): Snyk, GitHub, GitLab, Wiz and Tenable
-- Vulnerability Management, alongside the existing Dependency-Track and
-- DefectDojo connectors.
--
-- The Snyk connector's kind is `snyk-api`, not `snyk`: the file-upload Snyk
-- parser (internal/scanner/snyk.go) already writes findings under scanner
-- `snyk`, and a pull connector sharing that name would auto-close the other's
-- findings on every pull (see connector.go's kind-is-the-scanner-name rule).
--
-- auth_url is the OAuth token endpoint for the Wiz connector (its GraphQL API
-- endpoint and its OAuth issuer are different hosts depending on the tenant's
-- identity provider and region); every other kind leaves it empty. It is not a
-- secret, so it is stored in the clear like base_url.
ALTER TABLE connectors DROP CONSTRAINT connectors_kind_check;
ALTER TABLE connectors ADD CONSTRAINT connectors_kind_check
    CHECK (kind IN ('dependency-track', 'defectdojo', 'snyk-api', 'github', 'gitlab', 'wiz', 'tenable'));
ALTER TABLE connectors ADD COLUMN auth_url TEXT NOT NULL DEFAULT '';
