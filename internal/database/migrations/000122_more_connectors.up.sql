-- More pull connectors (M13 13.19): AWS Security Hub, Microsoft Defender,
-- Qualys VMDR, Trivy Operator, alongside the existing seven kinds.
--
-- role_arn is an optional IAM role ARN the AWS Security Hub connector assumes
-- via STS AssumeRole before calling GetFindings; every other kind leaves it
-- empty. Like auth_url it is not a secret, so it is stored in the clear.
--
-- Field reuse per kind (documented on Connector in connector.go):
--   aws-security-hub: base_url holds a comma-separated region list (not a
--     URL — Security Hub's endpoint is derived from the region, not chosen by
--     the operator); remote_project is an optional "product=...,severity=..."
--     filter; the token is optional (empty = the AWS SDK default credential
--     chain) or JSON {"access_key_id","secret_access_key","session_token"}.
--   microsoft-defender: base_url is the Defender for Endpoint API root;
--     auth_url is the tenant's Entra OAuth2 token endpoint (required, not a
--     secret, same shape as the Wiz connector); the token is JSON
--     {"client_id","client_secret"}.
--   qualys: base_url is the platform API URL; the token is JSON
--     {"username","password"} (HTTP Basic).
--   trivy-operator: base_url is the Kubernetes API server URL, or empty to
--     use the pod's own in-cluster service account; remote_project is an
--     optional namespace filter; the token is JSON {"bearer_token","ca_pem"}
--     (ca_pem optional) — bundled with the token like Wiz/Tenable's paired
--     secrets rather than a second secretbox.Registry column, since it is
--     only ever used alongside the bearer token and a connector has exactly
--     one token_enc to manage.
ALTER TABLE connectors DROP CONSTRAINT connectors_kind_check;
ALTER TABLE connectors ADD CONSTRAINT connectors_kind_check
    CHECK (kind IN ('dependency-track', 'defectdojo', 'snyk-api', 'github', 'gitlab', 'wiz', 'tenable',
                     'aws-security-hub', 'microsoft-defender', 'qualys', 'trivy-operator'));
ALTER TABLE connectors ADD COLUMN role_arn TEXT NOT NULL DEFAULT '';
