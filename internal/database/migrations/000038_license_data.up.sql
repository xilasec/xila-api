-- License data (M5.3).
--
-- Every SBOM component's license statements are resolved into a normalized SPDX
-- license expression on ingest (package internal/license). The raw `license`
-- column stays as the document said it.
--
--   license_expression  normalized SPDX expression; '' when the component has no
--                       license or a statement doesn't parse
--   license_ids         license ids it mentions (canonical case; LicenseRef-*
--                       verbatim), from every statement that parsed
--   license_categories  their distinct ScanCode LicenseDB categories
--   license_resolved    true when everything parsed into known ids; NULL = not
--                       computed yet. Rows that predate this migration are NULL
--                       and get resolved by a one-time, idempotent backfill at
--                       startup (sbom.Repository.BackfillLicenses), which only
--                       ever touches NULL rows — the partial index keeps the
--                       no-op re-run on later boots an index probe.
ALTER TABLE sbom_components
    ADD COLUMN IF NOT EXISTS license_expression TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS license_ids TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS license_categories TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS license_resolved BOOLEAN;

CREATE INDEX IF NOT EXISTS idx_components_license_unresolved
    ON sbom_components (license) WHERE license_resolved IS NULL;
CREATE INDEX IF NOT EXISTS idx_components_license_ids
    ON sbom_components USING GIN (license_ids);

-- Named sets of license ids ("approved for distribution", "needs legal
-- review") for license policies. Built-in groups per ScanCode category are
-- computed from the embedded catalog and not stored.
CREATE TABLE IF NOT EXISTS license_groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    license_ids TEXT[] NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
