-- Asset exposure: where an asset can be reached from. It multiplies the priority
-- of the findings on the asset (domain.Exposure) the way SBOM reachability does,
-- under the same rule: unknown (NULL) never discounts.
--   exposure_source  manual   = set by a person; inference never overwrites it
--                    inferred = derived from scanner evidence (internal/asset)
--   exposure_reason  the evidence, human-readable ("prowler s3_bucket_public_access
--                    failed on arn:aws:s3:::…")
ALTER TABLE assets
    ADD COLUMN exposure TEXT CHECK (exposure IN ('internet', 'internal', 'isolated')),
    ADD COLUMN exposure_source TEXT CHECK (exposure_source IN ('manual', 'inferred')),
    ADD COLUMN exposure_reason TEXT NOT NULL DEFAULT '',
    ADD COLUMN exposure_updated_at TIMESTAMPTZ,
    ADD CONSTRAINT assets_exposure_source CHECK ((exposure IS NULL) = (exposure_source IS NULL));

-- Typed relationships between assets, read as a sentence: from_asset <kind> to_asset
-- ("app:1.4 built_from python:3.12-slim", "app:1.4 deployed_as prod/app"). They may
-- cross projects (a platform team's base image, a product team's app image).
CREATE TABLE asset_relations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    from_asset_id UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    to_asset_id   UUID NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL CHECK (kind IN ('built_from', 'deployed_as', 'depends_on')),
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (from_asset_id <> to_asset_id),
    UNIQUE (from_asset_id, to_asset_id, kind)
);

CREATE INDEX idx_asset_relations_to ON asset_relations (to_asset_id, kind);
