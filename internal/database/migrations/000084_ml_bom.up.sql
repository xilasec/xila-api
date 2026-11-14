-- AI inventory (ML-BOM): every SBOM component gets a kind — software, model
-- (CycloneDX machine-learning-model), dataset (CycloneDX data) or ai-service
-- (a service that serves a model) — and AI components their model-card
-- essentials as ml (supplier, task, architecture, datasets, external refs…).
ALTER TABLE sbom_components
    ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'software'
        CHECK (kind IN ('software', 'model', 'dataset', 'ai-service')),
    ADD COLUMN IF NOT EXISTS ml JSONB;

-- Components stored before keep their CycloneDX type: classify them (their
-- model cards weren't kept, so ml stays unknown until the next upload).
UPDATE sbom_components SET kind = 'model' WHERE type = 'machine-learning-model';
UPDATE sbom_components SET kind = 'dataset' WHERE type = 'data';

-- The AI inventory filter (kind <> 'software') reads only the few AI rows.
CREATE INDEX IF NOT EXISTS sbom_components_ai_kind ON sbom_components (project_id, kind) WHERE kind <> 'software';
