DROP INDEX IF EXISTS sbom_components_ai_kind;
-- AI service rows exist only as the inventory rows of services.
UPDATE sboms s SET component_count = s.component_count - x.n
FROM (SELECT sbom_id, count(*)::int AS n FROM sbom_components WHERE kind = 'ai-service' GROUP BY sbom_id) x
WHERE x.sbom_id = s.id;
DELETE FROM sbom_components WHERE kind = 'ai-service';
ALTER TABLE sbom_components DROP COLUMN IF EXISTS ml, DROP COLUMN IF EXISTS kind;
