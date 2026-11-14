DROP TRIGGER IF EXISTS sboms_collection_guard ON sboms;
DROP TRIGGER IF EXISTS scans_collection_guard ON scans;
DROP FUNCTION IF EXISTS project_collection_guard();
DROP TRIGGER IF EXISTS projects_hierarchy ON projects;
DROP FUNCTION IF EXISTS projects_hierarchy_check();
DROP FUNCTION IF EXISTS project_subtree(UUID);
DROP FUNCTION IF EXISTS project_ancestors(UUID);
DROP INDEX IF EXISTS idx_projects_parent;
ALTER TABLE projects
    DROP CONSTRAINT IF EXISTS projects_parent_not_self,
    DROP COLUMN IF EXISTS is_collection,
    DROP COLUMN IF EXISTS parent_id;
