-- Project hierarchy (8.12): a project may have a parent in the same
-- organization, at most 5 levels deep, never in a cycle. A parent can be a
-- collection: it holds no scans or SBOMs of its own and rolls up its
-- descendants. Grants on a project reach every descendant
-- (membership.ProjectGrantsSQL reads project_ancestors).
ALTER TABLE projects
    ADD COLUMN parent_id UUID REFERENCES projects(id) ON DELETE SET NULL,
    ADD COLUMN is_collection BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT projects_parent_not_self CHECK (parent_id <> id);
CREATE INDEX idx_projects_parent ON projects (parent_id) WHERE parent_id IS NOT NULL;

-- project_ancestors(p): every strict ancestor of p with its distance
-- (1 = the parent). The depth guard only bounds a corrupt tree; the trigger
-- below keeps cycles out.
CREATE FUNCTION project_ancestors(p UUID) RETURNS TABLE (ancestor_id UUID, depth INT)
LANGUAGE sql STABLE AS $$
    WITH RECURSIVE up (id, depth) AS (
        SELECT parent_id, 1 FROM projects WHERE id = p AND parent_id IS NOT NULL
        UNION ALL
        SELECT pr.parent_id, up.depth + 1
          FROM up JOIN projects pr ON pr.id = up.id
         WHERE pr.parent_id IS NOT NULL AND up.depth < 64
    )
    SELECT id, depth FROM up
$$;

-- project_subtree(p): p itself (depth 0) and every descendant with its
-- distance below p.
CREATE FUNCTION project_subtree(p UUID) RETURNS TABLE (descendant_id UUID, depth INT)
LANGUAGE sql STABLE AS $$
    WITH RECURSIVE down (id, depth) AS (
        SELECT id, 0 FROM projects WHERE id = p
        UNION ALL
        SELECT c.id, down.depth + 1
          FROM down JOIN projects c ON c.parent_id = down.id
         WHERE down.depth < 64
    )
    SELECT id, depth FROM down
$$;

-- The tree's rules, in one place for every write path. Moves are serialized
-- (one advisory lock) so two concurrent moves can't close a cycle between
-- them.
CREATE FUNCTION projects_hierarchy_check() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    parent_level INT; -- the parent's level, a root being level 1
    height       INT; -- levels in NEW's subtree, NEW itself being 1
BEGIN
    IF NEW.is_collection AND (TG_OP = 'INSERT' OR NOT OLD.is_collection)
       AND (EXISTS (SELECT 1 FROM scans WHERE project_id = NEW.id)
            OR EXISTS (SELECT 1 FROM sboms WHERE project_id = NEW.id)) THEN
        RAISE EXCEPTION 'a project with scans or SBOMs cannot become a collection'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'projects_collection_empty';
    END IF;
    IF NEW.parent_id IS NULL
       OR (TG_OP = 'UPDATE' AND NEW.parent_id IS NOT DISTINCT FROM OLD.parent_id AND NEW.team_id = OLD.team_id) THEN
        RETURN NEW;
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('project_hierarchy'));
    IF NOT EXISTS (SELECT 1 FROM projects WHERE id = NEW.parent_id) THEN
        RETURN NEW; -- the foreign key reports it
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM projects pa
          JOIN teams tp ON tp.id = pa.team_id
          JOIN teams tc ON tc.id = NEW.team_id
         WHERE pa.id = NEW.parent_id AND tp.org_id = tc.org_id) THEN
        RAISE EXCEPTION 'a parent project must be in the same organization'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'projects_parent_same_org';
    END IF;
    IF NEW.parent_id = NEW.id
       OR EXISTS (SELECT 1 FROM project_ancestors(NEW.parent_id) WHERE ancestor_id = NEW.id) THEN
        RAISE EXCEPTION 'a project cannot be its own ancestor'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'projects_hierarchy_cycle';
    END IF;
    SELECT 1 + count(*) INTO parent_level FROM project_ancestors(NEW.parent_id);
    SELECT COALESCE(max(depth), 0) + 1 INTO height FROM project_subtree(NEW.id);
    IF parent_level + height > 5 THEN
        RAISE EXCEPTION 'project hierarchy deeper than 5 levels'
            USING ERRCODE = 'check_violation', CONSTRAINT = 'projects_hierarchy_depth';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER projects_hierarchy BEFORE INSERT OR UPDATE OF parent_id, team_id, is_collection ON projects
    FOR EACH ROW EXECUTE FUNCTION projects_hierarchy_check();

-- A collection holds no scans or SBOMs of its own: whatever creates one
-- (upload, connector pull, manual findings) is refused.
CREATE FUNCTION project_collection_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM projects WHERE id = NEW.project_id AND is_collection) THEN
        RAISE EXCEPTION 'project % is a collection: it holds no scans or SBOMs of its own', NEW.project_id
            USING ERRCODE = 'check_violation', CONSTRAINT = 'project_is_collection';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER scans_collection_guard BEFORE INSERT ON scans
    FOR EACH ROW EXECUTE FUNCTION project_collection_guard();
CREATE TRIGGER sboms_collection_guard BEFORE INSERT ON sboms
    FOR EACH ROW EXECUTE FUNCTION project_collection_guard();
