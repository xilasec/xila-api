-- Policy scope by project tags: a policy applies to a project when its scope
-- (global / its project list) covers it AND (include_tags is empty OR the
-- project has any of them) AND the project has none of exclude_tags — so
-- "every project except internal-tool" needs no project list.
ALTER TABLE policies
    ADD COLUMN include_tags TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN exclude_tags TEXT[] NOT NULL DEFAULT '{}';
