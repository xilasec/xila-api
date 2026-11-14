-- Gate on newly-introduced findings only (PR checks): don't fail on pre-existing
-- debt. "New" = seen in exactly one scan so far (first_scan_id = last_scan_id).
ALTER TABLE gate_policies ADD COLUMN IF NOT EXISTS new_only BOOLEAN NOT NULL DEFAULT false;
