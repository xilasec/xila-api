-- Splitting a multi-host infrastructure scan per asset (M12 12.16): with
-- split_assets the scan's findings are attributed to one host asset each (the
-- host the scanner names), created on first sight, instead of to the scan's
-- single asset.
ALTER TABLE scans ADD COLUMN split_assets BOOLEAN NOT NULL DEFAULT false;
