-- The previous key (CVE alone for package-less findings); the next dedup pass
-- re-elects groups under it.
UPDATE findings SET correlation_key = lower((SELECT min(c) FROM unnest(cve) c))
WHERE cardinality(cve) > 0 AND package_name = '' AND file_path <> '';
