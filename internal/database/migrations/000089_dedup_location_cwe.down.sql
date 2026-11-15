-- Previous behavior: no correlation key for non-CVE findings. Clear the keys
-- this migration added and the duplicate_of they produced; the next dedup
-- pass re-elects whatever remains under the old CVE-only rule.
UPDATE findings SET duplicate_of = NULL
WHERE correlation_key LIKE 'loc|%';

UPDATE findings SET correlation_key = NULL
WHERE correlation_key LIKE 'loc|%';
