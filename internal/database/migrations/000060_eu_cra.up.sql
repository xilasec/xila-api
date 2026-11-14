-- EU Cyber Resilience Act (Regulation (EU) 2024/2847), Annex I: Part I
-- essential cybersecurity requirements and Part II vulnerability handling.
--
-- Only what Xila can measure is mapped. New match types for requirements that
-- aren't about a vulnerability class:
--   kev   fails while an open finding is on CISA's Known Exploited list
--   sla   fails while an open finding is past its remediation deadline
--   sbom  fails while the project has no SBOM on its default version
--   vex   fails while the project has documented no vulnerability analysis
--         (no VEX statement and no finding assessment)
-- Process requirements (an update mechanism, a disclosure policy, …) are
-- `manual` controls: never scored, never shown as passing — they are listed
-- for attestation in the CRA evidence report.

ALTER TABLE controls ADD COLUMN assessment text NOT NULL DEFAULT 'automatic'
    CHECK (assessment IN ('automatic', 'manual'));

ALTER TABLE control_mappings DROP CONSTRAINT IF EXISTS control_mappings_match_type_check;
ALTER TABLE control_mappings ADD CONSTRAINT control_mappings_match_type_check
    CHECK (match_type IN ('cwe', 'rule', 'kev', 'sla', 'sbom', 'vex'));

INSERT INTO frameworks (key, name, version, description)
VALUES ('eu-cra', 'EU Cyber Resilience Act — Annex I', '2024/2847',
        'Essential cybersecurity requirements (Part I) and vulnerability handling requirements (Part II) of Regulation (EU) 2024/2847. Measurable requirements are mapped to findings, SBOMs and VEX; process requirements are manual and need attestation.');

INSERT INTO controls (framework_id, code, title, description, assessment)
SELECT fw.id, v.code, v.title, v.description, v.assessment
FROM frameworks fw
CROSS JOIN (VALUES
    ('I.1',     'Appropriate level of cybersecurity based on the risks', 'Design, development and production ensure a level of cybersecurity appropriate to the risks.', 'manual'),
    ('I.2(a)',  'No known exploitable vulnerabilities', 'Made available on the market without known exploitable vulnerabilities. Measured: no open finding on CISA KEV.', 'automatic'),
    ('I.2(b)',  'Secure by default configuration', 'Made available with a secure-by-default configuration. Measured: insecure-default and misconfiguration weaknesses.', 'automatic'),
    ('I.2(c)',  'Vulnerabilities addressable through security updates', 'Ensure vulnerabilities can be addressed through security updates, including automatic updates.', 'manual'),
    ('I.2(d)',  'Protection from unauthorised access', 'Appropriate control mechanisms: authentication, identity and access management. Measured: access-control and authentication weaknesses.', 'automatic'),
    ('I.2(e)',  'Confidentiality of data', 'Protect the confidentiality of stored, transmitted or processed data, e.g. by encryption. Measured: missing or weak cryptography, information exposure.', 'automatic'),
    ('I.2(f)',  'Integrity of data, commands and programs', 'Protect integrity against unauthorised manipulation or modification. Measured: integrity-verification, deserialisation and CSRF weaknesses.', 'automatic'),
    ('I.2(g)',  'Data minimisation', 'Process only data that are adequate, relevant and limited to what is necessary.', 'manual'),
    ('I.2(h)',  'Availability of essential functions', 'Protect the availability of essential functions, including resilience against denial-of-service. Measured: resource-exhaustion weaknesses.', 'automatic'),
    ('I.2(i)',  'Minimise impact on other services', 'Minimise the negative impact on the availability of services provided by other devices or networks.', 'manual'),
    ('I.2(j)',  'Limit attack surfaces', 'Designed to limit attack surfaces, including external interfaces. Measured: exposed debug code, dangerous methods and resources.', 'automatic'),
    ('I.2(k)',  'Reduce the impact of an incident', 'Exploitation mitigation mechanisms and techniques. Measured: memory-corruption weaknesses.', 'automatic'),
    ('I.2(l)',  'Security logging and monitoring', 'Record and monitor relevant internal activity, with an opt-out. Measured: insufficient-logging and log-injection weaknesses.', 'automatic'),
    ('I.2(m)',  'Secure removal of data and settings', 'Users can securely and easily remove all data and settings.', 'manual'),
    ('II.1',    'Identify and document components (SBOM)', 'Identify and document vulnerabilities and components, including a software bill of materials. Measured: an SBOM exists for the default version.', 'automatic'),
    ('II.2',    'Remediate vulnerabilities without delay', 'Address and remediate vulnerabilities without delay, including through security updates. Measured: no open finding past its remediation SLA.', 'automatic'),
    ('II.3',    'Regular security testing and review', 'Apply effective and regular tests and reviews of the security of the product.', 'manual'),
    ('II.4',    'Disclose fixed vulnerabilities', 'Once an update is available, share and publicly disclose information about fixed vulnerabilities. Measured: vulnerability analysis is documented (VEX statements or finding assessments).', 'automatic'),
    ('II.5',    'Coordinated vulnerability disclosure policy', 'Put in place and enforce a policy on coordinated vulnerability disclosure.', 'manual'),
    ('II.6',    'Contact address for reporting vulnerabilities', 'Facilitate the sharing of information about potential vulnerabilities, including a contact address.', 'manual'),
    ('II.7',    'Secure distribution of updates', 'Provide mechanisms to securely distribute updates.', 'manual'),
    ('II.8',    'Timely, free security updates with advisories', 'Disseminate security updates without delay and free of charge, with advisory messages.', 'manual')
) AS v(code, title, description, assessment)
WHERE fw.key = 'eu-cra';

-- Part I(2) by weakness class (CWE): the classes each requirement is about.
INSERT INTO control_mappings (control_id, match_type, cwe)
SELECT c.id, 'cwe', v.cwe
FROM controls c
JOIN frameworks fw ON fw.id = c.framework_id AND fw.key = 'eu-cra'
JOIN (VALUES
    -- (b) secure by default: insecure default initialisation, incorrect
    -- default permissions, default credentials, configuration.
    ('I.2(b)', 1188), ('I.2(b)', 276), ('I.2(b)', 1392), ('I.2(b)', 1393), ('I.2(b)', 16),
    -- (d) unauthorised access: access control, authorisation, authentication,
    -- missing authentication, hard-coded / weakly protected credentials.
    ('I.2(d)', 284), ('I.2(d)', 285), ('I.2(d)', 862), ('I.2(d)', 863), ('I.2(d)', 639),
    ('I.2(d)', 287), ('I.2(d)', 306), ('I.2(d)', 307), ('I.2(d)', 798), ('I.2(d)', 522), ('I.2(d)', 521),
    -- (e) confidentiality: missing / cleartext / weak cryptography, exposure.
    ('I.2(e)', 311), ('I.2(e)', 312), ('I.2(e)', 319), ('I.2(e)', 326), ('I.2(e)', 327),
    ('I.2(e)', 328), ('I.2(e)', 200), ('I.2(e)', 359), ('I.2(e)', 532),
    -- (f) integrity: authenticity and integrity checks, unsafe deserialisation,
    -- CSRF, untrusted code inclusion.
    ('I.2(f)', 345), ('I.2(f)', 347), ('I.2(f)', 353), ('I.2(f)', 494), ('I.2(f)', 502),
    ('I.2(f)', 352), ('I.2(f)', 829), ('I.2(f)', 915),
    -- (h) availability: uncontrolled resource consumption, ReDoS, recursion.
    ('I.2(h)', 400), ('I.2(h)', 770), ('I.2(h)', 1333), ('I.2(h)', 674), ('I.2(h)', 409),
    -- (j) attack surface: debug code, exposed dangerous methods, resources
    -- exposed to the wrong sphere, open redirects / SSRF reaching internals.
    ('I.2(j)', 489), ('I.2(j)', 749), ('I.2(j)', 668), ('I.2(j)', 918),
    -- (k) exploitation mitigation: memory corruption.
    ('I.2(k)', 787), ('I.2(k)', 416), ('I.2(k)', 125), ('I.2(k)', 120), ('I.2(k)', 190),
    -- (l) logging and monitoring.
    ('I.2(l)', 778), ('I.2(l)', 117), ('I.2(l)', 223)
) AS v(code, cwe) ON v.code = c.code;

-- The requirements measured by project facts rather than weakness classes.
INSERT INTO control_mappings (control_id, match_type)
SELECT c.id, v.match_type
FROM controls c
JOIN frameworks fw ON fw.id = c.framework_id AND fw.key = 'eu-cra'
JOIN (VALUES
    ('I.2(a)', 'kev'),
    ('II.1',   'sbom'),
    ('II.2',   'sla'),
    ('II.4',   'vex')
) AS v(code, match_type) ON v.code = c.code;
