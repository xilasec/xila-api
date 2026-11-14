-- SOC 2 Trust Services Criteria (framework soc2): CC1–CC9, A1, C1, PI1, P1–P8.
-- Logical access (CC6), system operations (CC7) and change management (CC8.1)
-- are measured where a signal maps (CWE classes, leaked secrets, KEV / SBOM /
-- SLA, Checkov/Trivy checks, and the Prowler checks Prowler's SOC 2 packs map
-- to those criteria); physical criteria (CC6.4, CC6.5) and all others are
-- manual. Titles are paraphrased, never the criteria's text.

INSERT INTO frameworks (key, name, version, description)
VALUES ('soc2', 'SOC 2 Trust Services Criteria', '2017 (rev. 2022)',
        'AICPA Trust Services Criteria for SOC 2: the Common Criteria plus Availability, Confidentiality, Processing Integrity and Privacy. Logical access, system operations and change management (CC6, CC7, CC8.1) are measured where findings evidence them; the rest are attested. Titles are paraphrased; consult the criteria for their text.');

INSERT INTO controls (framework_id, code, title, description, assessment)
SELECT fw.id, v.code, v.title, v.description, v.assessment
FROM frameworks fw
CROSS JOIN (VALUES
    ('CC1.1', 'Commitment to integrity and ethical values', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC1.2', 'Board independence and oversight of internal control', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC1.3', 'Structures, reporting lines and authorities are established', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC1.4', 'Commitment to attract, develop and retain competent people', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC1.5', 'People are held accountable for internal control duties', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC2.1', 'Relevant, quality information supports internal control', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC2.2', 'Internal communication of control objectives and duties', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC2.3', 'Communication with external parties about internal control', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC3.1', 'Objectives are clear enough to identify and assess risks', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC3.2', 'Risks to objectives are identified and analysed', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC3.3', 'The potential for fraud is considered in risk assessment', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC3.4', 'Significant changes affecting internal control are assessed', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC4.1', 'Controls are evaluated through ongoing and separate reviews', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC4.2', 'Control deficiencies are evaluated and communicated in time', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC5.1', 'Control activities are chosen to bring risks to acceptable levels', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC5.2', 'General controls over technology are selected and developed', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC5.3', 'Control activities are deployed through policies and procedures', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC6.1', 'Logical access security protects information assets', 'Measured: open findings in CWE-256, CWE-257, CWE-259, CWE-260, CWE-287, CWE-288 and 21 more weakness classes; open secret findings; failing Checkov/Prowler/Trivy checks.', 'automatic'),
    ('CC6.2', 'Users are registered and authorised before credentials are issued', 'Measured: failing Prowler checks.', 'automatic'),
    ('CC6.3', 'Access is granted, changed and removed by role and least privilege', 'Measured: open findings in CWE-22, CWE-250, CWE-269, CWE-276, CWE-284, CWE-285 and 4 more weakness classes; failing Checkov/Prowler/Trivy checks.', 'automatic'),
    ('CC6.4', 'Physical access to facilities and assets is restricted', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC6.5', 'Asset protections end only once data can no longer be recovered', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC6.6', 'The system is protected against threats from outside its boundaries', 'Measured: open findings in CWE-918; failing Checkov/Prowler/Trivy checks.', 'automatic'),
    ('CC6.7', 'Transmission and movement of information is restricted and protected', 'Measured: open findings in CWE-200, CWE-201, CWE-209, CWE-215, CWE-295, CWE-297 and 11 more weakness classes; failing Checkov/Prowler/Trivy checks.', 'automatic'),
    ('CC6.8', 'Unauthorised or malicious software is prevented or detected', 'Measured: open findings in CWE-353, CWE-494, CWE-506, CWE-829, CWE-912; failing Prowler checks.', 'automatic'),
    ('CC7.1', 'Configuration changes and new vulnerabilities are detected', 'Measured: open findings in CWE-16, CWE-489, CWE-614, CWE-942, CWE-1004, CWE-1188 and 2 more weakness classes; open findings on CISA KEV; an SBOM on the default branch; failing Checkov/Prowler/Trivy checks.', 'automatic'),
    ('CC7.2', 'System components are monitored for anomalies', 'Measured: open findings in CWE-117, CWE-223, CWE-778; failing Checkov/Prowler/Trivy checks.', 'automatic'),
    ('CC7.3', 'Security events are evaluated to decide whether they are incidents', 'Measured: failing Prowler checks.', 'automatic'),
    ('CC7.4', 'Security incidents are responded to under a defined programme', 'Measured: failing Prowler checks.', 'automatic'),
    ('CC7.5', 'Recovery from security incidents is identified and carried out', 'Measured: failing Prowler checks.', 'automatic'),
    ('CC8.1', 'Changes are authorised, designed, tested, approved and implemented', 'Measured: open findings past their remediation SLA; failing Prowler checks.', 'automatic'),
    ('CC9.1', 'Risks from business disruption are identified and mitigated', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('CC9.2', 'Risks from vendors and business partners are assessed and managed', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('A1.1', 'Processing capacity is managed and monitored', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('A1.2', 'Environmental protection, backup and recovery infrastructure is managed', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('A1.3', 'Recovery plan procedures are tested', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('C1.1', 'Confidential information is identified and protected', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('C1.2', 'Confidential information is disposed of as required', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('PI1.1', 'Processing objectives and data definitions are specified and communicated', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('PI1.2', 'System inputs are complete and accurate', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('PI1.3', 'Processing is complete, accurate and timely', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('PI1.4', 'Outputs are complete, accurate and delivered as intended', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('PI1.5', 'Stored inputs, items in process and outputs are complete and protected', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P1.1', 'Notice about privacy practices is provided to data subjects', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P2.1', 'Choices about personal information are communicated and consent obtained', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P3.1', 'Personal information is collected only for the stated objectives', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P3.2', 'Explicit consent is obtained where collection requires it', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P4.1', 'Use of personal information is limited to the stated objectives', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P4.2', 'Personal information is retained only as long as required', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P4.3', 'Personal information is disposed of securely', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P5.1', 'Data subjects can access their personal information', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P5.2', 'Personal information is corrected or amended on request', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P6.1', 'Disclosure to third parties happens only with consent', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P6.2', 'Authorised disclosures are recorded', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P6.3', 'Unauthorised disclosures are recorded', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P6.4', 'Third parties commit to protect personal information', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P6.5', 'Third parties report unauthorised disclosures', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P6.6', 'Affected parties are notified of breaches', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P6.7', 'Data subjects can obtain an account of disclosures', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P7.1', 'Personal information is accurate, complete and relevant', 'Not measurable by a scan: attest how it is met.', 'manual'),
    ('P8.1', 'Privacy inquiries, complaints and disputes are handled', 'Not measurable by a scan: attest how it is met.', 'manual')
) AS v(code, title, description, assessment)
WHERE fw.key = 'soc2';

-- By weakness class (CWE): tool-agnostic.
INSERT INTO control_mappings (control_id, match_type, cwe)
SELECT c.id, 'cwe', v.cwe
FROM controls c
JOIN frameworks fw ON fw.id = c.framework_id AND fw.key = 'soc2'
JOIN (VALUES
    ('CC6.1', 256), ('CC6.1', 257), ('CC6.1', 259), ('CC6.1', 260), ('CC6.1', 287), ('CC6.1', 288), ('CC6.1', 290), ('CC6.1', 306),
    ('CC6.1', 307), ('CC6.1', 308), ('CC6.1', 311), ('CC6.1', 312), ('CC6.1', 313), ('CC6.1', 316), ('CC6.1', 320), ('CC6.1', 321),
    ('CC6.1', 326), ('CC6.1', 327), ('CC6.1', 328), ('CC6.1', 384), ('CC6.1', 521), ('CC6.1', 522), ('CC6.1', 613), ('CC6.1', 620),
    ('CC6.1', 640), ('CC6.1', 798), ('CC6.1', 916),
    ('CC6.3', 22), ('CC6.3', 250), ('CC6.3', 269), ('CC6.3', 276), ('CC6.3', 284), ('CC6.3', 285), ('CC6.3', 639), ('CC6.3', 732),
    ('CC6.3', 862), ('CC6.3', 863),
    ('CC6.6', 918),
    ('CC6.7', 200), ('CC6.7', 201), ('CC6.7', 209), ('CC6.7', 215), ('CC6.7', 295), ('CC6.7', 297), ('CC6.7', 319), ('CC6.7', 326),
    ('CC6.7', 327), ('CC6.7', 359), ('CC6.7', 497), ('CC6.7', 532), ('CC6.7', 538), ('CC6.7', 548), ('CC6.7', 598), ('CC6.7', 615),
    ('CC6.7', 757),
    ('CC6.8', 353), ('CC6.8', 494), ('CC6.8', 506), ('CC6.8', 829), ('CC6.8', 912),
    ('CC7.1', 16), ('CC7.1', 489), ('CC7.1', 614), ('CC7.1', 942), ('CC7.1', 1004), ('CC7.1', 1188), ('CC7.1', 1392), ('CC7.1', 1393),
    ('CC7.2', 117), ('CC7.2', 223), ('CC7.2', 778)
) AS v(code, cwe) ON v.code = c.code;

-- By scanner rule: curated Checkov and Trivy (AVD) misconfiguration checks.
INSERT INTO control_mappings (control_id, match_type, scanner, rule_id)
SELECT c.id, 'rule', v.scanner, v.rule_id
FROM controls c
JOIN frameworks fw ON fw.id = c.framework_id AND fw.key = 'soc2'
JOIN (VALUES
    ('CC6.1', 'checkov', 'CKV_AWS_3'), ('CC6.1', 'checkov', 'CKV_AWS_8'), ('CC6.1', 'checkov', 'CKV_AWS_16'),
    ('CC6.1', 'checkov', 'CKV_AWS_19'), ('CC6.1', 'checkov', 'CKV_AWS_26'), ('CC6.1', 'checkov', 'CKV_AWS_27'),
    ('CC6.1', 'checkov', 'CKV_AWS_58'), ('CC6.1', 'checkov', 'CKV_AWS_64'), ('CC6.1', 'trivy', 'AVD-AWS-0026'),
    ('CC6.1', 'trivy', 'AVD-AWS-0039'), ('CC6.1', 'trivy', 'AVD-AWS-0079'), ('CC6.1', 'trivy', 'AVD-AWS-0080'),
    ('CC6.1', 'trivy', 'AVD-AWS-0088'), ('CC6.1', 'trivy', 'AVD-AWS-0131'), ('CC6.1', 'trivy', 'AVD-KCV-0030'),
    ('CC6.1', 'checkov', 'CKV_AWS_7'), ('CC6.1', 'checkov', 'CKV_AWS_33'), ('CC6.1', 'checkov', 'CKV_AWS_149'),
    ('CC6.1', 'trivy', 'AVD-AWS-0015'), ('CC6.1', 'trivy', 'AVD-AWS-0027'), ('CC6.1', 'trivy', 'AVD-AWS-0132'),
    ('CC6.1', 'checkov', 'CKV_AWS_17'), ('CC6.1', 'checkov', 'CKV_AWS_20'), ('CC6.1', 'checkov', 'CKV_AWS_53'),
    ('CC6.1', 'checkov', 'CKV_AWS_54'), ('CC6.1', 'checkov', 'CKV_AWS_55'), ('CC6.1', 'checkov', 'CKV_AWS_56'),
    ('CC6.1', 'trivy', 'AVD-AWS-0086'), ('CC6.1', 'trivy', 'AVD-AWS-0087'), ('CC6.1', 'trivy', 'AVD-AWS-0091'),
    ('CC6.1', 'trivy', 'AVD-AWS-0092'), ('CC6.1', 'trivy', 'AVD-AWS-0093'), ('CC6.1', 'trivy', 'AVD-AWS-0094'),
    ('CC6.1', 'trivy', 'AVD-AWS-0180'), ('CC6.1', 'checkov', 'CKV_AWS_41'), ('CC6.1', 'checkov', 'CKV_AWS_45'),
    ('CC6.1', 'checkov', 'CKV_AWS_46'), ('CC6.1', 'checkov', 'CKV_K8S_35'), ('CC6.1', 'trivy', 'AVD-KSV-0109'),
    ('CC6.1', 'checkov', 'CKV_AWS_10'), ('CC6.1', 'checkov', 'CKV_AWS_11'), ('CC6.1', 'checkov', 'CKV_AWS_12'),
    ('CC6.1', 'checkov', 'CKV_AWS_14'), ('CC6.1', 'checkov', 'CKV_AWS_15'), ('CC6.1', 'checkov', 'CKV_AWS_13'),
    ('CC6.1', 'checkov', 'CKV_AWS_9'),
    ('CC6.3', 'checkov', 'CKV_AWS_1'), ('CC6.3', 'checkov', 'CKV_AWS_49'), ('CC6.3', 'checkov', 'CKV_AWS_62'),
    ('CC6.3', 'checkov', 'CKV_AWS_109'), ('CC6.3', 'checkov', 'CKV_AWS_110'), ('CC6.3', 'checkov', 'CKV_AWS_111'),
    ('CC6.3', 'checkov', 'CKV_K8S_16'), ('CC6.3', 'checkov', 'CKV_K8S_17'), ('CC6.3', 'checkov', 'CKV_K8S_18'),
    ('CC6.3', 'checkov', 'CKV_K8S_19'), ('CC6.3', 'checkov', 'CKV_K8S_20'), ('CC6.3', 'checkov', 'CKV_K8S_23'),
    ('CC6.3', 'checkov', 'CKV_K8S_39'), ('CC6.3', 'trivy', 'AVD-KSV-0001'), ('CC6.3', 'trivy', 'AVD-KSV-0005'),
    ('CC6.3', 'trivy', 'AVD-KSV-0008'), ('CC6.3', 'trivy', 'AVD-KSV-0009'), ('CC6.3', 'trivy', 'AVD-KSV-0010'),
    ('CC6.3', 'trivy', 'AVD-KSV-0012'), ('CC6.3', 'trivy', 'AVD-KSV-0017'), ('CC6.3', 'trivy', 'AVD-KSV-0041'),
    ('CC6.3', 'trivy', 'AVD-KSV-0046'), ('CC6.3', 'trivy', 'AVD-KSV-0050'),
    ('CC6.6', 'checkov', 'CKV_AWS_24'), ('CC6.6', 'checkov', 'CKV_AWS_25'), ('CC6.6', 'checkov', 'CKV_AWS_38'),
    ('CC6.6', 'checkov', 'CKV_AWS_39'), ('CC6.6', 'checkov', 'CKV_AWS_88'), ('CC6.6', 'checkov', 'CKV_AWS_130'),
    ('CC6.6', 'checkov', 'CKV_AWS_260'), ('CC6.6', 'trivy', 'AVD-AWS-0009'), ('CC6.6', 'trivy', 'AVD-AWS-0040'),
    ('CC6.6', 'trivy', 'AVD-AWS-0041'), ('CC6.6', 'trivy', 'AVD-AWS-0104'), ('CC6.6', 'trivy', 'AVD-AWS-0105'),
    ('CC6.6', 'trivy', 'AVD-AWS-0107'), ('CC6.6', 'trivy', 'AVD-AWS-0164'), ('CC6.6', 'trivy', 'AVD-KSV-0038'),
    ('CC6.6', 'trivy', 'AVD-KUBE-0001'), ('CC6.6', 'trivy', 'AVD-KUBE-0002'),
    ('CC6.7', 'checkov', 'CKV_AWS_2'), ('CC6.7', 'checkov', 'CKV_AWS_34'), ('CC6.7', 'checkov', 'CKV_AWS_103'),
    ('CC6.7', 'trivy', 'AVD-AWS-0012'), ('CC6.7', 'trivy', 'AVD-AWS-0013'), ('CC6.7', 'trivy', 'AVD-AWS-0047'),
    ('CC6.7', 'trivy', 'AVD-AWS-0054'), ('CC6.7', 'trivy', 'AVD-KCV-0026'), ('CC6.7', 'trivy', 'AVD-KCV-0027'),
    ('CC7.1', 'checkov', 'CKV_AWS_79'), ('CC7.1', 'checkov', 'CKV_K8S_22'), ('CC7.1', 'checkov', 'CKV_K8S_28'),
    ('CC7.1', 'checkov', 'CKV_K8S_31'), ('CC7.1', 'checkov', 'CKV_K8S_38'), ('CC7.1', 'trivy', 'AVD-AWS-0028'),
    ('CC7.1', 'trivy', 'AVD-AWS-0130'), ('CC7.1', 'trivy', 'AVD-KSV-0014'), ('CC7.1', 'trivy', 'AVD-KSV-0036'),
    ('CC7.2', 'checkov', 'CKV_AWS_18'), ('CC7.2', 'checkov', 'CKV_AWS_37'), ('CC7.2', 'checkov', 'CKV_AWS_67'),
    ('CC7.2', 'checkov', 'CKV_AWS_76'), ('CC7.2', 'checkov', 'CKV_AWS_84'), ('CC7.2', 'checkov', 'CKV_AWS_86'),
    ('CC7.2', 'checkov', 'CKV_AWS_91'), ('CC7.2', 'checkov', 'CKV_AWS_92'), ('CC7.2', 'trivy', 'AVD-AWS-0010'),
    ('CC7.2', 'trivy', 'AVD-AWS-0014'), ('CC7.2', 'trivy', 'AVD-AWS-0038'), ('CC7.2', 'trivy', 'AVD-AWS-0089'),
    ('CC7.2', 'trivy', 'AVD-AWS-0178'), ('CC7.2', 'trivy', 'AVD-KCV-0019'), ('CC7.2', 'checkov', 'CKV_AWS_35'),
    ('CC7.2', 'checkov', 'CKV_AWS_36'), ('CC7.2', 'checkov', 'CKV_AWS_158'), ('CC7.2', 'trivy', 'AVD-AWS-0016'),
    ('CC7.2', 'trivy', 'AVD-AWS-0161')
) AS v(code, scanner, rule_id) ON v.code = c.code;

-- By Prowler check, as Prowler's own compliance packs map them
-- (prowler/compliance/{aws,azure,gcp,kubernetes}, commit d695be2).
INSERT INTO control_mappings (control_id, match_type, scanner, rule_id)
SELECT c.id, 'rule', v.scanner, v.rule_id
FROM controls c
JOIN frameworks fw ON fw.id = c.framework_id AND fw.key = 'soc2'
JOIN (VALUES
    ('CC6.1', 'prowler', 'aks_clusters_public_access_disabled'), ('CC6.1', 'prowler', 'app_function_not_publicly_accessible'), ('CC6.1', 'prowler', 'cloudstorage_bucket_public_access'),
    ('CC6.1', 'prowler', 'containerregistry_not_publicly_accessible'), ('CC6.1', 'prowler', 'entra_app_registration_credential_not_expired'), ('CC6.1', 'prowler', 'kms_key_enclave_attestation_not_enforced'),
    ('CC6.1', 'prowler', 'network_public_ip_shodan'), ('CC6.1', 'prowler', 's3_bucket_public_access'), ('CC6.1', 'prowler', 'storage_blob_public_access_level_is_disabled'),
    ('CC6.2', 'prowler', 'cloudsql_instance_public_access'), ('CC6.2', 'prowler', 'mysql_flexible_server_minimum_tls_version_12'), ('CC6.2', 'prowler', 'mysql_flexible_server_ssl_connection_enabled'),
    ('CC6.2', 'prowler', 'postgresql_flexible_server_enforce_ssl_enabled'), ('CC6.2', 'prowler', 'rds_instance_no_public_access'), ('CC6.2', 'prowler', 'sqlserver_recommended_minimal_tls_version'),
    ('CC6.2', 'prowler', 'sqlserver_tde_encrypted_with_cmk'), ('CC6.2', 'prowler', 'sqlserver_tde_encryption_enabled'), ('CC6.2', 'prowler', 'sqlserver_unrestricted_inbound_access'),
    ('CC6.2', 'prowler', 'storage_secure_transfer_required_is_enabled'),
    ('CC6.3', 'prowler', 'bedrock_full_access_policy_attached'), ('CC6.3', 'prowler', 'entra_non_privileged_user_has_mfa'), ('CC6.3', 'prowler', 'entra_privileged_user_has_mfa'),
    ('CC6.3', 'prowler', 'entra_user_with_vm_access_has_mfa'), ('CC6.3', 'prowler', 'iam_account_access_approval_enabled'), ('CC6.3', 'prowler', 'iam_aws_attached_policy_no_administrative_privileges'),
    ('CC6.3', 'prowler', 'iam_customer_attached_policy_no_administrative_privileges'), ('CC6.3', 'prowler', 'iam_inline_policy_no_administrative_privileges'), ('CC6.3', 'prowler', 'iam_inline_policy_no_wildcard_marketplace_subscribe'),
    ('CC6.3', 'prowler', 'iam_policy_no_wildcard_marketplace_subscribe'), ('CC6.3', 'prowler', 'iam_role_kms_enforce_separation_of_duties'), ('CC6.3', 'prowler', 'iam_role_sa_enforce_separation_of_duties'),
    ('CC6.3', 'prowler', 'iam_sa_no_administrative_privileges'), ('CC6.3', 'prowler', 'iam_sa_user_managed_key_unused'), ('CC6.3', 'prowler', 'kms_key_enclave_attestation_bypassable_path'),
    ('CC6.3', 'prowler', 'kms_key_enclave_attestation_no_deployment_binding'),
    ('CC6.6', 'prowler', 'app_minimum_tls_version_12'), ('CC6.6', 'prowler', 'compute_firewall_rdp_access_from_the_internet_allowed'), ('CC6.6', 'prowler', 'compute_firewall_ssh_access_from_the_internet_allowed'),
    ('CC6.6', 'prowler', 'compute_instance_block_project_wide_ssh_keys_disabled'), ('CC6.6', 'prowler', 'compute_instance_ip_forwarding_is_enabled'), ('CC6.6', 'prowler', 'compute_instance_public_ip'),
    ('CC6.6', 'prowler', 'compute_instance_serial_ports_in_use'), ('CC6.6', 'prowler', 'compute_network_dns_logging_enabled'), ('CC6.6', 'prowler', 'compute_public_address_shodan'),
    ('CC6.6', 'prowler', 'ec2_ami_public'), ('CC6.6', 'prowler', 'ec2_confidential_workload_host_public_ip'), ('CC6.6', 'prowler', 'ec2_confidential_workload_host_unrestricted_ingress'),
    ('CC6.6', 'prowler', 'ec2_confidential_workload_host_vsock_proxy_exposed'), ('CC6.6', 'prowler', 'ec2_ebs_public_snapshot'), ('CC6.6', 'prowler', 'ec2_ebs_snapshot_account_block_public_access'),
    ('CC6.6', 'prowler', 'ec2_instance_port_cassandra_exposed_to_internet'), ('CC6.6', 'prowler', 'ec2_instance_port_cifs_exposed_to_internet'), ('CC6.6', 'prowler', 'ec2_instance_port_elasticsearch_kibana_exposed_to_internet'),
    ('CC6.6', 'prowler', 'ec2_instance_port_ftp_exposed_to_internet'), ('CC6.6', 'prowler', 'ec2_instance_port_kafka_exposed_to_internet'), ('CC6.6', 'prowler', 'ec2_instance_port_kerberos_exposed_to_internet'),
    ('CC6.6', 'prowler', 'ec2_instance_port_ldap_exposed_to_internet'), ('CC6.6', 'prowler', 'ec2_instance_port_memcached_exposed_to_internet'), ('CC6.6', 'prowler', 'ec2_instance_port_mongodb_exposed_to_internet'),
    ('CC6.6', 'prowler', 'ec2_instance_port_mysql_exposed_to_internet'), ('CC6.6', 'prowler', 'ec2_instance_port_oracle_exposed_to_internet'), ('CC6.6', 'prowler', 'ec2_instance_port_postgresql_exposed_to_internet'),
    ('CC6.6', 'prowler', 'ec2_instance_port_rdp_exposed_to_internet'), ('CC6.6', 'prowler', 'ec2_instance_port_redis_exposed_to_internet'), ('CC6.6', 'prowler', 'ec2_instance_port_sqlserver_exposed_to_internet'),
    ('CC6.6', 'prowler', 'ec2_instance_port_ssh_exposed_to_internet'), ('CC6.6', 'prowler', 'ec2_instance_port_telnet_exposed_to_internet'), ('CC6.6', 'prowler', 'ec2_instance_public_ip'),
    ('CC6.6', 'prowler', 'ec2_launch_template_no_public_ip'), ('CC6.6', 'prowler', 'ec2_networkacl_allow_ingress_any_port'), ('CC6.6', 'prowler', 'ec2_networkacl_allow_ingress_tcp_port_22'),
    ('CC6.6', 'prowler', 'ec2_networkacl_allow_ingress_tcp_port_3389'), ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_all_ports'), ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_any_port'),
    ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports'), ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22'), ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389'),
    ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_cassandra_7199_9160_8888'), ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_elasticsearch_kibana_9200_9300_5601'), ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_ftp_20_21'),
    ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_kafka_9092'), ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_memcached_11211'), ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mongodb_27017_27018'),
    ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_mysql_3306'), ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_oracle_1521_2483'), ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_postgres_5432'),
    ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_redis_6379'), ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_sql_server_1433_1434'), ('CC6.6', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_telnet_23'),
    ('CC6.6', 'prowler', 'ec2_securitygroup_allow_wide_open_public_ipv4'), ('CC6.6', 'prowler', 'mysql_flexible_server_minimum_tls_version_12'), ('CC6.6', 'prowler', 'mysql_flexible_server_ssl_connection_enabled'),
    ('CC6.6', 'prowler', 'network_http_internet_access_restricted'), ('CC6.6', 'prowler', 'network_rdp_internet_access_restricted'), ('CC6.6', 'prowler', 'network_ssh_internet_access_restricted'),
    ('CC6.6', 'prowler', 'network_subnet_nsg_associated'), ('CC6.6', 'prowler', 'network_udp_internet_access_restricted'), ('CC6.6', 'prowler', 'postgresql_flexible_server_enforce_ssl_enabled'),
    ('CC6.6', 'prowler', 'sqlserver_recommended_minimal_tls_version'), ('CC6.6', 'prowler', 'storage_ensure_minimum_tls_version_12'), ('CC6.6', 'prowler', 'vpc_subnet_no_public_ip_by_default'),
    ('CC6.6', 'prowler', 'vpc_subnet_separate_private_public'),
    ('CC6.7', 'prowler', 'acm_certificates_expiration_check'), ('CC6.7', 'prowler', 'app_minimum_tls_version_12'), ('CC6.7', 'prowler', 'cloudsql_instance_ssl_connections'),
    ('CC6.7', 'prowler', 'compute_firewall_rdp_access_from_the_internet_allowed'), ('CC6.7', 'prowler', 'compute_firewall_ssh_access_from_the_internet_allowed'), ('CC6.7', 'prowler', 'dms_endpoint_redis_in_transit_encryption_enabled'),
    ('CC6.7', 'prowler', 'dns_dnssec_disabled'), ('CC6.7', 'prowler', 'dns_rsasha1_in_use_to_key_sign_in_dnssec'), ('CC6.7', 'prowler', 'dns_rsasha1_in_use_to_zone_sign_in_dnssec'),
    ('CC6.7', 'prowler', 'dynamodb_accelerator_cluster_in_transit_encryption_enabled'), ('CC6.7', 'prowler', 'ec2_transitgateway_auto_accept_vpc_attachments'), ('CC6.7', 'prowler', 'elasticache_redis_cluster_in_transit_encryption_enabled'),
    ('CC6.7', 'prowler', 'kafka_cluster_in_transit_encryption_enabled'), ('CC6.7', 'prowler', 'kafka_connector_in_transit_encryption_enabled'), ('CC6.7', 'prowler', 'monitor_storage_account_with_activity_logs_cmk_encrypted'),
    ('CC6.7', 'prowler', 'redshift_cluster_in_transit_encryption_enabled'), ('CC6.7', 'prowler', 'sqlserver_tde_encrypted_with_cmk'), ('CC6.7', 'prowler', 'sqlserver_tde_encryption_enabled'),
    ('CC6.7', 'prowler', 'storage_ensure_encryption_with_customer_managed_keys'), ('CC6.7', 'prowler', 'storage_infrastructure_encryption_is_enabled'), ('CC6.7', 'prowler', 'storage_secure_transfer_required_is_enabled'),
    ('CC6.7', 'prowler', 'transfer_server_in_transit_encryption_enabled'), ('CC6.7', 'prowler', 'vm_ensure_attached_disks_encrypted_with_cmk'), ('CC6.7', 'prowler', 'vm_ensure_unattached_disks_encrypted_with_cmk'),
    ('CC6.8', 'prowler', 'defender_additional_email_configured_with_a_security_contact'), ('CC6.8', 'prowler', 'defender_assessments_vm_endpoint_protection_installed'), ('CC6.8', 'prowler', 'defender_auto_provisioning_log_analytics_agent_vms_on'),
    ('CC6.8', 'prowler', 'defender_auto_provisioning_vulnerabilty_assessments_machines_on'), ('CC6.8', 'prowler', 'defender_container_images_resolved_vulnerabilities'), ('CC6.8', 'prowler', 'defender_container_images_scan_enabled'),
    ('CC6.8', 'prowler', 'defender_ensure_defender_for_app_services_is_on'), ('CC6.8', 'prowler', 'defender_ensure_defender_for_arm_is_on'), ('CC6.8', 'prowler', 'defender_ensure_defender_for_azure_sql_databases_is_on'),
    ('CC6.8', 'prowler', 'defender_ensure_defender_for_containers_is_on'), ('CC6.8', 'prowler', 'defender_ensure_defender_for_cosmosdb_is_on'), ('CC6.8', 'prowler', 'defender_ensure_defender_for_databases_is_on'),
    ('CC6.8', 'prowler', 'defender_ensure_defender_for_dns_is_on'), ('CC6.8', 'prowler', 'defender_ensure_defender_for_keyvault_is_on'), ('CC6.8', 'prowler', 'defender_ensure_defender_for_os_relational_databases_is_on'),
    ('CC6.8', 'prowler', 'defender_ensure_defender_for_server_is_on'), ('CC6.8', 'prowler', 'defender_ensure_defender_for_sql_servers_is_on'), ('CC6.8', 'prowler', 'defender_ensure_defender_for_storage_is_on'),
    ('CC6.8', 'prowler', 'defender_ensure_iot_hub_defender_is_on'), ('CC6.8', 'prowler', 'defender_ensure_mcas_is_enabled'), ('CC6.8', 'prowler', 'defender_ensure_notify_alerts_severity_is_high'),
    ('CC6.8', 'prowler', 'defender_ensure_notify_emails_to_owners'), ('CC6.8', 'prowler', 'defender_ensure_system_updates_are_applied'), ('CC6.8', 'prowler', 'defender_ensure_wdatp_is_enabled'),
    ('CC6.8', 'prowler', 'guardduty_is_enabled'), ('CC6.8', 'prowler', 'iam_cloud_asset_inventory_enabled'), ('CC6.8', 'prowler', 'securityhub_enabled'),
    ('CC6.8', 'prowler', 'sqlserver_microsoft_defender_enabled'),
    ('CC7.1', 'prowler', 'defender_additional_email_configured_with_a_security_contact'), ('CC7.1', 'prowler', 'defender_assessments_vm_endpoint_protection_installed'), ('CC7.1', 'prowler', 'defender_auto_provisioning_log_analytics_agent_vms_on'),
    ('CC7.1', 'prowler', 'defender_auto_provisioning_vulnerabilty_assessments_machines_on'), ('CC7.1', 'prowler', 'defender_container_images_resolved_vulnerabilities'), ('CC7.1', 'prowler', 'defender_container_images_scan_enabled'),
    ('CC7.1', 'prowler', 'defender_ensure_defender_for_app_services_is_on'), ('CC7.1', 'prowler', 'defender_ensure_defender_for_arm_is_on'), ('CC7.1', 'prowler', 'defender_ensure_defender_for_azure_sql_databases_is_on'),
    ('CC7.1', 'prowler', 'defender_ensure_defender_for_containers_is_on'), ('CC7.1', 'prowler', 'defender_ensure_defender_for_cosmosdb_is_on'), ('CC7.1', 'prowler', 'defender_ensure_defender_for_databases_is_on'),
    ('CC7.1', 'prowler', 'defender_ensure_defender_for_dns_is_on'), ('CC7.1', 'prowler', 'defender_ensure_defender_for_keyvault_is_on'), ('CC7.1', 'prowler', 'defender_ensure_defender_for_os_relational_databases_is_on'),
    ('CC7.1', 'prowler', 'defender_ensure_defender_for_server_is_on'), ('CC7.1', 'prowler', 'defender_ensure_defender_for_sql_servers_is_on'), ('CC7.1', 'prowler', 'defender_ensure_defender_for_storage_is_on'),
    ('CC7.1', 'prowler', 'defender_ensure_iot_hub_defender_is_on'), ('CC7.1', 'prowler', 'defender_ensure_mcas_is_enabled'), ('CC7.1', 'prowler', 'defender_ensure_notify_alerts_severity_is_high'),
    ('CC7.1', 'prowler', 'defender_ensure_notify_emails_to_owners'), ('CC7.1', 'prowler', 'defender_ensure_system_updates_are_applied'), ('CC7.1', 'prowler', 'defender_ensure_wdatp_is_enabled'),
    ('CC7.1', 'prowler', 'ec2_instance_managed_by_ssm'), ('CC7.1', 'prowler', 'gemini_api_disabled'), ('CC7.1', 'prowler', 'guardduty_is_enabled'),
    ('CC7.1', 'prowler', 'iam_cloud_asset_inventory_enabled'), ('CC7.1', 'prowler', 'kms_key_enclave_attestation_pcr_mismatch'), ('CC7.1', 'prowler', 'securityhub_enabled'),
    ('CC7.1', 'prowler', 'sqlserver_microsoft_defender_enabled'), ('CC7.1', 'prowler', 'ssm_managed_compliant_patching'),
    ('CC7.2', 'prowler', 'apigateway_restapi_logging_enabled'), ('CC7.2', 'prowler', 'app_http_logs_enabled'), ('CC7.2', 'prowler', 'cloudsql_instance_postgres_log_connections_flag'),
    ('CC7.2', 'prowler', 'cloudsql_instance_postgres_log_disconnections_flag'), ('CC7.2', 'prowler', 'cloudsql_instance_postgres_log_error_verbosity_flag'), ('CC7.2', 'prowler', 'cloudsql_instance_postgres_log_min_duration_statement_flag'),
    ('CC7.2', 'prowler', 'cloudsql_instance_postgres_log_min_error_statement_flag'), ('CC7.2', 'prowler', 'cloudsql_instance_postgres_log_min_messages_flag'), ('CC7.2', 'prowler', 'cloudsql_instance_postgres_log_statement_flag'),
    ('CC7.2', 'prowler', 'cloudstorage_bucket_log_retention_policy_lock'), ('CC7.2', 'prowler', 'cloudtrail_bedrock_logging_enabled'), ('CC7.2', 'prowler', 'cloudtrail_cloudwatch_logging_enabled'),
    ('CC7.2', 'prowler', 'cloudtrail_multi_region_enabled'), ('CC7.2', 'prowler', 'cloudtrail_s3_dataevents_read_enabled'), ('CC7.2', 'prowler', 'cloudtrail_s3_dataevents_write_enabled'),
    ('CC7.2', 'prowler', 'cloudwatch_changes_to_network_acls_alarm_configured'), ('CC7.2', 'prowler', 'cloudwatch_changes_to_network_gateways_alarm_configured'), ('CC7.2', 'prowler', 'cloudwatch_changes_to_network_route_tables_alarm_configured'),
    ('CC7.2', 'prowler', 'cloudwatch_changes_to_vpcs_alarm_configured'), ('CC7.2', 'prowler', 'cloudwatch_log_group_retention_policy_specific_days_enabled'), ('CC7.2', 'prowler', 'compute_loadbalancer_logging_enabled'),
    ('CC7.2', 'prowler', 'compute_network_dns_logging_enabled'), ('CC7.2', 'prowler', 'compute_project_os_login_enabled'), ('CC7.2', 'prowler', 'compute_subnet_flow_logs_enabled'),
    ('CC7.2', 'prowler', 'defender_auto_provisioning_log_analytics_agent_vms_on'), ('CC7.2', 'prowler', 'ec2_confidential_workload_host_imdsv2_not_enforced'), ('CC7.2', 'prowler', 'ec2_instance_imdsv2_enabled'),
    ('CC7.2', 'prowler', 'ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22'), ('CC7.2', 'prowler', 'elb_logging_enabled'), ('CC7.2', 'prowler', 'elbv2_logging_enabled'),
    ('CC7.2', 'prowler', 'guardduty_is_enabled'), ('CC7.2', 'prowler', 'iam_audit_logs_enabled'), ('CC7.2', 'prowler', 'keyvault_logging_enabled'),
    ('CC7.2', 'prowler', 'kms_key_enclave_attestation_unknown_image'), ('CC7.2', 'prowler', 'kms_key_enclave_debug_attestation_detected'), ('CC7.2', 'prowler', 'logging_log_metric_filter_and_alert_for_audit_configuration_changes_enabled'),
    ('CC7.2', 'prowler', 'logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled'), ('CC7.2', 'prowler', 'logging_log_metric_filter_and_alert_for_custom_role_changes_enabled'), ('CC7.2', 'prowler', 'logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled'),
    ('CC7.2', 'prowler', 'logging_log_metric_filter_and_alert_for_sql_instance_configuration_changes_enabled'), ('CC7.2', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_firewall_rule_changes_enabled'), ('CC7.2', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_network_changes_enabled'),
    ('CC7.2', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled'), ('CC7.2', 'prowler', 'logging_sink_created'), ('CC7.2', 'prowler', 'monitor_storage_account_with_activity_logs_cmk_encrypted'),
    ('CC7.2', 'prowler', 'monitor_storage_account_with_activity_logs_is_private'), ('CC7.2', 'prowler', 'mysql_flexible_server_audit_log_connection_activated'), ('CC7.2', 'prowler', 'mysql_flexible_server_audit_log_enabled'),
    ('CC7.2', 'prowler', 'network_flow_log_captured_sent'), ('CC7.2', 'prowler', 'network_flow_log_more_than_90_days'), ('CC7.2', 'prowler', 'postgresql_flexible_server_log_checkpoints_on'),
    ('CC7.2', 'prowler', 'postgresql_flexible_server_log_connections_on'), ('CC7.2', 'prowler', 'postgresql_flexible_server_log_disconnections_on'), ('CC7.2', 'prowler', 'postgresql_flexible_server_log_retention_days_greater_3'),
    ('CC7.2', 'prowler', 'rds_instance_integration_cloudwatch_logs'), ('CC7.2', 'prowler', 'redshift_cluster_audit_logging'), ('CC7.2', 'prowler', 's3_bucket_server_access_logging_enabled'),
    ('CC7.2', 'prowler', 'securityhub_enabled'), ('CC7.2', 'prowler', 'vpc_flow_logs_enabled'),
    ('CC7.3', 'prowler', 'apigateway_restapi_logging_enabled'), ('CC7.3', 'prowler', 'app_http_logs_enabled'), ('CC7.3', 'prowler', 'cloudsql_instance_postgres_log_connections_flag'),
    ('CC7.3', 'prowler', 'cloudsql_instance_postgres_log_disconnections_flag'), ('CC7.3', 'prowler', 'cloudsql_instance_postgres_log_error_verbosity_flag'), ('CC7.3', 'prowler', 'cloudsql_instance_postgres_log_min_duration_statement_flag'),
    ('CC7.3', 'prowler', 'cloudsql_instance_postgres_log_min_error_statement_flag'), ('CC7.3', 'prowler', 'cloudsql_instance_postgres_log_min_messages_flag'), ('CC7.3', 'prowler', 'cloudsql_instance_postgres_log_statement_flag'),
    ('CC7.3', 'prowler', 'cloudstorage_bucket_log_retention_policy_lock'), ('CC7.3', 'prowler', 'cloudtrail_cloudwatch_logging_enabled'), ('CC7.3', 'prowler', 'cloudtrail_log_file_validation_enabled'),
    ('CC7.3', 'prowler', 'cloudwatch_changes_to_network_acls_alarm_configured'), ('CC7.3', 'prowler', 'cloudwatch_changes_to_network_gateways_alarm_configured'), ('CC7.3', 'prowler', 'cloudwatch_changes_to_network_route_tables_alarm_configured'),
    ('CC7.3', 'prowler', 'cloudwatch_changes_to_vpcs_alarm_configured'), ('CC7.3', 'prowler', 'cloudwatch_log_group_kms_encryption_enabled'), ('CC7.3', 'prowler', 'cloudwatch_log_group_retention_policy_specific_days_enabled'),
    ('CC7.3', 'prowler', 'compute_loadbalancer_logging_enabled'), ('CC7.3', 'prowler', 'compute_network_dns_logging_enabled'), ('CC7.3', 'prowler', 'compute_project_os_login_enabled'),
    ('CC7.3', 'prowler', 'compute_subnet_flow_logs_enabled'), ('CC7.3', 'prowler', 'defender_auto_provisioning_log_analytics_agent_vms_on'), ('CC7.3', 'prowler', 'defender_ensure_notify_alerts_severity_is_high'),
    ('CC7.3', 'prowler', 'elb_logging_enabled'), ('CC7.3', 'prowler', 'elbv2_logging_enabled'), ('CC7.3', 'prowler', 'guardduty_is_enabled'),
    ('CC7.3', 'prowler', 'guardduty_no_high_severity_findings'), ('CC7.3', 'prowler', 'iam_audit_logs_enabled'), ('CC7.3', 'prowler', 'iam_cloud_asset_inventory_enabled'),
    ('CC7.3', 'prowler', 'keyvault_logging_enabled'), ('CC7.3', 'prowler', 'logging_log_metric_filter_and_alert_for_audit_configuration_changes_enabled'), ('CC7.3', 'prowler', 'logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled'),
    ('CC7.3', 'prowler', 'logging_log_metric_filter_and_alert_for_custom_role_changes_enabled'), ('CC7.3', 'prowler', 'logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled'), ('CC7.3', 'prowler', 'logging_log_metric_filter_and_alert_for_sql_instance_configuration_changes_enabled'),
    ('CC7.3', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_firewall_rule_changes_enabled'), ('CC7.3', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_network_changes_enabled'), ('CC7.3', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled'),
    ('CC7.3', 'prowler', 'monitor_alert_create_policy_assignment'), ('CC7.3', 'prowler', 'monitor_alert_create_update_nsg'), ('CC7.3', 'prowler', 'monitor_alert_create_update_public_ip_address_rule'),
    ('CC7.3', 'prowler', 'monitor_alert_create_update_security_solution'), ('CC7.3', 'prowler', 'monitor_alert_create_update_sqlserver_fr'), ('CC7.3', 'prowler', 'monitor_alert_delete_nsg'),
    ('CC7.3', 'prowler', 'monitor_alert_delete_policy_assignment'), ('CC7.3', 'prowler', 'monitor_alert_delete_public_ip_address_rule'), ('CC7.3', 'prowler', 'monitor_alert_delete_security_solution'),
    ('CC7.3', 'prowler', 'monitor_alert_delete_sqlserver_fr'), ('CC7.3', 'prowler', 'monitor_storage_account_with_activity_logs_cmk_encrypted'), ('CC7.3', 'prowler', 'monitor_storage_account_with_activity_logs_is_private'),
    ('CC7.3', 'prowler', 'mysql_flexible_server_audit_log_connection_activated'), ('CC7.3', 'prowler', 'mysql_flexible_server_audit_log_enabled'), ('CC7.3', 'prowler', 'network_flow_log_captured_sent'),
    ('CC7.3', 'prowler', 'network_flow_log_more_than_90_days'), ('CC7.3', 'prowler', 'postgresql_flexible_server_log_checkpoints_on'), ('CC7.3', 'prowler', 'postgresql_flexible_server_log_connections_on'),
    ('CC7.3', 'prowler', 'postgresql_flexible_server_log_disconnections_on'), ('CC7.3', 'prowler', 'postgresql_flexible_server_log_retention_days_greater_3'), ('CC7.3', 'prowler', 'rds_instance_integration_cloudwatch_logs'),
    ('CC7.3', 'prowler', 's3_bucket_server_access_logging_enabled'), ('CC7.3', 'prowler', 'securityhub_enabled'), ('CC7.3', 'prowler', 'vpc_flow_logs_enabled'),
    ('CC7.4', 'prowler', 'cloudsql_instance_automated_backups'), ('CC7.4', 'prowler', 'cloudwatch_changes_to_network_acls_alarm_configured'), ('CC7.4', 'prowler', 'cloudwatch_changes_to_network_gateways_alarm_configured'),
    ('CC7.4', 'prowler', 'cloudwatch_changes_to_network_route_tables_alarm_configured'), ('CC7.4', 'prowler', 'cloudwatch_changes_to_vpcs_alarm_configured'), ('CC7.4', 'prowler', 'defender_ensure_notify_alerts_severity_is_high'),
    ('CC7.4', 'prowler', 'dynamodb_tables_pitr_enabled'), ('CC7.4', 'prowler', 'efs_have_backup_enabled'), ('CC7.4', 'prowler', 'guardduty_is_enabled'),
    ('CC7.4', 'prowler', 'guardduty_no_high_severity_findings'), ('CC7.4', 'prowler', 'logging_log_metric_filter_and_alert_for_audit_configuration_changes_enabled'), ('CC7.4', 'prowler', 'logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled'),
    ('CC7.4', 'prowler', 'logging_log_metric_filter_and_alert_for_custom_role_changes_enabled'), ('CC7.4', 'prowler', 'logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled'), ('CC7.4', 'prowler', 'logging_log_metric_filter_and_alert_for_sql_instance_configuration_changes_enabled'),
    ('CC7.4', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_firewall_rule_changes_enabled'), ('CC7.4', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_network_changes_enabled'), ('CC7.4', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled'),
    ('CC7.4', 'prowler', 'monitor_alert_create_policy_assignment'), ('CC7.4', 'prowler', 'monitor_alert_create_update_nsg'), ('CC7.4', 'prowler', 'monitor_alert_create_update_public_ip_address_rule'),
    ('CC7.4', 'prowler', 'monitor_alert_create_update_security_solution'), ('CC7.4', 'prowler', 'monitor_alert_create_update_sqlserver_fr'), ('CC7.4', 'prowler', 'monitor_alert_delete_nsg'),
    ('CC7.4', 'prowler', 'monitor_alert_delete_policy_assignment'), ('CC7.4', 'prowler', 'monitor_alert_delete_public_ip_address_rule'), ('CC7.4', 'prowler', 'monitor_alert_delete_security_solution'),
    ('CC7.4', 'prowler', 'monitor_alert_delete_sqlserver_fr'), ('CC7.4', 'prowler', 'rds_instance_backup_enabled'), ('CC7.4', 'prowler', 'redshift_cluster_automated_snapshot'),
    ('CC7.4', 'prowler', 's3_bucket_object_versioning'), ('CC7.4', 'prowler', 'securityhub_enabled'), ('CC7.4', 'prowler', 'storage_ensure_soft_delete_is_enabled'),
    ('CC7.4', 'prowler', 'vm_ensure_attached_disks_encrypted_with_cmk'), ('CC7.4', 'prowler', 'vm_ensure_unattached_disks_encrypted_with_cmk'),
    ('CC7.5', 'prowler', 'cloudsql_instance_automated_backups'), ('CC7.5', 'prowler', 'ec2_ebs_snapshots_encrypted'), ('CC7.5', 'prowler', 'ec2_ebs_volume_snapshots_exists'),
    ('CC7.5', 'prowler', 'neptune_cluster_copy_tags_to_snapshots'), ('CC7.5', 'prowler', 'neptune_cluster_snapshot_encrypted'), ('CC7.5', 'prowler', 'rds_instance_copy_tags_to_snapshots'),
    ('CC7.5', 'prowler', 'redshift_cluster_automated_snapshot'), ('CC7.5', 'prowler', 'storage_ensure_encryption_with_customer_managed_keys'), ('CC7.5', 'prowler', 'storage_infrastructure_encryption_is_enabled'),
    ('CC7.5', 'prowler', 'vm_ensure_attached_disks_encrypted_with_cmk'), ('CC7.5', 'prowler', 'vm_ensure_unattached_disks_encrypted_with_cmk'),
    ('CC8.1', 'prowler', 'config_recorder_all_regions_enabled'), ('CC8.1', 'prowler', 'iam_cloud_asset_inventory_enabled'), ('CC8.1', 'prowler', 'monitor_alert_create_policy_assignment'),
    ('CC8.1', 'prowler', 'monitor_alert_create_update_nsg'), ('CC8.1', 'prowler', 'monitor_alert_create_update_public_ip_address_rule'), ('CC8.1', 'prowler', 'monitor_alert_create_update_security_solution'),
    ('CC8.1', 'prowler', 'monitor_alert_create_update_sqlserver_fr'), ('CC8.1', 'prowler', 'monitor_alert_delete_nsg'), ('CC8.1', 'prowler', 'monitor_alert_delete_policy_assignment'),
    ('CC8.1', 'prowler', 'monitor_alert_delete_public_ip_address_rule'), ('CC8.1', 'prowler', 'monitor_alert_delete_security_solution'), ('CC8.1', 'prowler', 'monitor_alert_delete_sqlserver_fr'),
    ('CC8.1', 'prowler', 'monitor_diagnostic_setting_with_appropriate_categories'), ('CC8.1', 'prowler', 'monitor_diagnostic_settings_exists'), ('CC8.1', 'prowler', 'monitor_storage_account_with_activity_logs_cmk_encrypted')
) AS v(code, scanner, rule_id) ON v.code = c.code;

-- By finding category.
INSERT INTO control_mappings (control_id, match_type, category)
SELECT c.id, 'category', v.category
FROM controls c
JOIN frameworks fw ON fw.id = c.framework_id AND fw.key = 'soc2'
JOIN (VALUES
    ('CC6.1', 'secret')
) AS v(code, category) ON v.code = c.code;

-- By finding state (kev, sla) or project fact (sbom, vex).
INSERT INTO control_mappings (control_id, match_type)
SELECT c.id, v.match_type
FROM controls c
JOIN frameworks fw ON fw.id = c.framework_id AND fw.key = 'soc2'
JOIN (VALUES
    ('CC7.1', 'kev'), ('CC7.1', 'sbom'),
    ('CC8.1', 'sla')
) AS v(code, match_type) ON v.code = c.code;
