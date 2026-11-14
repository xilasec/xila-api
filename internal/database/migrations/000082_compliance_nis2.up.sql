-- NIS2 Directive (EU) 2022/2555, Article 21(2)(a)–(j) (framework nis2). EU law,
-- quoted in each description. Measured: (e) acquisition, development and
-- maintenance incl. vulnerability handling (KEV, SLA, secure-coding and
-- configuration CWE classes); (h) cryptography; (i) access control and asset
-- management (access CWE classes, SBOM); (j) multi-factor authentication. Prowler
-- checks come from Prowler's NIS2 packs (Implementing Regulation (EU) 2024/2690
-- sections, attributed to the Article 21(2) point each section implements; the
-- access-control section's MFA checks evidence (j), the rest (i)). (a)–(d), (f)
-- and (g) are manual.

INSERT INTO frameworks (key, name, version, description)
VALUES ('nis2', 'NIS2 Directive — Article 21(2)', '(EU) 2022/2555',
        'Cybersecurity risk-management measures of Article 21(2)(a)–(j) of Directive (EU) 2022/2555. Points (e) development and vulnerability handling, (h) cryptography, (i) access control and asset management and (j) multi-factor authentication are measured where findings evidence them; the rest are attested.');

INSERT INTO controls (framework_id, code, title, description, assessment)
SELECT fw.id, v.code, v.title, v.description, v.assessment
FROM frameworks fw
CROSS JOIN (VALUES
    ('21(2)(a)', 'Risk analysis and information system security policies', 'Article 21(2)(a): “policies on risk analysis and information system security”. Not measurable by a scan: attest how it is met.', 'manual'),
    ('21(2)(b)', 'Incident handling', 'Article 21(2)(b): “incident handling”. Not measurable by a scan: attest how it is met.', 'manual'),
    ('21(2)(c)', 'Business continuity and crisis management', 'Article 21(2)(c): “business continuity, such as backup management and disaster recovery, and crisis management”. Not measurable by a scan: attest how it is met.', 'manual'),
    ('21(2)(d)', 'Supply chain security', 'Article 21(2)(d): “supply chain security, including security-related aspects concerning the relationships between each entity and its direct suppliers or service providers”. Not measurable by a scan: attest how it is met.', 'manual'),
    ('21(2)(e)', 'Security in acquisition, development and maintenance', 'Article 21(2)(e): “security in network and information systems acquisition, development and maintenance, including vulnerability handling and disclosure”. Measured: open findings in CWE-16, CWE-22, CWE-77, CWE-78, CWE-79, CWE-88 and 33 more weakness classes; open findings on CISA KEV; open findings past their remediation SLA; failing Checkov/Prowler/Trivy checks.', 'automatic'),
    ('21(2)(f)', 'Assessing the effectiveness of risk-management measures', 'Article 21(2)(f): “policies and procedures to assess the effectiveness of cybersecurity risk-management measures”. Not measurable by a scan: attest how it is met.', 'manual'),
    ('21(2)(g)', 'Cyber hygiene and cybersecurity training', 'Article 21(2)(g): “basic cyber hygiene practices and cybersecurity training”. Not measurable by a scan: attest how it is met.', 'manual'),
    ('21(2)(h)', 'Cryptography and encryption', 'Article 21(2)(h): “policies and procedures regarding the use of cryptography and, where appropriate, encryption”. Measured: open findings in CWE-295, CWE-297, CWE-311, CWE-312, CWE-313, CWE-316 and 11 more weakness classes; failing Checkov/Prowler/Trivy checks.', 'automatic'),
    ('21(2)(i)', 'Human resources security, access control and asset management', 'Article 21(2)(i): “human resources security, access control policies and asset management”. Measured: open findings in CWE-22, CWE-250, CWE-269, CWE-276, CWE-284, CWE-285 and 4 more weakness classes; an SBOM on the default branch; failing Checkov/Prowler/Trivy checks.', 'automatic'),
    ('21(2)(j)', 'Multi-factor authentication and secured communications', 'Article 21(2)(j): “the use of multi-factor authentication or continuous authentication solutions, secured voice, video and text communications and secured emergency communication systems within the entity, where appropriate”. Measured: open findings in CWE-308; failing Prowler checks.', 'automatic')
) AS v(code, title, description, assessment)
WHERE fw.key = 'nis2';

-- By weakness class (CWE): tool-agnostic.
INSERT INTO control_mappings (control_id, match_type, cwe)
SELECT c.id, 'cwe', v.cwe
FROM controls c
JOIN frameworks fw ON fw.id = c.framework_id AND fw.key = 'nis2'
JOIN (VALUES
    ('21(2)(e)', 16), ('21(2)(e)', 22), ('21(2)(e)', 77), ('21(2)(e)', 78), ('21(2)(e)', 79), ('21(2)(e)', 88), ('21(2)(e)', 89), ('21(2)(e)', 90),
    ('21(2)(e)', 91), ('21(2)(e)', 94), ('21(2)(e)', 95), ('21(2)(e)', 113), ('21(2)(e)', 116), ('21(2)(e)', 119), ('21(2)(e)', 120), ('21(2)(e)', 125),
    ('21(2)(e)', 134), ('21(2)(e)', 190), ('21(2)(e)', 352), ('21(2)(e)', 416), ('21(2)(e)', 434), ('21(2)(e)', 476), ('21(2)(e)', 489), ('21(2)(e)', 502),
    ('21(2)(e)', 601), ('21(2)(e)', 611), ('21(2)(e)', 614), ('21(2)(e)', 643), ('21(2)(e)', 787), ('21(2)(e)', 917), ('21(2)(e)', 918), ('21(2)(e)', 942),
    ('21(2)(e)', 1004), ('21(2)(e)', 1021), ('21(2)(e)', 1188), ('21(2)(e)', 1321), ('21(2)(e)', 1336), ('21(2)(e)', 1392), ('21(2)(e)', 1393),
    ('21(2)(h)', 295), ('21(2)(h)', 297), ('21(2)(h)', 311), ('21(2)(h)', 312), ('21(2)(h)', 313), ('21(2)(h)', 316), ('21(2)(h)', 319), ('21(2)(h)', 320),
    ('21(2)(h)', 321), ('21(2)(h)', 326), ('21(2)(h)', 327), ('21(2)(h)', 328), ('21(2)(h)', 330), ('21(2)(h)', 331), ('21(2)(h)', 338), ('21(2)(h)', 757),
    ('21(2)(h)', 916),
    ('21(2)(i)', 22), ('21(2)(i)', 250), ('21(2)(i)', 269), ('21(2)(i)', 276), ('21(2)(i)', 284), ('21(2)(i)', 285), ('21(2)(i)', 639), ('21(2)(i)', 732),
    ('21(2)(i)', 862), ('21(2)(i)', 863),
    ('21(2)(j)', 308)
) AS v(code, cwe) ON v.code = c.code;

-- By scanner rule: curated Checkov and Trivy (AVD) misconfiguration checks.
INSERT INTO control_mappings (control_id, match_type, scanner, rule_id)
SELECT c.id, 'rule', v.scanner, v.rule_id
FROM controls c
JOIN frameworks fw ON fw.id = c.framework_id AND fw.key = 'nis2'
JOIN (VALUES
    ('21(2)(e)', 'checkov', 'CKV_AWS_79'), ('21(2)(e)', 'checkov', 'CKV_K8S_22'), ('21(2)(e)', 'checkov', 'CKV_K8S_28'),
    ('21(2)(e)', 'checkov', 'CKV_K8S_31'), ('21(2)(e)', 'checkov', 'CKV_K8S_38'), ('21(2)(e)', 'trivy', 'AVD-AWS-0028'),
    ('21(2)(e)', 'trivy', 'AVD-AWS-0130'), ('21(2)(e)', 'trivy', 'AVD-KSV-0014'), ('21(2)(e)', 'trivy', 'AVD-KSV-0036'),
    ('21(2)(h)', 'checkov', 'CKV_AWS_3'), ('21(2)(h)', 'checkov', 'CKV_AWS_8'), ('21(2)(h)', 'checkov', 'CKV_AWS_16'),
    ('21(2)(h)', 'checkov', 'CKV_AWS_19'), ('21(2)(h)', 'checkov', 'CKV_AWS_26'), ('21(2)(h)', 'checkov', 'CKV_AWS_27'),
    ('21(2)(h)', 'checkov', 'CKV_AWS_58'), ('21(2)(h)', 'checkov', 'CKV_AWS_64'), ('21(2)(h)', 'trivy', 'AVD-AWS-0026'),
    ('21(2)(h)', 'trivy', 'AVD-AWS-0039'), ('21(2)(h)', 'trivy', 'AVD-AWS-0079'), ('21(2)(h)', 'trivy', 'AVD-AWS-0080'),
    ('21(2)(h)', 'trivy', 'AVD-AWS-0088'), ('21(2)(h)', 'trivy', 'AVD-AWS-0131'), ('21(2)(h)', 'trivy', 'AVD-KCV-0030'),
    ('21(2)(h)', 'checkov', 'CKV_AWS_2'), ('21(2)(h)', 'checkov', 'CKV_AWS_34'), ('21(2)(h)', 'checkov', 'CKV_AWS_103'),
    ('21(2)(h)', 'trivy', 'AVD-AWS-0012'), ('21(2)(h)', 'trivy', 'AVD-AWS-0013'), ('21(2)(h)', 'trivy', 'AVD-AWS-0047'),
    ('21(2)(h)', 'trivy', 'AVD-AWS-0054'), ('21(2)(h)', 'trivy', 'AVD-KCV-0026'), ('21(2)(h)', 'trivy', 'AVD-KCV-0027'),
    ('21(2)(h)', 'checkov', 'CKV_AWS_7'), ('21(2)(h)', 'checkov', 'CKV_AWS_33'), ('21(2)(h)', 'checkov', 'CKV_AWS_149'),
    ('21(2)(h)', 'trivy', 'AVD-AWS-0015'), ('21(2)(h)', 'trivy', 'AVD-AWS-0027'), ('21(2)(h)', 'trivy', 'AVD-AWS-0132'),
    ('21(2)(i)', 'checkov', 'CKV_AWS_1'), ('21(2)(i)', 'checkov', 'CKV_AWS_49'), ('21(2)(i)', 'checkov', 'CKV_AWS_62'),
    ('21(2)(i)', 'checkov', 'CKV_AWS_109'), ('21(2)(i)', 'checkov', 'CKV_AWS_110'), ('21(2)(i)', 'checkov', 'CKV_AWS_111'),
    ('21(2)(i)', 'checkov', 'CKV_K8S_16'), ('21(2)(i)', 'checkov', 'CKV_K8S_17'), ('21(2)(i)', 'checkov', 'CKV_K8S_18'),
    ('21(2)(i)', 'checkov', 'CKV_K8S_19'), ('21(2)(i)', 'checkov', 'CKV_K8S_20'), ('21(2)(i)', 'checkov', 'CKV_K8S_23'),
    ('21(2)(i)', 'checkov', 'CKV_K8S_39'), ('21(2)(i)', 'trivy', 'AVD-KSV-0001'), ('21(2)(i)', 'trivy', 'AVD-KSV-0005'),
    ('21(2)(i)', 'trivy', 'AVD-KSV-0008'), ('21(2)(i)', 'trivy', 'AVD-KSV-0009'), ('21(2)(i)', 'trivy', 'AVD-KSV-0010'),
    ('21(2)(i)', 'trivy', 'AVD-KSV-0012'), ('21(2)(i)', 'trivy', 'AVD-KSV-0017'), ('21(2)(i)', 'trivy', 'AVD-KSV-0041'),
    ('21(2)(i)', 'trivy', 'AVD-KSV-0046'), ('21(2)(i)', 'trivy', 'AVD-KSV-0050'), ('21(2)(i)', 'checkov', 'CKV_AWS_17'),
    ('21(2)(i)', 'checkov', 'CKV_AWS_20'), ('21(2)(i)', 'checkov', 'CKV_AWS_53'), ('21(2)(i)', 'checkov', 'CKV_AWS_54'),
    ('21(2)(i)', 'checkov', 'CKV_AWS_55'), ('21(2)(i)', 'checkov', 'CKV_AWS_56'), ('21(2)(i)', 'trivy', 'AVD-AWS-0086'),
    ('21(2)(i)', 'trivy', 'AVD-AWS-0087'), ('21(2)(i)', 'trivy', 'AVD-AWS-0091'), ('21(2)(i)', 'trivy', 'AVD-AWS-0092'),
    ('21(2)(i)', 'trivy', 'AVD-AWS-0093'), ('21(2)(i)', 'trivy', 'AVD-AWS-0094'), ('21(2)(i)', 'trivy', 'AVD-AWS-0180')
) AS v(code, scanner, rule_id) ON v.code = c.code;

-- By Prowler check, as Prowler's own compliance packs map them
-- (prowler/compliance/{aws,azure,gcp,kubernetes}, commit d695be2).
INSERT INTO control_mappings (control_id, match_type, scanner, rule_id)
SELECT c.id, 'rule', v.scanner, v.rule_id
FROM controls c
JOIN frameworks fw ON fw.id = c.framework_id AND fw.key = 'nis2'
JOIN (VALUES
    ('21(2)(e)', 'prowler', 'aisearch_service_not_publicly_accessible'), ('21(2)(e)', 'prowler', 'aks_network_policy_enabled'), ('21(2)(e)', 'prowler', 'apikeys_api_restrictions_configured'),
    ('21(2)(e)', 'prowler', 'apikeys_key_rotated_in_90_days'), ('21(2)(e)', 'prowler', 'app_client_certificates_on'), ('21(2)(e)', 'prowler', 'app_ensure_auth_is_set_up'),
    ('21(2)(e)', 'prowler', 'app_ensure_http_is_redirected_to_https'), ('21(2)(e)', 'prowler', 'app_ensure_java_version_is_latest'), ('21(2)(e)', 'prowler', 'app_ensure_php_version_is_latest'),
    ('21(2)(e)', 'prowler', 'app_ensure_python_version_is_latest'), ('21(2)(e)', 'prowler', 'app_ensure_using_http20'), ('21(2)(e)', 'prowler', 'app_ftp_deployment_disabled'),
    ('21(2)(e)', 'prowler', 'app_function_access_keys_configured'), ('21(2)(e)', 'prowler', 'app_function_application_insights_enabled'), ('21(2)(e)', 'prowler', 'app_function_ftps_deployment_disabled'),
    ('21(2)(e)', 'prowler', 'app_function_identity_is_configured'), ('21(2)(e)', 'prowler', 'app_function_identity_without_admin_privileges'), ('21(2)(e)', 'prowler', 'app_function_latest_runtime_version'),
    ('21(2)(e)', 'prowler', 'app_function_not_publicly_accessible'), ('21(2)(e)', 'prowler', 'app_function_vnet_integration_enabled'), ('21(2)(e)', 'prowler', 'app_http_logs_enabled'),
    ('21(2)(e)', 'prowler', 'app_minimum_tls_version_12'), ('21(2)(e)', 'prowler', 'app_register_with_identity'), ('21(2)(e)', 'prowler', 'appengine_version_php_runtime_supported'),
    ('21(2)(e)', 'prowler', 'artifacts_container_analysis_enabled'), ('21(2)(e)', 'prowler', 'autoscaling_group_launch_configuration_requires_imdsv2'), ('21(2)(e)', 'prowler', 'bedrock_vpc_endpoints_configured'),
    ('21(2)(e)', 'prowler', 'bigquery_dataset_cmk_encryption'), ('21(2)(e)', 'prowler', 'cloudtrail_threat_detection_enumeration'), ('21(2)(e)', 'prowler', 'cloudtrail_threat_detection_llm_jacking'),
    ('21(2)(e)', 'prowler', 'cloudtrail_threat_detection_privilege_escalation'), ('21(2)(e)', 'prowler', 'cloudwatch_changes_to_network_acls_alarm_configured'), ('21(2)(e)', 'prowler', 'cloudwatch_changes_to_network_gateways_alarm_configured'),
    ('21(2)(e)', 'prowler', 'cloudwatch_changes_to_network_route_tables_alarm_configured'), ('21(2)(e)', 'prowler', 'cloudwatch_changes_to_vpcs_alarm_configured'), ('21(2)(e)', 'prowler', 'codebuild_project_logging_enabled'),
    ('21(2)(e)', 'prowler', 'codebuild_project_no_secrets_in_variables'), ('21(2)(e)', 'prowler', 'codebuild_project_older_90_days'), ('21(2)(e)', 'prowler', 'codebuild_project_s3_logs_encrypted'),
    ('21(2)(e)', 'prowler', 'codebuild_project_source_repo_url_no_sensitive_credentials'), ('21(2)(e)', 'prowler', 'codebuild_project_user_controlled_buildspec'), ('21(2)(e)', 'prowler', 'codebuild_report_group_export_encrypted'),
    ('21(2)(e)', 'prowler', 'compute_firewall_rdp_access_from_the_internet_allowed'), ('21(2)(e)', 'prowler', 'compute_firewall_ssh_access_from_the_internet_allowed'), ('21(2)(e)', 'prowler', 'compute_instance_block_project_wide_ssh_keys_disabled'),
    ('21(2)(e)', 'prowler', 'compute_instance_shielded_vm_enabled'), ('21(2)(e)', 'prowler', 'compute_network_default_in_use'), ('21(2)(e)', 'prowler', 'compute_network_dns_logging_enabled'),
    ('21(2)(e)', 'prowler', 'compute_network_not_legacy'), ('21(2)(e)', 'prowler', 'containerregistry_admin_user_disabled'), ('21(2)(e)', 'prowler', 'containerregistry_not_publicly_accessible'),
    ('21(2)(e)', 'prowler', 'cosmosdb_account_firewall_use_selected_networks'), ('21(2)(e)', 'prowler', 'defender_additional_email_configured_with_a_security_contact'), ('21(2)(e)', 'prowler', 'defender_assessments_vm_endpoint_protection_installed'),
    ('21(2)(e)', 'prowler', 'defender_auto_provisioning_log_analytics_agent_vms_on'), ('21(2)(e)', 'prowler', 'defender_auto_provisioning_vulnerabilty_assessments_machines_on'), ('21(2)(e)', 'prowler', 'defender_container_images_resolved_vulnerabilities'),
    ('21(2)(e)', 'prowler', 'defender_container_images_scan_enabled'), ('21(2)(e)', 'prowler', 'defender_ensure_defender_for_app_services_is_on'), ('21(2)(e)', 'prowler', 'defender_ensure_defender_for_arm_is_on'),
    ('21(2)(e)', 'prowler', 'defender_ensure_defender_for_azure_sql_databases_is_on'), ('21(2)(e)', 'prowler', 'defender_ensure_defender_for_containers_is_on'), ('21(2)(e)', 'prowler', 'defender_ensure_defender_for_cosmosdb_is_on'),
    ('21(2)(e)', 'prowler', 'defender_ensure_defender_for_databases_is_on'), ('21(2)(e)', 'prowler', 'defender_ensure_defender_for_dns_is_on'), ('21(2)(e)', 'prowler', 'defender_ensure_defender_for_keyvault_is_on'),
    ('21(2)(e)', 'prowler', 'defender_ensure_defender_for_os_relational_databases_is_on'), ('21(2)(e)', 'prowler', 'defender_ensure_defender_for_server_is_on'), ('21(2)(e)', 'prowler', 'defender_ensure_defender_for_sql_servers_is_on'),
    ('21(2)(e)', 'prowler', 'defender_ensure_defender_for_storage_is_on'), ('21(2)(e)', 'prowler', 'defender_ensure_iot_hub_defender_is_on'), ('21(2)(e)', 'prowler', 'defender_ensure_mcas_is_enabled'),
    ('21(2)(e)', 'prowler', 'defender_ensure_notify_alerts_severity_is_high'), ('21(2)(e)', 'prowler', 'defender_ensure_notify_emails_to_owners'), ('21(2)(e)', 'prowler', 'defender_ensure_system_updates_are_applied'),
    ('21(2)(e)', 'prowler', 'defender_ensure_wdatp_is_enabled'), ('21(2)(e)', 'prowler', 'dns_dnssec_disabled'), ('21(2)(e)', 'prowler', 'dns_rsasha1_in_use_to_key_sign_in_dnssec'),
    ('21(2)(e)', 'prowler', 'dns_rsasha1_in_use_to_zone_sign_in_dnssec'), ('21(2)(e)', 'prowler', 'dynamodb_accelerator_cluster_in_transit_encryption_enabled'), ('21(2)(e)', 'prowler', 'ec2_confidential_workload_host_imdsv2_not_enforced'),
    ('21(2)(e)', 'prowler', 'ec2_instance_account_imdsv2_enabled'), ('21(2)(e)', 'prowler', 'ec2_instance_imdsv2_enabled'), ('21(2)(e)', 'prowler', 'ec2_instance_port_cassandra_exposed_to_internet'),
    ('21(2)(e)', 'prowler', 'ec2_instance_port_cifs_exposed_to_internet'), ('21(2)(e)', 'prowler', 'ec2_instance_port_elasticsearch_kibana_exposed_to_internet'), ('21(2)(e)', 'prowler', 'ec2_instance_port_ftp_exposed_to_internet'),
    ('21(2)(e)', 'prowler', 'ec2_instance_port_kafka_exposed_to_internet'), ('21(2)(e)', 'prowler', 'ec2_instance_port_kerberos_exposed_to_internet'), ('21(2)(e)', 'prowler', 'ec2_instance_port_ldap_exposed_to_internet'),
    ('21(2)(e)', 'prowler', 'ec2_instance_port_memcached_exposed_to_internet'), ('21(2)(e)', 'prowler', 'ec2_instance_port_mongodb_exposed_to_internet'), ('21(2)(e)', 'prowler', 'ec2_instance_port_mysql_exposed_to_internet'),
    ('21(2)(e)', 'prowler', 'ec2_instance_port_oracle_exposed_to_internet'), ('21(2)(e)', 'prowler', 'ec2_instance_port_postgresql_exposed_to_internet'), ('21(2)(e)', 'prowler', 'ec2_instance_port_rdp_exposed_to_internet'),
    ('21(2)(e)', 'prowler', 'ec2_instance_port_redis_exposed_to_internet'), ('21(2)(e)', 'prowler', 'ec2_instance_port_sqlserver_exposed_to_internet'), ('21(2)(e)', 'prowler', 'ec2_instance_port_ssh_exposed_to_internet'),
    ('21(2)(e)', 'prowler', 'ec2_instance_port_telnet_exposed_to_internet'), ('21(2)(e)', 'prowler', 'ec2_launch_template_imdsv2_required'), ('21(2)(e)', 'prowler', 'ec2_networkacl_allow_ingress_tcp_port_22'),
    ('21(2)(e)', 'prowler', 'ec2_networkacl_allow_ingress_tcp_port_3389'), ('21(2)(e)', 'prowler', 'ecs_task_definitions_host_networking_mode_users'), ('21(2)(e)', 'prowler', 'eks_cluster_network_policy_enabled'),
    ('21(2)(e)', 'prowler', 'elasticache_redis_cluster_auto_minor_version_upgrades'), ('21(2)(e)', 'prowler', 'elasticbeanstalk_environment_managed_updates_enabled'), ('21(2)(e)', 'prowler', 'elasticbeanstalk_environment_php_platform_updated'),
    ('21(2)(e)', 'prowler', 'elbv2_nlb_tls_termination_enabled'), ('21(2)(e)', 'prowler', 'entra_global_admin_in_less_than_five_users'), ('21(2)(e)', 'prowler', 'entra_policy_ensure_default_user_cannot_create_tenants'),
    ('21(2)(e)', 'prowler', 'entra_policy_guest_invite_only_for_admin_roles'), ('21(2)(e)', 'prowler', 'entra_policy_restricts_user_consent_for_apps'), ('21(2)(e)', 'prowler', 'entra_trusted_named_locations_exists'),
    ('21(2)(e)', 'prowler', 'gcr_container_scanning_enabled'), ('21(2)(e)', 'prowler', 'glue_development_endpoints_cloudwatch_logs_encryption_enabled'), ('21(2)(e)', 'prowler', 'glue_development_endpoints_job_bookmark_encryption_enabled'),
    ('21(2)(e)', 'prowler', 'glue_development_endpoints_s3_encryption_enabled'), ('21(2)(e)', 'prowler', 'iam_account_access_approval_enabled'), ('21(2)(e)', 'prowler', 'iam_avoid_root_usage'),
    ('21(2)(e)', 'prowler', 'iam_custom_role_has_permissions_to_administer_resource_locks'), ('21(2)(e)', 'prowler', 'iam_inline_policy_no_administrative_privileges'), ('21(2)(e)', 'prowler', 'iam_no_service_roles_at_project_level'),
    ('21(2)(e)', 'prowler', 'iam_role_cross_service_confused_deputy_prevention'), ('21(2)(e)', 'prowler', 'iam_role_kms_enforce_separation_of_duties'), ('21(2)(e)', 'prowler', 'iam_role_sa_enforce_separation_of_duties'),
    ('21(2)(e)', 'prowler', 'iam_rotate_access_key_90_days'), ('21(2)(e)', 'prowler', 'iam_sa_no_administrative_privileges'), ('21(2)(e)', 'prowler', 'iam_sa_no_user_managed_keys'),
    ('21(2)(e)', 'prowler', 'iam_sa_user_managed_key_unused'), ('21(2)(e)', 'prowler', 'iam_securityaudit_role_created'), ('21(2)(e)', 'prowler', 'iam_service_account_unused'),
    ('21(2)(e)', 'prowler', 'kafka_cluster_in_transit_encryption_enabled'), ('21(2)(e)', 'prowler', 'kafka_cluster_mutual_tls_authentication_enabled'), ('21(2)(e)', 'prowler', 'kafka_connector_in_transit_encryption_enabled'),
    ('21(2)(e)', 'prowler', 'keyvault_key_expiration_set_in_non_rbac'), ('21(2)(e)', 'prowler', 'keyvault_non_rbac_secret_expiration_set'), ('21(2)(e)', 'prowler', 'logging_log_metric_filter_and_alert_for_audit_configuration_changes_enabled'),
    ('21(2)(e)', 'prowler', 'logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled'), ('21(2)(e)', 'prowler', 'logging_log_metric_filter_and_alert_for_custom_role_changes_enabled'), ('21(2)(e)', 'prowler', 'logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled'),
    ('21(2)(e)', 'prowler', 'logging_log_metric_filter_and_alert_for_sql_instance_configuration_changes_enabled'), ('21(2)(e)', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_firewall_rule_changes_enabled'), ('21(2)(e)', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_network_changes_enabled'),
    ('21(2)(e)', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled'), ('21(2)(e)', 'prowler', 'memorydb_cluster_auto_minor_version_upgrades'), ('21(2)(e)', 'prowler', 'monitor_alert_create_policy_assignment'),
    ('21(2)(e)', 'prowler', 'monitor_alert_create_update_nsg'), ('21(2)(e)', 'prowler', 'monitor_alert_create_update_public_ip_address_rule'), ('21(2)(e)', 'prowler', 'monitor_alert_create_update_security_solution'),
    ('21(2)(e)', 'prowler', 'monitor_alert_create_update_sqlserver_fr'), ('21(2)(e)', 'prowler', 'monitor_alert_delete_nsg'), ('21(2)(e)', 'prowler', 'monitor_alert_delete_policy_assignment'),
    ('21(2)(e)', 'prowler', 'monitor_alert_delete_public_ip_address_rule'), ('21(2)(e)', 'prowler', 'monitor_alert_delete_security_solution'), ('21(2)(e)', 'prowler', 'monitor_alert_delete_sqlserver_fr'),
    ('21(2)(e)', 'prowler', 'mysql_flexible_server_minimum_tls_version_12'), ('21(2)(e)', 'prowler', 'network_bastion_host_exists'), ('21(2)(e)', 'prowler', 'network_flow_log_captured_sent'),
    ('21(2)(e)', 'prowler', 'network_flow_log_more_than_90_days'), ('21(2)(e)', 'prowler', 'network_http_internet_access_restricted'), ('21(2)(e)', 'prowler', 'network_public_ip_shodan'),
    ('21(2)(e)', 'prowler', 'network_rdp_internet_access_restricted'), ('21(2)(e)', 'prowler', 'network_ssh_internet_access_restricted'), ('21(2)(e)', 'prowler', 'network_udp_internet_access_restricted'),
    ('21(2)(e)', 'prowler', 'network_watcher_enabled'), ('21(2)(e)', 'prowler', 'networkfirewall_deletion_protection'), ('21(2)(e)', 'prowler', 'networkfirewall_in_all_vpc'),
    ('21(2)(e)', 'prowler', 'networkfirewall_logging_enabled'), ('21(2)(e)', 'prowler', 'networkfirewall_multi_az'), ('21(2)(e)', 'prowler', 'networkfirewall_policy_default_action_fragmented_packets'),
    ('21(2)(e)', 'prowler', 'networkfirewall_policy_default_action_full_packets'), ('21(2)(e)', 'prowler', 'networkfirewall_policy_rule_group_associated'), ('21(2)(e)', 'prowler', 'opensearch_service_domains_updated_to_the_latest_service_software_version'),
    ('21(2)(e)', 'prowler', 'postgresql_flexible_server_log_retention_days_greater_3'), ('21(2)(e)', 'prowler', 'redshift_cluster_in_transit_encryption_enabled'), ('21(2)(e)', 'prowler', 'route53_dangling_ip_subdomain_takeover'),
    ('21(2)(e)', 'prowler', 'route53_domains_privacy_protection_enabled'), ('21(2)(e)', 'prowler', 'sagemaker_models_network_isolation_enabled'), ('21(2)(e)', 'prowler', 'secretsmanager_secret_rotated_periodically'),
    ('21(2)(e)', 'prowler', 'sqlserver_auditing_retention_90_days'), ('21(2)(e)', 'prowler', 'sqlserver_azuread_administrator_enabled'), ('21(2)(e)', 'prowler', 'sqlserver_microsoft_defender_enabled'),
    ('21(2)(e)', 'prowler', 'sqlserver_recommended_minimal_tls_version'), ('21(2)(e)', 'prowler', 'sqlserver_tde_encryption_enabled'), ('21(2)(e)', 'prowler', 'sqlserver_va_emails_notifications_admins_enabled'),
    ('21(2)(e)', 'prowler', 'sqlserver_vulnerability_assessment_enabled'), ('21(2)(e)', 'prowler', 'ssm_managed_compliant_patching'), ('21(2)(e)', 'prowler', 'storage_default_network_access_rule_is_denied'),
    ('21(2)(e)', 'prowler', 'storage_ensure_minimum_tls_version_12'), ('21(2)(e)', 'prowler', 'storage_ensure_private_endpoints_in_storage_accounts'), ('21(2)(e)', 'prowler', 'storage_secure_transfer_required_is_enabled'),
    ('21(2)(e)', 'prowler', 'transfer_server_in_transit_encryption_enabled'), ('21(2)(e)', 'prowler', 'vpc_endpoint_connections_trust_boundaries'), ('21(2)(e)', 'prowler', 'vpc_endpoint_services_allowed_principals_trust_boundaries'),
    ('21(2)(h)', 'prowler', 'acm_certificates_transparency_logs_enabled'), ('21(2)(h)', 'prowler', 'acm_certificates_with_secure_key_algorithms'), ('21(2)(h)', 'prowler', 'apigateway_restapi_cache_encrypted'),
    ('21(2)(h)', 'prowler', 'apikeys_api_restrictions_configured'), ('21(2)(h)', 'prowler', 'apikeys_key_exists'), ('21(2)(h)', 'prowler', 'apikeys_key_rotated_in_90_days'),
    ('21(2)(h)', 'prowler', 'app_client_certificates_on'), ('21(2)(h)', 'prowler', 'app_function_access_keys_configured'), ('21(2)(h)', 'prowler', 'app_minimum_tls_version_12'),
    ('21(2)(h)', 'prowler', 'artifacts_container_analysis_enabled'), ('21(2)(h)', 'prowler', 'athena_workgroup_encryption'), ('21(2)(h)', 'prowler', 'backup_recovery_point_encrypted'),
    ('21(2)(h)', 'prowler', 'backup_vaults_encrypted'), ('21(2)(h)', 'prowler', 'bigquery_dataset_cmk_encryption'), ('21(2)(h)', 'prowler', 'bigquery_table_cmk_encryption'),
    ('21(2)(h)', 'prowler', 'cloudtrail_kms_encryption_enabled'), ('21(2)(h)', 'prowler', 'cloudwatch_log_metric_filter_root_usage'), ('21(2)(h)', 'prowler', 'cloudwatch_log_metric_filter_sign_in_without_mfa'),
    ('21(2)(h)', 'prowler', 'codebuild_project_s3_logs_encrypted'), ('21(2)(h)', 'prowler', 'codebuild_report_group_export_encrypted'), ('21(2)(h)', 'prowler', 'compute_instance_block_project_wide_ssh_keys_disabled'),
    ('21(2)(h)', 'prowler', 'compute_instance_encryption_with_csek_enabled'), ('21(2)(h)', 'prowler', 'compute_network_dns_logging_enabled'), ('21(2)(h)', 'prowler', 'dataproc_encrypted_with_cmks_disabled'),
    ('21(2)(h)', 'prowler', 'defender_ensure_defender_for_keyvault_is_on'), ('21(2)(h)', 'prowler', 'dms_endpoint_redis_in_transit_encryption_enabled'), ('21(2)(h)', 'prowler', 'dns_dnssec_disabled'),
    ('21(2)(h)', 'prowler', 'dns_rsasha1_in_use_to_key_sign_in_dnssec'), ('21(2)(h)', 'prowler', 'dns_rsasha1_in_use_to_zone_sign_in_dnssec'), ('21(2)(h)', 'prowler', 'dynamodb_accelerator_cluster_encryption_enabled'),
    ('21(2)(h)', 'prowler', 'dynamodb_accelerator_cluster_in_transit_encryption_enabled'), ('21(2)(h)', 'prowler', 'elasticache_redis_cluster_in_transit_encryption_enabled'), ('21(2)(h)', 'prowler', 'iam_no_expired_server_certificates_stored'),
    ('21(2)(h)', 'prowler', 'iam_no_root_access_key'), ('21(2)(h)', 'prowler', 'iam_password_policy_expires_passwords_within_90_days_or_less'), ('21(2)(h)', 'prowler', 'iam_password_policy_lowercase'),
    ('21(2)(h)', 'prowler', 'iam_password_policy_minimum_length_14'), ('21(2)(h)', 'prowler', 'iam_password_policy_number'), ('21(2)(h)', 'prowler', 'iam_password_policy_reuse_24'),
    ('21(2)(h)', 'prowler', 'iam_password_policy_symbol'), ('21(2)(h)', 'prowler', 'iam_password_policy_uppercase'), ('21(2)(h)', 'prowler', 'iam_rotate_access_key_90_days'),
    ('21(2)(h)', 'prowler', 'iam_sa_no_user_managed_keys'), ('21(2)(h)', 'prowler', 'iam_sa_user_managed_key_rotate_90_days'), ('21(2)(h)', 'prowler', 'iam_sa_user_managed_key_unused'),
    ('21(2)(h)', 'prowler', 'iam_user_no_setup_initial_access_key'), ('21(2)(h)', 'prowler', 'iam_user_two_active_access_key'), ('21(2)(h)', 'prowler', 'kafka_connector_in_transit_encryption_enabled'),
    ('21(2)(h)', 'prowler', 'keyvault_key_expiration_set_in_non_rbac'), ('21(2)(h)', 'prowler', 'keyvault_key_rotation_enabled'), ('21(2)(h)', 'prowler', 'keyvault_logging_enabled'),
    ('21(2)(h)', 'prowler', 'keyvault_non_rbac_secret_expiration_set'), ('21(2)(h)', 'prowler', 'keyvault_private_endpoints'), ('21(2)(h)', 'prowler', 'keyvault_rbac_enabled'),
    ('21(2)(h)', 'prowler', 'keyvault_rbac_key_expiration_set'), ('21(2)(h)', 'prowler', 'keyvault_rbac_secret_expiration_set'), ('21(2)(h)', 'prowler', 'keyvault_recoverable'),
    ('21(2)(h)', 'prowler', 'kms_key_not_publicly_accessible'), ('21(2)(h)', 'prowler', 'kms_key_rotation_enabled'), ('21(2)(h)', 'prowler', 'monitor_storage_account_with_activity_logs_cmk_encrypted'),
    ('21(2)(h)', 'prowler', 'redshift_cluster_in_transit_encryption_enabled'), ('21(2)(h)', 'prowler', 'route53_domains_privacy_protection_enabled'), ('21(2)(h)', 'prowler', 'secretsmanager_automatic_rotation_enabled'),
    ('21(2)(h)', 'prowler', 'secretsmanager_not_publicly_accessible'), ('21(2)(h)', 'prowler', 'secretsmanager_secret_rotated_periodically'), ('21(2)(h)', 'prowler', 'secretsmanager_secret_unused'),
    ('21(2)(h)', 'prowler', 'sqlserver_auditing_enabled'), ('21(2)(h)', 'prowler', 'sqlserver_tde_encrypted_with_cmk'), ('21(2)(h)', 'prowler', 'sqlserver_tde_encryption_enabled'),
    ('21(2)(h)', 'prowler', 'storage_ensure_encryption_with_customer_managed_keys'), ('21(2)(h)', 'prowler', 'storage_infrastructure_encryption_is_enabled'), ('21(2)(h)', 'prowler', 'storage_key_rotation_90_days'),
    ('21(2)(h)', 'prowler', 'storage_secure_transfer_required_is_enabled'), ('21(2)(h)', 'prowler', 'transfer_server_in_transit_encryption_enabled'), ('21(2)(h)', 'prowler', 'vm_ensure_attached_disks_encrypted_with_cmk'),
    ('21(2)(h)', 'prowler', 'vm_ensure_unattached_disks_encrypted_with_cmk'),
    ('21(2)(i)', 'prowler', 'accessanalyzer_enabled'), ('21(2)(i)', 'prowler', 'aisearch_service_not_publicly_accessible'), ('21(2)(i)', 'prowler', 'aks_clusters_created_with_private_nodes'),
    ('21(2)(i)', 'prowler', 'aks_network_policy_enabled'), ('21(2)(i)', 'prowler', 'apigateway_restapi_client_certificate_enabled'), ('21(2)(i)', 'prowler', 'apigatewayv2_api_access_logging_enabled'),
    ('21(2)(i)', 'prowler', 'apikeys_key_rotated_in_90_days'), ('21(2)(i)', 'prowler', 'app_ensure_auth_is_set_up'), ('21(2)(i)', 'prowler', 'app_function_ftps_deployment_disabled'),
    ('21(2)(i)', 'prowler', 'app_function_identity_is_configured'), ('21(2)(i)', 'prowler', 'app_http_logs_enabled'), ('21(2)(i)', 'prowler', 'app_minimum_tls_version_12'),
    ('21(2)(i)', 'prowler', 'appstream_fleet_maximum_session_duration'), ('21(2)(i)', 'prowler', 'appstream_fleet_session_disconnect_timeout'), ('21(2)(i)', 'prowler', 'appstream_fleet_session_idle_disconnect_timeout'),
    ('21(2)(i)', 'prowler', 'backup_plans_exist'), ('21(2)(i)', 'prowler', 'backup_vaults_exist'), ('21(2)(i)', 'prowler', 'bigquery_dataset_cmk_encryption'),
    ('21(2)(i)', 'prowler', 'bigquery_dataset_public_access'), ('21(2)(i)', 'prowler', 'bigquery_table_cmk_encryption'), ('21(2)(i)', 'prowler', 'cloudsql_instance_automated_backups'),
    ('21(2)(i)', 'prowler', 'cloudsql_instance_postgres_log_connections_flag'), ('21(2)(i)', 'prowler', 'cloudsql_instance_postgres_log_disconnections_flag'), ('21(2)(i)', 'prowler', 'cloudsql_instance_postgres_log_error_verbosity_flag'),
    ('21(2)(i)', 'prowler', 'cloudsql_instance_postgres_log_min_duration_statement_flag'), ('21(2)(i)', 'prowler', 'cloudsql_instance_postgres_log_min_error_statement_flag'), ('21(2)(i)', 'prowler', 'cloudsql_instance_postgres_log_min_messages_flag'),
    ('21(2)(i)', 'prowler', 'cloudsql_instance_postgres_log_statement_flag'), ('21(2)(i)', 'prowler', 'cloudsql_instance_private_ip_assignment'), ('21(2)(i)', 'prowler', 'cloudsql_instance_sqlserver_contained_database_authentication_flag'),
    ('21(2)(i)', 'prowler', 'cloudsql_instance_sqlserver_remote_access_flag'), ('21(2)(i)', 'prowler', 'cloudsql_instance_ssl_connections'), ('21(2)(i)', 'prowler', 'cloudstorage_bucket_log_retention_policy_lock'),
    ('21(2)(i)', 'prowler', 'cloudtrail_logs_s3_bucket_access_logging_enabled'), ('21(2)(i)', 'prowler', 'cloudwatch_log_metric_filter_aws_organizations_changes'), ('21(2)(i)', 'prowler', 'cloudwatch_log_metric_filter_policy_changes'),
    ('21(2)(i)', 'prowler', 'cloudwatch_log_metric_filter_security_group_changes'), ('21(2)(i)', 'prowler', 'cognito_identity_pool_guest_access_disabled'), ('21(2)(i)', 'prowler', 'cognito_user_pool_blocks_compromised_credentials_sign_in_attempts'),
    ('21(2)(i)', 'prowler', 'cognito_user_pool_blocks_potential_malicious_sign_in_attempts'), ('21(2)(i)', 'prowler', 'cognito_user_pool_password_policy_lowercase'), ('21(2)(i)', 'prowler', 'cognito_user_pool_password_policy_minimum_length_14'),
    ('21(2)(i)', 'prowler', 'cognito_user_pool_password_policy_number'), ('21(2)(i)', 'prowler', 'cognito_user_pool_password_policy_symbol'), ('21(2)(i)', 'prowler', 'cognito_user_pool_password_policy_uppercase'),
    ('21(2)(i)', 'prowler', 'compute_firewall_rdp_access_from_the_internet_allowed'), ('21(2)(i)', 'prowler', 'compute_firewall_ssh_access_from_the_internet_allowed'), ('21(2)(i)', 'prowler', 'compute_instance_block_project_wide_ssh_keys_disabled'),
    ('21(2)(i)', 'prowler', 'compute_instance_encryption_with_csek_enabled'), ('21(2)(i)', 'prowler', 'compute_loadbalancer_logging_enabled'), ('21(2)(i)', 'prowler', 'compute_network_dns_logging_enabled'),
    ('21(2)(i)', 'prowler', 'compute_network_not_legacy'), ('21(2)(i)', 'prowler', 'compute_project_os_login_enabled'), ('21(2)(i)', 'prowler', 'compute_subnet_flow_logs_enabled'),
    ('21(2)(i)', 'prowler', 'containerregistry_not_publicly_accessible'), ('21(2)(i)', 'prowler', 'containerregistry_uses_private_link'), ('21(2)(i)', 'prowler', 'cosmosdb_account_firewall_use_selected_networks'),
    ('21(2)(i)', 'prowler', 'cosmosdb_account_use_private_endpoints'), ('21(2)(i)', 'prowler', 'defender_auto_provisioning_log_analytics_agent_vms_on'), ('21(2)(i)', 'prowler', 'dlm_ebs_snapshot_lifecycle_policy_exists'),
    ('21(2)(i)', 'prowler', 'dns_dnssec_disabled'), ('21(2)(i)', 'prowler', 'dns_rsasha1_in_use_to_key_sign_in_dnssec'), ('21(2)(i)', 'prowler', 'dns_rsasha1_in_use_to_zone_sign_in_dnssec'),
    ('21(2)(i)', 'prowler', 'dynamodb_table_protected_by_backup_plan'), ('21(2)(i)', 'prowler', 'ec2_ebs_snapshot_account_block_public_access'), ('21(2)(i)', 'prowler', 'ec2_ebs_volume_protected_by_backup_plan'),
    ('21(2)(i)', 'prowler', 'ec2_instance_profile_attached'), ('21(2)(i)', 'prowler', 'ecr_repositories_lifecycle_policy_enabled'), ('21(2)(i)', 'prowler', 'ecs_task_definitions_containers_readonly_access'),
    ('21(2)(i)', 'prowler', 'efs_access_point_enforce_root_directory'), ('21(2)(i)', 'prowler', 'efs_access_point_enforce_user_identity'), ('21(2)(i)', 'prowler', 'efs_not_publicly_accessible'),
    ('21(2)(i)', 'prowler', 'eks_control_plane_logging_all_types_enabled'), ('21(2)(i)', 'prowler', 'entra_global_admin_in_less_than_five_users'), ('21(2)(i)', 'prowler', 'entra_policy_default_users_cannot_create_security_groups'),
    ('21(2)(i)', 'prowler', 'entra_policy_ensure_default_user_cannot_create_apps'), ('21(2)(i)', 'prowler', 'entra_policy_ensure_default_user_cannot_create_tenants'), ('21(2)(i)', 'prowler', 'entra_policy_guest_invite_only_for_admin_roles'),
    ('21(2)(i)', 'prowler', 'entra_policy_guest_users_access_restrictions'), ('21(2)(i)', 'prowler', 'entra_policy_restricts_user_consent_for_apps'), ('21(2)(i)', 'prowler', 'entra_policy_user_consent_for_verified_apps'),
    ('21(2)(i)', 'prowler', 'entra_users_cannot_create_microsoft_365_groups'), ('21(2)(i)', 'prowler', 'fsx_file_system_copy_tags_to_backups_enabled'), ('21(2)(i)', 'prowler', 'fsx_file_system_copy_tags_to_volumes_enabled'),
    ('21(2)(i)', 'prowler', 'iam_account_access_approval_enabled'), ('21(2)(i)', 'prowler', 'iam_audit_logs_enabled'), ('21(2)(i)', 'prowler', 'iam_avoid_root_usage'),
    ('21(2)(i)', 'prowler', 'iam_inline_policy_no_administrative_privileges'), ('21(2)(i)', 'prowler', 'iam_no_service_roles_at_project_level'), ('21(2)(i)', 'prowler', 'iam_password_policy_expires_passwords_within_90_days_or_less'),
    ('21(2)(i)', 'prowler', 'iam_password_policy_lowercase'), ('21(2)(i)', 'prowler', 'iam_policy_allows_privilege_escalation'), ('21(2)(i)', 'prowler', 'iam_policy_attached_only_to_group_or_roles'),
    ('21(2)(i)', 'prowler', 'iam_policy_no_full_access_to_cloudtrail'), ('21(2)(i)', 'prowler', 'iam_policy_no_full_access_to_kms'), ('21(2)(i)', 'prowler', 'iam_role_access_not_stale_to_bedrock'),
    ('21(2)(i)', 'prowler', 'iam_role_administratoraccess_policy'), ('21(2)(i)', 'prowler', 'iam_role_kms_enforce_separation_of_duties'), ('21(2)(i)', 'prowler', 'iam_role_sa_enforce_separation_of_duties'),
    ('21(2)(i)', 'prowler', 'iam_rotate_access_key_90_days'), ('21(2)(i)', 'prowler', 'iam_sa_no_administrative_privileges'), ('21(2)(i)', 'prowler', 'iam_sa_no_user_managed_keys'),
    ('21(2)(i)', 'prowler', 'iam_sa_user_managed_key_rotate_90_days'), ('21(2)(i)', 'prowler', 'iam_sa_user_managed_key_unused'), ('21(2)(i)', 'prowler', 'iam_service_account_unused'),
    ('21(2)(i)', 'prowler', 'iam_user_access_not_stale_to_bedrock'), ('21(2)(i)', 'prowler', 'iam_user_access_not_stale_to_sagemaker'), ('21(2)(i)', 'prowler', 'iam_user_accesskey_unused'),
    ('21(2)(i)', 'prowler', 'iam_user_console_access_unused'), ('21(2)(i)', 'prowler', 'keyvault_key_expiration_set_in_non_rbac'), ('21(2)(i)', 'prowler', 'keyvault_key_rotation_enabled'),
    ('21(2)(i)', 'prowler', 'keyvault_logging_enabled'), ('21(2)(i)', 'prowler', 'keyvault_non_rbac_secret_expiration_set'), ('21(2)(i)', 'prowler', 'keyvault_private_endpoints'),
    ('21(2)(i)', 'prowler', 'keyvault_rbac_key_expiration_set'), ('21(2)(i)', 'prowler', 'keyvault_rbac_secret_expiration_set'), ('21(2)(i)', 'prowler', 'keyvault_recoverable'),
    ('21(2)(i)', 'prowler', 'kms_cmk_rotation_enabled'), ('21(2)(i)', 'prowler', 'kms_key_not_publicly_accessible'), ('21(2)(i)', 'prowler', 'kms_key_rotation_enabled'),
    ('21(2)(i)', 'prowler', 'logging_log_metric_filter_and_alert_for_audit_configuration_changes_enabled'), ('21(2)(i)', 'prowler', 'logging_log_metric_filter_and_alert_for_bucket_permission_changes_enabled'), ('21(2)(i)', 'prowler', 'logging_log_metric_filter_and_alert_for_custom_role_changes_enabled'),
    ('21(2)(i)', 'prowler', 'logging_log_metric_filter_and_alert_for_project_ownership_changes_enabled'), ('21(2)(i)', 'prowler', 'logging_log_metric_filter_and_alert_for_sql_instance_configuration_changes_enabled'), ('21(2)(i)', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_firewall_rule_changes_enabled'),
    ('21(2)(i)', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_network_changes_enabled'), ('21(2)(i)', 'prowler', 'logging_log_metric_filter_and_alert_for_vpc_network_route_changes_enabled'), ('21(2)(i)', 'prowler', 'logging_sink_created'),
    ('21(2)(i)', 'prowler', 'monitor_alert_create_policy_assignment'), ('21(2)(i)', 'prowler', 'monitor_alert_create_update_nsg'), ('21(2)(i)', 'prowler', 'monitor_alert_create_update_public_ip_address_rule'),
    ('21(2)(i)', 'prowler', 'monitor_alert_create_update_security_solution'), ('21(2)(i)', 'prowler', 'monitor_alert_create_update_sqlserver_fr'), ('21(2)(i)', 'prowler', 'monitor_alert_delete_nsg'),
    ('21(2)(i)', 'prowler', 'monitor_alert_delete_policy_assignment'), ('21(2)(i)', 'prowler', 'monitor_alert_delete_public_ip_address_rule'), ('21(2)(i)', 'prowler', 'monitor_alert_delete_security_solution'),
    ('21(2)(i)', 'prowler', 'monitor_alert_delete_sqlserver_fr'), ('21(2)(i)', 'prowler', 'monitor_storage_account_with_activity_logs_cmk_encrypted'), ('21(2)(i)', 'prowler', 'monitor_storage_account_with_activity_logs_is_private'),
    ('21(2)(i)', 'prowler', 'mysql_flexible_server_audit_log_connection_activated'), ('21(2)(i)', 'prowler', 'mysql_flexible_server_audit_log_enabled'), ('21(2)(i)', 'prowler', 'mysql_flexible_server_minimum_tls_version_12'),
    ('21(2)(i)', 'prowler', 'neptune_cluster_copy_tags_to_snapshots'), ('21(2)(i)', 'prowler', 'network_bastion_host_exists'), ('21(2)(i)', 'prowler', 'network_flow_log_captured_sent'),
    ('21(2)(i)', 'prowler', 'network_flow_log_more_than_90_days'), ('21(2)(i)', 'prowler', 'network_http_internet_access_restricted'), ('21(2)(i)', 'prowler', 'network_public_ip_shodan'),
    ('21(2)(i)', 'prowler', 'network_rdp_internet_access_restricted'), ('21(2)(i)', 'prowler', 'network_ssh_internet_access_restricted'), ('21(2)(i)', 'prowler', 'network_udp_internet_access_restricted'),
    ('21(2)(i)', 'prowler', 'network_watcher_enabled'), ('21(2)(i)', 'prowler', 'organizations_tags_policies_enabled_and_attached'), ('21(2)(i)', 'prowler', 'postgresql_flexible_server_log_checkpoints_on'),
    ('21(2)(i)', 'prowler', 'postgresql_flexible_server_log_connections_on'), ('21(2)(i)', 'prowler', 'postgresql_flexible_server_log_disconnections_on'), ('21(2)(i)', 'prowler', 'postgresql_flexible_server_log_retention_days_greater_3'),
    ('21(2)(i)', 'prowler', 'rds_cluster_copy_tags_to_snapshots'), ('21(2)(i)', 'prowler', 'rds_cluster_protected_by_backup_plan'), ('21(2)(i)', 'prowler', 'rds_instance_copy_tags_to_snapshots'),
    ('21(2)(i)', 'prowler', 'rds_instance_protected_by_backup_plan'), ('21(2)(i)', 'prowler', 's3_bucket_lifecycle_enabled'), ('21(2)(i)', 'prowler', 's3_bucket_server_access_logging_enabled'),
    ('21(2)(i)', 'prowler', 'secretsmanager_automatic_rotation_enabled'), ('21(2)(i)', 'prowler', 'secretsmanager_secret_rotated_periodically'), ('21(2)(i)', 'prowler', 'sqlserver_auditing_retention_90_days'),
    ('21(2)(i)', 'prowler', 'sqlserver_recommended_minimal_tls_version'), ('21(2)(i)', 'prowler', 'sqlserver_tde_encrypted_with_cmk'), ('21(2)(i)', 'prowler', 'sqlserver_tde_encryption_enabled'),
    ('21(2)(i)', 'prowler', 'ssmincidents_enabled_with_plans'), ('21(2)(i)', 'prowler', 'storage_blob_public_access_level_is_disabled'), ('21(2)(i)', 'prowler', 'storage_default_network_access_rule_is_denied'),
    ('21(2)(i)', 'prowler', 'storage_ensure_azure_services_are_trusted_to_access_is_enabled'), ('21(2)(i)', 'prowler', 'storage_ensure_encryption_with_customer_managed_keys'), ('21(2)(i)', 'prowler', 'storage_ensure_minimum_tls_version_12'),
    ('21(2)(i)', 'prowler', 'storage_ensure_private_endpoints_in_storage_accounts'), ('21(2)(i)', 'prowler', 'storage_ensure_soft_delete_is_enabled'), ('21(2)(i)', 'prowler', 'storage_infrastructure_encryption_is_enabled'),
    ('21(2)(i)', 'prowler', 'storage_key_rotation_90_days'), ('21(2)(i)', 'prowler', 'storage_secure_transfer_required_is_enabled'), ('21(2)(i)', 'prowler', 'transfer_server_in_transit_encryption_enabled'),
    ('21(2)(i)', 'prowler', 'vm_ensure_attached_disks_encrypted_with_cmk'), ('21(2)(i)', 'prowler', 'vm_ensure_unattached_disks_encrypted_with_cmk'), ('21(2)(i)', 'prowler', 'wafv2_webacl_logging_enabled'),
    ('21(2)(j)', 'prowler', 'apigatewayv2_api_access_logging_enabled'), ('21(2)(j)', 'prowler', 'cloudtrail_bucket_requires_mfa_delete'), ('21(2)(j)', 'prowler', 'cloudwatch_log_metric_filter_sign_in_without_mfa'),
    ('21(2)(j)', 'prowler', 'cognito_identity_pool_guest_access_disabled'), ('21(2)(j)', 'prowler', 'cognito_user_pool_mfa_enabled'), ('21(2)(j)', 'prowler', 'directoryservice_supported_mfa_radius_enabled'),
    ('21(2)(j)', 'prowler', 'dms_endpoint_mongodb_authentication_enabled'), ('21(2)(j)', 'prowler', 'entra_conditional_access_policy_require_mfa_for_management_api'), ('21(2)(j)', 'prowler', 'entra_non_privileged_user_has_mfa'),
    ('21(2)(j)', 'prowler', 'entra_privileged_user_has_mfa'), ('21(2)(j)', 'prowler', 'entra_trusted_named_locations_exists'), ('21(2)(j)', 'prowler', 'entra_user_with_vm_access_has_mfa'),
    ('21(2)(j)', 'prowler', 'iam_administrator_access_with_mfa'), ('21(2)(j)', 'prowler', 'iam_root_hardware_mfa_enabled'), ('21(2)(j)', 'prowler', 'iam_root_mfa_enabled'),
    ('21(2)(j)', 'prowler', 'iam_user_hardware_mfa_enabled'), ('21(2)(j)', 'prowler', 'iam_user_mfa_enabled_console_access'), ('21(2)(j)', 'prowler', 'kafka_cluster_mutual_tls_authentication_enabled'),
    ('21(2)(j)', 'prowler', 'neptune_cluster_iam_authentication_enabled'), ('21(2)(j)', 'prowler', 'opensearch_service_domains_use_cognito_authentication_for_kibana'), ('21(2)(j)', 'prowler', 'rds_cluster_iam_authentication_enabled'),
    ('21(2)(j)', 'prowler', 'rds_instance_iam_authentication_enabled'), ('21(2)(j)', 'prowler', 's3_bucket_no_mfa_delete')
) AS v(code, scanner, rule_id) ON v.code = c.code;

-- By finding state (kev, sla) or project fact (sbom, vex).
INSERT INTO control_mappings (control_id, match_type)
SELECT c.id, v.match_type
FROM controls c
JOIN frameworks fw ON fw.id = c.framework_id AND fw.key = 'nis2'
JOIN (VALUES
    ('21(2)(e)', 'kev'), ('21(2)(e)', 'sla'),
    ('21(2)(i)', 'sbom')
) AS v(code, match_type) ON v.code = c.code;
