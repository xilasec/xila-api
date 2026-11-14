-- Seed a CIS AWS Foundations Benchmark framework mapped to Prowler check IDs
-- (match_type='rule', scanner='prowler'). A failing Prowler check now drives
-- CIS compliance the same way CWEs drive OWASP.
INSERT INTO frameworks (key, name, version, description)
VALUES ('cis-aws-3.0', 'CIS AWS Foundations Benchmark', '3.0',
        'CIS AWS Foundations Benchmark, mapped to Prowler checks (scanner=prowler).');

INSERT INTO controls (framework_id, code, title)
SELECT fw.id, v.code, v.title
FROM frameworks fw
CROSS JOIN (VALUES
    ('1.4',  'Ensure no root account access key exists'),
    ('1.5',  'Ensure MFA is enabled for the root account'),
    ('1.6',  'Ensure hardware MFA is enabled for the root account'),
    ('1.7',  'Eliminate use of the root account for administrative tasks'),
    ('1.8',  'Ensure IAM password policy requires minimum length of 14'),
    ('1.9',  'Ensure IAM password policy prevents password reuse'),
    ('1.10', 'Ensure MFA is enabled for all IAM users with console access'),
    ('1.12', 'Ensure credentials unused for 45 days are disabled'),
    ('1.14', 'Ensure access keys are rotated every 90 days or less'),
    ('1.16', 'Ensure no IAM policies grant full administrative privileges'),
    ('1.20', 'Ensure IAM Access Analyzer is enabled'),
    ('2.1.1','Ensure S3 buckets have default encryption enabled'),
    ('2.1.2','Ensure S3 bucket policy denies HTTP requests'),
    ('2.1.4','Ensure S3 buckets block public access'),
    ('3.1',  'Ensure CloudTrail is enabled in all regions'),
    ('3.2',  'Ensure CloudTrail log file validation is enabled'),
    ('3.3',  'Ensure the CloudTrail S3 bucket is not publicly accessible'),
    ('3.5',  'Ensure AWS Config is enabled in all regions'),
    ('3.7',  'Ensure CloudTrail logs are encrypted at rest with KMS'),
    ('4.1',  'Ensure a log metric filter and alarm for unauthorized API calls'),
    ('4.3',  'Ensure a log metric filter and alarm for root account usage'),
    ('5.2',  'Ensure no security group allows ingress from 0.0.0.0/0 to port 22'),
    ('5.3',  'Ensure no security group allows ingress from 0.0.0.0/0 to port 3389'),
    ('5.4',  'Ensure VPC flow logging is enabled in all VPCs'),
    ('5.5',  'Ensure the default security group restricts all traffic')
) AS v(code, title)
WHERE fw.key = 'cis-aws-3.0';

INSERT INTO control_mappings (control_id, match_type, scanner, rule_id)
SELECT c.id, 'rule', 'prowler', v.check_id
FROM controls c
JOIN frameworks fw ON fw.id = c.framework_id AND fw.key = 'cis-aws-3.0'
JOIN (VALUES
    ('1.4',  'iam_no_root_access_key'),
    ('1.5',  'iam_root_mfa_enabled'),
    ('1.6',  'iam_root_hardware_mfa_enabled'),
    ('1.7',  'iam_avoid_root_usage'),
    ('1.8',  'iam_password_policy_minimum_length_14'),
    ('1.9',  'iam_password_policy_reuse_24'),
    ('1.10', 'iam_user_mfa_enabled_console_access'),
    ('1.12', 'iam_disable_45_days_credentials'),
    ('1.14', 'iam_rotate_access_key_90_days'),
    ('1.16', 'iam_policy_no_administrative_privileges'),
    ('1.20', 'accessanalyzer_enabled'),
    ('2.1.1','s3_bucket_default_encryption'),
    ('2.1.2','s3_bucket_secure_transport_policy'),
    ('2.1.4','s3_account_level_public_access_blocks'),
    ('3.1',  'cloudtrail_multi_region_enabled'),
    ('3.2',  'cloudtrail_log_file_validation_enabled'),
    ('3.3',  'cloudtrail_logs_s3_bucket_is_not_publicly_accessible'),
    ('3.5',  'config_recorder_all_regions_enabled'),
    ('3.7',  'cloudtrail_kms_encryption_enabled'),
    ('4.1',  'cloudwatch_log_metric_filter_unauthorized_api_calls'),
    ('4.3',  'cloudwatch_log_metric_filter_root_usage'),
    ('5.2',  'ec2_securitygroup_allow_ingress_from_internet_to_port_22'),
    ('5.3',  'ec2_securitygroup_allow_ingress_from_internet_to_port_3389'),
    ('5.4',  'vpc_flow_logs_enabled'),
    ('5.5',  'ec2_securitygroup_default_restrict_traffic')
) AS v(code, check_id) ON v.code = c.code;
