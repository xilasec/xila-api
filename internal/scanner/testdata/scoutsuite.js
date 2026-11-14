scoutsuite_results =
{
 "account_id": "gcp-project-id",
 "last_run": {
  "ruleset_name": "default",
  "time": "2021-01-08 17:28:00+0100",
  "version": "5.10.2"
 },
 "provider_code": "gcp",
 "provider_name": "Google Cloud Platform",
 "result_format": "json",
 "services": {
  "cloudstorage": {
   "buckets_count": 2,
   "findings": {
    "cloudstorage-bucket-no-logging": {
     "checked_items": 2,
     "compliance": [
      {
       "name": "CIS Google Cloud Platform Foundations",
       "reference": "5.3",
       "version": "1.0.0"
      }
     ],
     "dashboard_name": "Buckets",
     "description": "Bucket with Logging Disabled",
     "flagged_items": 2,
     "id_suffix": "logging_enabled",
     "items": [
      "cloudstorage.projects.gcp-project-id.buckets.52fc025e81845686d3c9fe5a5dc4f5e7ae740064.logging_enabled",
      "cloudstorage.projects.gcp-project-id.buckets.be0c682b7f6d9568fed2ec924eea5ebcfe083f3b.logging_enabled"
     ],
     "level": "warning",
     "path": "cloudstorage.projects.id.buckets.id",
     "rationale": "Enable access and storage logs, in order to capture all events which may affect objects within target buckets.",
     "references": [
      "https://cloud.google.com/storage/docs/access-logs"
     ],
     "remediation": null,
     "service": "Cloud Storage"
    },
    "cloudstorage-bucket-no-versioning": {
     "checked_items": 2,
     "compliance": null,
     "dashboard_name": "Buckets",
     "description": "Bucket with Versioning Disabled",
     "flagged_items": 2,
     "id_suffix": "versioning_enabled",
     "items": [
      "cloudstorage.projects.gcp-project-id.buckets.52fc025e81845686d3c9fe5a5dc4f5e7ae740064.versioning_enabled",
      "cloudstorage.projects.gcp-project-id.buckets.be0c682b7f6d9568fed2ec924eea5ebcfe083f3b.versioning_enabled"
     ],
     "level": "warning",
     "path": "cloudstorage.projects.id.buckets.id",
     "rationale": "Enable Object Versioning to protect Cloud Storage data from being overwritten or accidentally deleted.",
     "references": [
      "https://cloud.google.com/storage/docs/using-object-versioning"
     ],
     "remediation": null,
     "service": "Cloud Storage"
    },
    "cloudstorage-bucket-allAuthenticatedUsers": {
     "checked_items": 2,
     "compliance": [
      {
       "name": "CIS Google Cloud Platform Foundations",
       "reference": "5.1",
       "version": "1.0.0"
      }
     ],
     "dashboard_name": "Buckets",
     "description": "Bucket Accessible by \"allAuthenticatedUsers\"",
     "display_path": "cloudstorage.projects.id.buckets.id",
     "flagged_items": 0,
     "id_suffix": "allAuthenticatedUsers",
     "items": [],
     "level": "danger",
     "path": "cloudstorage.projects.id.buckets.id",
     "rationale": "Allowing anonymous and/or public access grants permissions to anyone to access bucket content. Such access might not be desired if you are storing any sensitive data. Hence, ensure that anonymous and/or public access to a bucket is not allowed.",
     "references": [
      "https://cloud.google.com/storage/docs/access-control/iam-reference",
      "https://cloud.google.com/storage/docs/access-control/making-data-public"
     ],
     "remediation": "No role should contain \"allUsers\" and/or \"allAuthenticatedUsers\" as a member.",
     "service": "Cloud Storage"
    }
   },
   "projects": {
    "gcp-project-id": {
     "buckets": {
      "52fc025e81845686d3c9fe5a5dc4f5e7ae740064": {
       "creation_date": "2019-01-24 09:35:13.157000+00:00",
       "id": "52fc025e81845686d3c9fe5a5dc4f5e7ae740064",
       "location": "EU",
       "logging_enabled": false,
       "name": "gcp-project-id.appspot.com",
       "project_id": "gcp-project-id",
       "project_number": 1111111111,
       "storage_class": "standard",
       "uniform_bucket_level_access": false,
       "versioning_enabled": false
      },
      "be0c682b7f6d9568fed2ec924eea5ebcfe083f3b": {
       "creation_date": "2019-01-24 09:35:13.151000+00:00",
       "id": "be0c682b7f6d9568fed2ec924eea5ebcfe083f3b",
       "location": "EU",
       "logging_enabled": false,
       "name": "staging.gcp-project-id.appspot.com",
       "project_id": "gcp-project-id",
       "project_number": 1111111111,
       "storage_class": "standard",
       "uniform_bucket_level_access": false,
       "versioning_enabled": false
      }
     },
     "buckets_count": 2
    }
   }
  }
 }
}
