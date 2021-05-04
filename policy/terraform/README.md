# Terraform checks

|ID|Severity|Name|Framework
|---|---|---|---|
|TF_GCP_01|DENY|Bucket without uniform_level_access|   |
|TF_GCP_02|DENY|Bucket IAM Member allUsers or allAuthenticatedUsers|   |
|TF_GCP_03|DENY|Bucket IAM Binding allUsers or allAuthenticatedUsers|   |
|TF_GCP_04|DENY|IAM Policy containing allUsers or allAuthenticatedUsers|   |
|TF_GCP_05|DENY|GKE not using alias ip|   |
|TF_GCP_06|DENY|Project having auto-created network|   |
|TF_GCP_07|DENY|BQ Dataset IAM Member allUsers or allAuthenticatedUsers|   |
|TF_GCP_08|DENY|BQ Table IAM Member allUsers or allAuthenticatedUsers|   |
|TF_GCP_09|DENY|BQ Dataset IAM Binding allUsers or allAuthenticatedUsers|   |
|TF_GCP_10|DENY|BQ Table IAM Binding allUsers or allAuthenticatedUsers|   |
|TF_GCP_11|DENY|GCE Weak SSL policies|   |
|TF_GCP_12|DENY|IAP IAM Member allUsers or allAuthenticatedUsers|   |
|TF_GCP_13|DENY|IAP IAM Binding allUsers or allAuthenticatedUsers|   |
|TF_GCP_14|DENY|Firewall rule allowing unrestricted ingress|   |
|TF_GCP_15|DENY|Org IAM Member Default service accounts on org level|   |
|TF_GCP_16|DENY|Org IAM Binding Default service accounts on org level|   |
|TF_GCP_17|DENY|IAM Member impersonation roles on project, folder and org |   |
|TF_GCP_18|DENY|IAM Binding impersonation roles on project, folder and org|   |
|TF_GCP_19|DENY|GKE not using auto_upgrade|   |
|TF_GCP_20|DENY|GCE not using secure_boot|   |
|TF_GCP_21|DENY|GKE not using auto_repair|   |
|TF_GCP_22|DENY|GKE nodes in pool not using secure_boot|   |
|TF_GCP_23|DENY|GKE masters not using secure_boot|   |
|TF_GCP_24|DENY|GKE Workload Identity not enabled on masters|   |
|TF_GCP_25|DENY|GKE Workload Identity not enabled on nodes in pool|   |
|TF_GCP_26|DENY|GKE release_channel not set to "REGULAR"|   |
|TF_GCP_27|DENY|GKE image_type not set to "COS"|   |
|TF_GCP_28|DENY|GKE security_group not set to "gke-security-groups@\<domain\>"|   |
|TF_GCP_29|DENY|GKE cluster not removing default node pool|   |
|TF_GCP_32|DENY|GKE enabled_integrity_monitoring set to false|   |
|TF_GCP_34|DENY|GKE shielded_nodes not enabled in cluster |   |






## Make an exception

If you specify the `//` [comment property](https://www.terraform.io/docs/configuration/syntax-json.html#comment-properties) inside of a resource with the value being a comma separated list of ids you can ignore checks for an asset.

Example
```
"resource": {
    "google_storage_bucket": {
        "b3": {
            "name": "b3",
            "//": "TF_GCS_01",
            "uniform_bucket_level_access": false,
            "location": "eu",
            "storage_class": "STANDARD"
        }
    }
}
```

## Links

* [Checkov](https://github.com/bridgecrewio/checkov/tree/master/checkov/terraform/checks/resource/gcp)
