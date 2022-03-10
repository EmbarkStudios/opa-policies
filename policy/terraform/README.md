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
|TF_GCP_24|DENY|GKE DEPRECATED|   |
|TF_GCP_25|DENY|GKE Workload Identity not enabled on nodes in pool|   |
|TF_GCP_26|DENY|GKE release_channel not set to "REGULAR"|   |
|TF_GCP_27|DENY|GKE image_type not set to "COS"|   |
|TF_GCP_28|DENY|GKE security_group not set to "gke-security-groups@\<domain\>"|   |
|TF_GCP_29|DENY|GKE cluster not removing default node pool|   |
|TF_GCP_30|DENY|KMS Crypto Key IAM Member allUsers or allAuthenticatedUsers|   |
|TF_GCP_31|DENY|KMS Crypto Key IAM Binding allUsers or allAuthenticatedUsers|   |
|TF_GCP_32|DENY|GKE enabled_integrity_monitoring set to false|   |
|TF_GCP_34|DENY|GKE shielded_nodes not enabled in cluster |   |
|TF_GCP_35|DENY|KMS Crypto Key rotation longer than 90 days|   |
|TF_GCP_36|DENY|GCE Instance using the default service account|   |
|TF_GCP_37|DENY|Folder IAM Member Default service accounts on folder level|   |
|TF_GCP_38|DENY|Folder IAM Binding Default service accounts on folder level|   |
|TF_GCP_39|DENY|GCE Instance not using OS Login|   |
|TF_GCP_40|DENY|Project metadata setting project-wide ssh keys|   |
|TF_GCP_41|DENY|GKE Nodes running with a default service account|   |
|TF_GCP_42|DENY|GCE network using auto_create_subnetworks |   |
|TF_GCP_43|DENY|IAP IAM not specifying host |   |
|TF_GCP_44|DENY|IAM `user:` in favor of `group:` and `serviceAccount:` |   |
|TF_GCP_45|DENY|GKE legacy ABAC enabled |   |
|TF_GCP_46|DENY|CloudSQL auto backups disabled |   |
|TF_GCP_47|DENY|CloudSQL disk auto resize disabled |   |
|TF_GCP_48|DENY|CloudSQL zonal instance, prefer regional |   |
|TF_GCP_49|DENY|Cloud Memorystore redis without auth |   |
|TF_GCP_50|DENY|Artifact Registry IAM Binding allUsers or allAuthenticatedUsers |   |
|TF_GCP_51|DENY|Artifact Registry IAM Member allUsers or allAuthenticatedUsers |   |
|TF_GCP_52|DENY|CloudSQL Postgres with no point in time recovery |   |
|TF_GCP_53|DENY|CloudSQL MySQL with missing flags |   |


## hcl vs json

We are using the `tf.json` format internally (as opposed to `HCL` - `.tf`). All of the Terraform checks are only tested using `tf.json` and while the checks might work making exceptions will probably not work for `.tf` due to us using the `//` [comment property](https://www.terraform.io/docs/configuration/syntax-json.html#comment-properties).

## Make an exception

If you specify the `//` [comment property](https://www.terraform.io/docs/configuration/syntax-json.html#comment-properties) inside of a resource with the value being a comma separated list of ids you can ignore checks for an asset.

Example

```json
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
