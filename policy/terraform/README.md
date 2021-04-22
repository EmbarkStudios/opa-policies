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









TO EVALUTE:

### GCP CIS Benchmarks

#### Compile time

* (custom) Discourage admin/editor on project level as opposed to specific resource on bucket/pubsub, etc
* (custom) Ensure GKE basic auth is disabled
* (custom) Ensure Kubernetes Cluster is created with Alias IP ranges enabled
* (custom) Ensure Container-Optimized OS (cos) is used for Kubernetes Engine Clusters Node image
* (custom) Ensure default appengine & compute SA's are not used (project level)

* 1.4 Ensure that there are only GCP-managed service account keys for each service account
* 1.5 Ensure that Service Account has no Admin privileges
* 1.6 Ensure that IAM users are not assigned the Service Account User or Service Account Token Creator roles at project level
* 1.9 Ensure that Cloud KMS cryptokeys are not anonymously or publicly accessible
* 1.10 Ensure KMS encryption keys are rotated within a period of 90 days
* 1.11 Ensure that Separation of duties is enforced while assigning KMS related roles to users
* 1.12 Ensure API keys are not created for a project
* 1.13 Ensure API keys are restricted to use by only specified Hosts and Apps
* 1.14 Ensure API keys are restricted to only APIs that application needs access
* 1.15 Ensure API keys are rotated every 90 days
* 3.1 Ensure that the default network does not exist in a project
* 3.2 Ensure legacy networks do not exist for a project
* 3.6 Ensure that SSH access is restricted from the internet??
* 3.7 Ensure that RDP access is restricted from the Internet??
* 4.1 Ensure that instances are not configured to use the default service account
* 4.2 Ensure that instances are not configured to use the default service account with full access to all Cloud APIs
* 4.3 Ensure "Block Project-wide SSH keys" is enabled for VM instances??
* 4.4 Ensure oslogin is enabled for a Project
* 4.5 Ensure 'Enable connecting to serial ports' is not enabled for VM Instance
* 4.6 Ensure that IP forwarding is not enabled on Instances
* 4.8 Ensure Compute instances are launched with Shielded VM enabled
* 4.9 Ensure that Compute instances do not have public IP addresses
* 6.1.1 Ensure that a MySQL database instance does not allow anyone to connect with administrative privileges
* 6.1.2 Ensure that the 'local_infile' database flag for a Cloud SQL Mysql instance is set to 'off'
* 6.2.1 Ensure that the 'log_checkpoints' database flag for Cloud SQL PostgreSQL instance is set to 'on'
* 6.2.3 Ensure that the 'log_disconnections' database flag for Cloud SQL PostgreSQL instance is set to 'on'
* 6.2.4 Ensure that the 'log_lock_waits' database flag for Cloud SQL PostgreSQL instance is set to 'on'
* 6.2.6 Ensure that the 'log_temp_files' database flag for Cloud SQL PostgreSQL instance is set to '0' (on)
* 6.4 Ensure that the Cloud SQL database instance requires all incoming connections to use SSL
* 6.5 Ensure that Cloud SQL database instances are not open to the world
* 6.6 Ensure that Cloud SQL database instances do not have public IPs
* 6.7 Ensure that Cloud SQL database instances are configured with automated backups
* 7.1 Ensure that BigQuery datasets are not anonymously or publicly accessible

### AWS CIS Benchmarks
