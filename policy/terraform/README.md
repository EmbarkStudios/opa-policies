# Terraform checks

|ID|Severity|Name|Framework
|---|---|---|---|
|TF_GCP_01|DENY|Bucket without uniform_level_access|   |
|TF_GCP_02|DENY|Bucket IAM Member allUsers & allAuthenticatedUsers|   |
|TF_GCP_03|DENY|Bucket IAM Binding allUsers & allAuthenticatedUsers|   |


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
