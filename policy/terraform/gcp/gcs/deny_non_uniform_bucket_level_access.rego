package terraform_gcp

# DENY(TF_GCP_01)

exception[k] {
    input.resource.google_storage_bucket
    bucket := input.resource.google_storage_bucket[k]
    bucket["//"] == "TF_GCP_01"
}

deny_non_uniform_level_access[msg] {
    id := "TF_GCP_01"
    input.resource.google_storage_bucket
    bucket := input.resource.google_storage_bucket[k]
    not exception[k]
    not exists_and_true_string(bucket, "uniform_bucket_level_access")
    msg = sprintf("%s: Bucket %v should have uniform level access", [id, k])
}
