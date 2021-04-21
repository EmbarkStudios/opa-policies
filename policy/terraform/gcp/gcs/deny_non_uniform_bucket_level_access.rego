package terraform_gcp

import data.terraform

check01 := "TF_GCP_01"

deny_non_uniform_level_access[msg] {
	input.resource.google_storage_bucket
	bucket := input.resource.google_storage_bucket[k]
	not make_exception(check01, bucket)
	not is_true(bucket.uniform_bucket_level_access)
	msg = sprintf("%s: Bucket %v should have uniform level access", [check01, k])
}
