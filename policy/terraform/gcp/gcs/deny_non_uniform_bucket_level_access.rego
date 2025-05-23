package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check01 := "TF_GCP_01"

deny_non_uniform_level_access contains msg if {
	input.resource.google_storage_bucket
	bucket := input.resource.google_storage_bucket[k]
	not make_exception(check01, bucket)
	not l.is_true(bucket.uniform_bucket_level_access)
	msg = sprintf("%s: Bucket %v should have uniform level access. More info: %s", [check01, k, l.get_url(check01)])
}
