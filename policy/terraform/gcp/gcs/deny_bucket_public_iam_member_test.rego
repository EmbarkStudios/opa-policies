package terraform_gcp

import rego.v1

import data.testing as t

test_deny_bucket_public_iam_member if {
	inp := {"resource": {"google_storage_bucket_iam_member": {"public-member": {
		"bucket": "a bucket",
		"role": "roles/storage.admin",
		"member": "allUsers",
	}}}}

	t.error_count(deny_bucket_public_iam_member, 1) with input as inp
}

test_not_deny_bucket_public_iam_member_when_exception if {
	inp := {"resource": {"google_storage_bucket_iam_member": {"public-member": {
		"//": "TF_GCP_02",
		"bucket": "embark-public",
		"role": "roles/storage.admin",
		"member": "allUsers",
	}}}}

	t.no_errors(deny_bucket_public_iam_member) with input as inp
}

test_deny_bucket_public_iam_member_more_members if {
	inp := {"resource": {"google_storage_bucket_iam_member": {
		"public-member": {
			"//": "TF_GCP_02",
			"bucket": "embark-public",
			"role": "roles/storage.admin",
			"member": "allUsers",
		},
		"should be blocked": {
			"bucket": "a bucket",
			"role": "roles/storage.admin",
			"member": "allUsers",
		},
	}}}

	t.error_count(deny_bucket_public_iam_member, 1) with input as inp
}
