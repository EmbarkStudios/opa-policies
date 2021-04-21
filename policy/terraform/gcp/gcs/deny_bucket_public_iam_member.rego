package terraform_gcp

import data.terraform

check02 := "TF_GCP_02"

# DENY(TF_GCP_02)
deny_bucket_public_iam_member[msg] {
	input.resource.google_storage_bucket_iam_member
	member := input.resource.google_storage_bucket_iam_member[k]
	contains_element(blacklisted_users, member.member)
	not make_exception(check02, member)

	msg = sprintf("%s: public users not allowed for bucket: %s", [check02, member.bucket])
}
