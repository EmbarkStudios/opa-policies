package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check02 := "TF_GCP_02"

# DENY(TF_GCP_02)
deny_bucket_public_iam_member contains msg if {
	input.resource.google_storage_bucket_iam_member
	member := input.resource.google_storage_bucket_iam_member[k]
	l.contains_element(blacklisted_users, member.member)
	not make_exception(check02, member)

	msg = sprintf("%s: public users not allowed for bucket: %s. More info: %s", [check02, member.bucket, l.get_url(check02)])
}
