package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check03 := "TF_GCP_03"

# DENY(TF_GCP_03)
deny_public_iam_binding contains msg if {
	input.resource.google_storage_bucket_iam_binding
	binding := input.resource.google_storage_bucket_iam_binding[k]
	binding.members[member] == blacklisted_users[user]
	not make_exception(check03, binding)

	msg = sprintf("%s: public users (%s) not allowed for bucket: %s. More info: %s", [check03, binding.members[member], binding.bucket, l.get_url(check03)])
}
