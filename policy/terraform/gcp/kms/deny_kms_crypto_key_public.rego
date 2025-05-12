package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check30 := "TF_GCP_30"

deny_kms_crypto_key_iam_member_public contains msg if {
	input.resource.google_kms_crypto_key_iam_member
	iam := input.resource.google_kms_crypto_key_iam_member[key]

	not make_exception(check30, iam)

	iam.member == blacklisted_users[user]

	msg = sprintf("%s: KMS Crypto Key %s is accessible to public. More info: %s", [check30, key, l.get_url(check30)])
}

check31 := "TF_GCP_31"

deny_kms_crypto_key_iam_binding_public contains msg if {
	input.resource.google_kms_crypto_key_iam_binding
	iam := input.resource.google_kms_crypto_key_iam_binding[key]

	not make_exception(check31, iam)

	iam.members[member] == blacklisted_users[user]

	msg = sprintf("%s: KMS Crypto Key %s is accessible to public. More info: %s", [check31, key, l.get_url(check30)])
}
