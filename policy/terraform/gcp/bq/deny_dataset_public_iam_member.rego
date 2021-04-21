package terraform_gcp

import data.terraform

check07 := "TF_GCP_07"

# DENY(TF_GCP_07)
deny_dataset_public_iam_member[msg] {
	input.resource.google_bigquery_dataset_iam_member
	member := input.resource.google_bigquery_dataset_iam_member[k]
	contains_element(blacklisted_users, member.member)
	not make_exception(check07, member)

	msg = sprintf("%s: public users not allowed for dataset: %s", [check07, member.dataset_id])
}
