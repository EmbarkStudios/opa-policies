package terraform_gcp

import data.terraform

check08 := "TF_GCP_08"

# DENY(TF_GCP_08)
deny_table_public_iam_member[msg] {
	input.resource.google_bigquery_table_iam_member
	member := input.resource.google_bigquery_table_iam_member[k]
	contains_element(blacklisted_users, member.member)
	not make_exception(check08, member)

	msg = sprintf("%s: public users not allowed for dataset: %s, table: %s", [check08, member.dataset_id, member.table_id])
}
