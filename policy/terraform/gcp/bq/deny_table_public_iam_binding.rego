package terraform_gcp

import data.terraform

check10 := "TF_GCP_10"

# DENY(TF_GCP_10)
deny_table_public_iam_binding[msg] {
	input.resource.google_bigquery_table_iam_binding
	binding := input.resource.google_bigquery_table_iam_binding[k]
	binding.members[member] == blacklisted_users[user]
	not make_exception(check10, binding)

	msg = sprintf("%s: public users (%s) not allowed for dataset: %s, table: %s", [check10, binding.members[member], binding.dataset_id, binding.table_id])
}
