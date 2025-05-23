package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check10 := "TF_GCP_10"

# DENY(TF_GCP_10)
deny_table_public_iam_binding contains msg if {
	input.resource.google_bigquery_table_iam_binding
	binding := input.resource.google_bigquery_table_iam_binding[k]
	binding.members[member] == blacklisted_users[user]
	not make_exception(check10, binding)

	msg = sprintf("%s: public users (%s) not allowed for dataset: %s, table: %s. More info: %s", [check10, binding.members[member], binding.dataset_id, binding.table_id, l.get_url(check10)])
}
