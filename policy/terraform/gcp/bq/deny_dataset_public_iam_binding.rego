package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check09 := "TF_GCP_09"

# DENY(TF_GCP_09)
deny_dataset_public_iam_binding contains msg if {
	input.resource.google_bigquery_dataset_iam_binding
	binding := input.resource.google_bigquery_dataset_iam_binding[k]
	binding.members[member] == blacklisted_users[user]
	not make_exception(check09, binding)

	msg = sprintf("%s: public users (%s) not allowed for dataset: %s. More info: %s", [check09, binding.members[member], binding.dataset_id, l.get_url(check09)])
}
