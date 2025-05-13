package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check07 := "TF_GCP_07"

# DENY(TF_GCP_07)
deny_dataset_public_iam_member contains msg if {
	input.resource.google_bigquery_dataset_iam_member
	member := input.resource.google_bigquery_dataset_iam_member[_]
	l.contains_element(blacklisted_users, member.member)
	not make_exception(check07, member)

	msg = sprintf("%s: public users not allowed for dataset: %s. More info: %s", [check07, member.dataset_id, l.get_url(check07)])
}
