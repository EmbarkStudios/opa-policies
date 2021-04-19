package terraform_gcp

import data.terraform

check04 := "TF_GCP_04"

# DENY(TF_GCP_04)
deny_iam_policy[msg] {
	input.data.google_iam_policy
	binding := input.data.google_iam_policy[i].binding[j]
	binding.members[member] == blacklisted_users[user]
	not make_exception(check04, binding)

	msg = sprintf("%s: public users (%s) not allowed for policy", [check04, binding.members[member]])
}
