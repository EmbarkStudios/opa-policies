package terraform_gcp

import data.lib as l
import data.terraform

check13 := "TF_GCP_13"

# DENY(TF_GCP_13)
deny_iap_public_binding[msg] {
	input.resource.google_iap_web_iam_binding
	binding := input.resource.google_iap_web_iam_binding[k]
	binding.members[member] == blacklisted_users[user]
	not make_exception(check13, binding)

	msg = sprintf("%s: public users (%s) not allowed. More info: %s", [check13, binding.members[member], l.get_url(check13)])
}
