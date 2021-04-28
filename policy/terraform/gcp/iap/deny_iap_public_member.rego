package terraform_gcp

import data.lib as l
import data.terraform

check12 := "TF_GCP_12"

# DENY(TF_GCP_12)
deny_iap_public_member[msg] {
	input.resource.google_iap_web_iam_member
	member := input.resource.google_iap_web_iam_member[k]
	l.contains_element(blacklisted_users, member.member)
	not make_exception(check12, member)

	msg = sprintf("%s: public users (%s) not allowed. More info: %s", [check12, member.member, l.get_url(check12)])
}
