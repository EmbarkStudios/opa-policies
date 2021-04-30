package terraform_gcp

import data.lib as l
import data.terraform

check37 := "TF_GCP_37"

# DENY(TF_GCP_37)
deny_default_sa_member_on_folder_level[msg] {
	input.resource.google_folder_iam_member
	member := input.resource.google_folder_iam_member[i]

	not make_exception(check37, member)

	regex.match(default_service_account_regexp, member.member)

	msg = sprintf("%s: default service account [%s] not allowed on folder level. More info: %s", [check37, member.member, l.get_url(check37)])
}
