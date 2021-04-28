package terraform_gcp

import data.lib as l
import data.terraform

check15 := "TF_GCP_15"

# DENY(TF_GCP_15)
deny_default_sa_member_on_org_level[msg] {
	input.resource.google_organization_iam_member
	member := input.resource.google_organization_iam_member[i]
	regex.match(default_service_account_regexp, member.member)
	not make_exception(check15, member)

	msg = sprintf("%s: default service account [%s] not allowed on org level. More info: %s", [check15, member.member, l.get_url(check15)])
}
