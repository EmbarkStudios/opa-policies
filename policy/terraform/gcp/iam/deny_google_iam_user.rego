package terraform_gcp

import data.lib as l
import data.terraform

check44 := "TF_GCP_44"

# DENY(TF_GCP_44)
deny_user_org_member[msg] {
	input.resource.google_organization_iam_member
	member := input.resource.google_organization_iam_member[i]
	not make_exception(check44, member)
    contains(member.member, "user:")

	msg = sprintf("%s: prefer group/service_account over user, [%s] not allowed on org level. More info: %s", [check44, member.member, l.get_url(check44)])
}

deny_user_folder_member[msg] {
	input.resource.google_folder_iam_member
	member := input.resource.google_folder_iam_member[i]
	not make_exception(check44, member)
    contains(member.member, "user:")

	msg = sprintf("%s: prefer group/service_account over user, [%s] not allowed on folder level. More info: %s", [check44, member.member, l.get_url(check44)])
}

deny_user_proj_member[msg] {
	input.resource.google_project_iam_member
	member := input.resource.google_project_iam_member[i]
	not make_exception(check44, member)
    contains(member.member, "user:")

	msg = sprintf("%s: prefer group/service_account over user, [%s] not allowed on project level. More info: %s", [check44, member.member, l.get_url(check44)])
}
