package terraform_gcp

import data.lib as l
import data.terraform

check17 := "TF_GCP_17"

# DENY(TF_GCP_17)
deny_impersonation_roles_org_member[msg] {
	input.resource.google_organization_iam_member
	member := input.resource.google_organization_iam_member[i]
	member.role == impersonation_roles[role]
	not make_exception(check17, member)

	msg = sprintf("%s: impersonation role [%s] on member [%s] not allowed on org level. More info: %s", [check17, member.role, member.member, l.get_url(check17)])
}

deny_impersonation_roles_folder_member[msg] {
	input.resource.google_folder_iam_member
	member := input.resource.google_folder_iam_member[i]
	member.role == impersonation_roles[role]
	not make_exception(check17, member)

	msg = sprintf("%s: impersonation role [%s] on member [%s] not allowed on folder level. More info: %s", [check17, member.role, member.member, l.get_url(check17)])
}

deny_impersonation_roles_proj_member[msg] {
	input.resource.google_project_iam_member
	member := input.resource.google_project_iam_member[i]
	member.role == impersonation_roles[role]
	not make_exception(check17, member)

	msg = sprintf("%s: impersonation role [%s] on member [%s] not allowed on project level. More info: %s", [check17, member.role, member.member, l.get_url(check17)])
}
