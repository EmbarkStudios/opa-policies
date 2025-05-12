package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check18 := "TF_GCP_18"

# DENY(TF_GCP_18)
deny_impersonation_roles_org_binding contains msg if {
	input.resource.google_organization_iam_binding
	binding := input.resource.google_organization_iam_binding[i]
	binding.role == impersonation_roles[role]
	not make_exception(check18, binding)

	msg = sprintf("%s: impersonation role [%s] not allowed on org level. More info: %s", [check18, binding.role, l.get_url(check18)])
}

deny_impersonation_roles_folder_binding contains msg if {
	input.resource.google_folder_iam_binding
	binding := input.resource.google_folder_iam_binding[i]
	binding.role == impersonation_roles[role]
	not make_exception(check18, binding)

	msg = sprintf("%s: impersonation role [%s] not allowed on folder level. More info: %s", [check18, binding.role, l.get_url(check18)])
}

deny_impersonation_roles_proj_binding contains msg if {
	input.resource.google_project_iam_binding
	binding := input.resource.google_project_iam_binding[i]
	binding.role == impersonation_roles[role]
	not make_exception(check18, binding)

	msg = sprintf("%s: impersonation role [%s] not allowed on project level. More info: %s", [check18, binding.role, l.get_url(check18)])
}
