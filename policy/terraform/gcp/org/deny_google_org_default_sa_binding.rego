package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check16 := "TF_GCP_16"

# DENY(TF_GCP_16)
deny_default_sa_binding_on_org_level contains msg if {
	input.resource.google_organization_iam_binding
	binding := input.resource.google_organization_iam_binding[i]
	member := binding.members[m]
	regex.match(default_service_account_regexp, member)
	not make_exception(check16, binding)

	msg = sprintf("%s: default service account [%s] not allowed on org level. More info: %s", [check16, member, l.get_url(check16)])
}
