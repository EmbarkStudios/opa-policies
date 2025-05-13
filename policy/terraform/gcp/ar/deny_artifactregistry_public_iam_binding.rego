package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check50 := "TF_GCP_50"

# DENY(TF_GCP_50)
deny_artifactregistry_public_iam_binding contains msg if {
	input.resource.google_artifact_registry_repository_iam_binding
	binding := input.resource.google_artifact_registry_repository_iam_binding[k]
	binding.members[member] == blacklisted_users[user]
	not make_exception(check50, binding)

	msg = sprintf("%s: public users (%s) not allowed for artifact registry. More info: %s", [check50, binding.members[member], l.get_url(check50)])
}
