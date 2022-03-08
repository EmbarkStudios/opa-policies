package terraform_gcp

import data.lib as l
import data.terraform

check51 := "TF_GCP_51"

# DENY(TF_GCP_51)
deny_artifactregistry_public_iam_member[msg] {
	input.resource.google_artifact_registry_repository_iam_member
	member := input.resource.google_artifact_registry_repository_iam_member[_]
	l.contains_element(blacklisted_users, member.member)
	not make_exception(check51, member)

	msg = sprintf("%s: public users not allowed for artifact registry. More info: %s", [check51, l.get_url(check51)])
}
