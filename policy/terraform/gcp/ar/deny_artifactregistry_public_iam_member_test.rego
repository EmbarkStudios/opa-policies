package terraform_gcp

import rego.v1

import data.testing as t

test_deny_artifactregistry_public_iam_member if {
	inp := {"resource": {"google_artifact_registry_repository_iam_member": {"public-member": {
		"repository": "test",
		"role": "roles/viewer",
		"member": "allUsers",
	}}}}

	t.error_count(deny_artifactregistry_public_iam_member, 1) with input as inp
}

test_not_deny_artifactregistry_public_iam_member_when_exception if {
	inp := {"resource": {"google_artifact_registry_repository_iam_member": {"public-member": {
		"//": "TF_GCP_51",
		"repository": "test",
		"role": "roles/viewer",
		"member": "allUsers",
	}}}}

	t.no_errors(deny_artifactregistry_public_iam_member) with input as inp
}

test_deny_artifactregistry_public_iam_member_more_members if {
	inp := {"resource": {"google_artifact_registry_repository_iam_member": {
		"public-member": {
			"//": "TF_GCP_51",
			"repository": "test1",
			"role": "roles/viewer",
			"member": "allUsers",
		},
		"should be blocked": {
			"repository": "test2",
			"role": "roles/viewer",
			"member": "allUsers",
		},
	}}}

	t.error_count(deny_artifactregistry_public_iam_member, 1) with input as inp
}
