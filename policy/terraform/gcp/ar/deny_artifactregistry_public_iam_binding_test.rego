package terraform_gcp

import rego.v1

import data.testing as t

test_deny_artifactregistry_public_iam_binding if {
	inp := {"resource": {"google_artifact_registry_repository_iam_binding": {"public-member": {
		"repository": "ds",
		"role": "roles/viewer",
		"members": ["allUsers", "group:test@embark.dev"],
	}}}}

	t.error_count(deny_artifactregistry_public_iam_binding, 1) with input as inp
}

test_not_deny_artifactregistry_public_iam_binding_when_exception if {
	inp := {"resource": {"google_artifact_registry_repository_iam_binding": {"public-member": {
		"//": "TF_GCP_50",
		"repository": "test",
		"role": "roles/viewer",
		"members": ["allUsers", "group:test@embark.dev"],
	}}}}

	t.no_errors(deny_artifactregistry_public_iam_binding) with input as inp
}

test_deny_artifactregistry_public_iam_binding_more_members if {
	inp := {"resource": {"google_artifact_registry_repository_iam_binding": {
		"public-member": {
			"//": "TF_GCP_50",
			"repository": "test1",
			"role": "roles/viewer",
			"members": ["allUsers", "group:test@embark.dev"],
		},
		"should be blocked": {
			"repository": "test2",
			"role": "roles/viewer",
			"members": ["allUsers", "group:test@embark.dev"],
		},
		"should not be blocked": {
			"repository": "test3",
			"role": "roles/viewer",
			"members": ["group:test@embark.dev"],
		},
	}}}

	t.error_count(deny_artifactregistry_public_iam_binding, 1) with input as inp
}
