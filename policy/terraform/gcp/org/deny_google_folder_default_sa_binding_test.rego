package terraform_gcp

import rego.v1

import data.testing as t

test_deny_default_sa_folder_binding if {
	inp := {"resource": {"google_folder_iam_binding": {"public": {
		"folder": "folder/1234",
		"role": "roles/viewer",
		"members": ["88888888-compute@developer.gserviceaccount.com"],
	}}}}

	t.error_count(deny_default_sa_binding_on_folder_level, 1) with input as inp
}

test_allow_valid_sa_folder_binding if {
	inp := {"resource": {"google_folder_iam_binding": {
		"valid": {
			"folder": "folder/1234",
			"role": "roles/viewer",
			"members": ["my-service@my-project.iam.gserviceaccount.com"],
		},
		"excepted": {
			"//": "TF_GCP_38",
			"folder": "folder/1234",
			"role": "roles/viewer",
			"members": ["88888888-compute@developer.gserviceaccount.com"],
		},
	}}}

	t.no_errors(deny_default_sa_binding_on_folder_level) with input as inp
}
