package terraform_gcp

import rego.v1

import data.testing as t

test_deny_default_sa_folder_member if {
	inp := {"resource": {"google_folder_iam_member": {"public": {
		"folder": "folder/1234",
		"role": "roles/viewer",
		"member": "88888888-compute@developer.gserviceaccount.com",
	}}}}

	t.error_count(deny_default_sa_member_on_folder_level, 1) with input as inp
}

test_allow_valid_sa_folder_member if {
	inp := {"resource": {"google_folder_iam_member": {
		"valid": {
			"folder": "folder/1234",
			"role": "roles/viewer",
			"member": "my-service@my-project.iam.gserviceaccount.com",
		},
		"excepted": {
			"//": "TF_GCP_37",
			"folder": "folder/1234",
			"role": "roles/viewer",
			"member": "88888888-compute@developer.gserviceaccount.com",
		},
	}}}

	t.no_errors(deny_default_sa_member_on_folder_level) with input as inp
}
