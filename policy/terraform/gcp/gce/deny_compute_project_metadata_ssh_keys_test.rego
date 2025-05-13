package terraform_gcp

import rego.v1

import data.testing as t

test_deny_compute_project_metadata_ssh_keys if {
	inp := {"resource": {
		"google_compute_project_metadata": {"default": {"metadata": {"ssh-keys": "bar"}}},
		"google_compute_project_metadata_item": {"default": {
			"key": "ssh-keys",
			"value": "bar",
		}},
	}}

	t.error_count(deny_compute_project_metadata_ssh_keys, 1) with input as inp
	t.error_count(deny_compute_project_metadata_item_ssh_keys, 1) with input as inp
}

test_allow_compute_project_metadata_ssh_keys_excepted if {
	inp := {"resource": {
		"google_compute_project_metadata": {"default": {
			"//": "TF_GCP_40",
			"metadata": {"ssh-keys": "bar"},
		}},
		"google_compute_project_metadata_item": {"default": {
			"//": "TF_GCP_40",
			"key": "ssh-keys",
			"value": "bar",
		}},
	}}

	t.no_errors(deny_compute_project_metadata_ssh_keys) with input as inp
	t.no_errors(deny_compute_project_metadata_item_ssh_keys) with input as inp
}
