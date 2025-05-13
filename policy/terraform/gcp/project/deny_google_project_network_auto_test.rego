package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_project_auto_created_network_with_exclusions if {
	inp := {"resource": {"google_project": {"p": {
		"//": "TF_GCP_06",
		"name": "p",
		"project_id": "project_id",
	}}}}

	t.no_errors(deny_project_auto_created_network) with input as inp
}

test_deny_project_auto_created_network if {
	inp := {"resource": {"google_project": {"p": {
		"name": "p",
		"project_id": "project_id",
	}}}}

	t.error_count(deny_project_auto_created_network, 1) with input as inp
}

test_deny_project_auto_created_network_with_property if {
	inp := {"resource": {"google_project": {"p": {
		"name": "p",
		"project_id": "project_id",
		"auto_create_network": true,
	}}}}

	t.error_count(deny_project_auto_created_network, 1) with input as inp
}

test_not_deny_project_auto_created_network if {
	inp := {"resource": {"google_project": {"p": {
		"name": "p",
		"project_id": "project_id",
		"auto_create_network": false,
	}}}}

	t.no_errors(deny_project_auto_created_network) with input as inp
}

test_not_deny_project_auto_created_network_string if {
	inp := {"resource": {"google_project": {"p": {
		"name": "p",
		"project_id": "project_id",
		"auto_create_network": "false",
	}}}}

	t.no_errors(deny_project_auto_created_network) with input as inp
}
