package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_autoupgrade if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"management": {"auto_upgrade": true},
	}}}}

	t.no_errors(deny_gke_autoupgrade_disabled) with input as inp
}

test_not_deny_autoupgrade_exclusions if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"//": "TF_GCP_19",
	}}}}

	t.no_errors(deny_gke_autoupgrade_disabled) with input as inp
}

test_deny_missing_autoupgrade_config if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"management": {},
	}}}}

	t.error_count(deny_gke_autoupgrade_disabled, 1) with input as inp
}

test_deny_autoupgrade_false if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"management": {"auto_upgrade": false},
	}}}}

	t.error_count(deny_gke_autoupgrade_disabled, 1) with input as inp
}

test_deny_autoupgrade_false_string if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"management": {"auto_upgrade": "false"},
	}}}}

	t.error_count(deny_gke_autoupgrade_disabled, 1) with input as inp
}
