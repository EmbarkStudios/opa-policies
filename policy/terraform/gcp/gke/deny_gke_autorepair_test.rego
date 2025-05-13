package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_autorepair if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"management": {"auto_repair": true},
	}}}}

	t.no_errors(deny_gke_autorepair_disabled) with input as inp
}

test_not_deny_autorepair_exclusions if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"//": "TF_GCP_21",
	}}}}

	t.no_errors(deny_gke_autorepair_disabled) with input as inp
}

test_deny_missing_autorepair_config if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"management": {},
	}}}}

	t.error_count(deny_gke_autorepair_disabled, 1) with input as inp
}

test_deny_autorepair_false if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"management": {"auto_repair": false},
	}}}}

	t.error_count(deny_gke_autorepair_disabled, 1) with input as inp
}

test_deny_autorepair_false_string if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"management": {"auto_repair": "false"},
	}}}}

	t.error_count(deny_gke_autorepair_disabled, 1) with input as inp
}
