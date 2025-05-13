package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_remove_default_node_pool if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"remove_default_node_pool": true,
	}}}}

	t.no_errors(deny_gke_remove_default_node_pool) with input as inp
}

test_not_deny_remove_default_node_pool_exclusions if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"//": "TF_GCP_29",
	}}}}

	t.no_errors(deny_gke_remove_default_node_pool) with input as inp
}

test_deny_remove_default_node_pool_false if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"remove_default_node_pool": false,
	}}}}

	t.error_count(deny_gke_remove_default_node_pool, 1) with input as inp
}

test_deny_remove_default_node_pool_false_string if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"remove_default_node_pool": "false",
	}}}}

	t.error_count(deny_gke_remove_default_node_pool, 1) with input as inp
}
