package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_shielded_nodes if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"enable_shielded_nodes": true,
	}}}}

	t.no_errors(deny_gke_shielded_nodes) with input as inp
}

test_not_deny_shielded_nodes_exclusions if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"//": "TF_GCP_34",
	}}}}

	t.no_errors(deny_gke_shielded_nodes) with input as inp
}

test_deny_shielded_nodes_false if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"enable_shielded_nodes": false,
	}}}}

	t.error_count(deny_gke_shielded_nodes, 1) with input as inp
}

test_deny_shielded_nodes_false_string if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"enable_shielded_nodes": "false",
	}}}}

	t.error_count(deny_gke_shielded_nodes, 1) with input as inp
}
