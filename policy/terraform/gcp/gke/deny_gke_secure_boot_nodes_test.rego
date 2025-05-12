package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_secureboot_nodes if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"node_config": {"shielded_instance_config": {"enable_secure_boot": true}},
	}}}}

	t.no_errors(deny_gke_secureboot_nodes_disabled) with input as inp
}

test_not_deny_secureboot_nodes_exclusions if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"//": "TF_GCP_22",
	}}}}

	t.no_errors(deny_gke_secureboot_nodes_disabled) with input as inp
}

test_deny_missing_secureboot_nodes_config if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"node_config": {"shielded_instance_config": {}},
	}}}}

	t.error_count(deny_gke_secureboot_nodes_disabled, 1) with input as inp
}

test_deny_secureboot_nodes_false if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"node_config": {"shielded_instance_config": {"enable_secure_boot": false}},
	}}}}

	t.error_count(deny_gke_secureboot_nodes_disabled, 1) with input as inp
}

test_deny_secureboot_nodes_false_string if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"location": "us-central1",
		"node_config": {"shielded_instance_config": {"enable_secure_boot": "false"}},
	}}}}

	t.error_count(deny_gke_secureboot_nodes_disabled, 1) with input as inp
}
