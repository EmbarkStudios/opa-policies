package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_secureboot_masters if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"node_config": {"shielded_instance_config": {"enable_secure_boot": true}},
	}}}}

	t.no_errors(deny_gke_secureboot_masters_disabled) with input as inp
}

test_not_deny_secureboot_masters_exclusions if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"//": "TF_GCP_23",
	}}}}

	t.no_errors(deny_gke_secureboot_masters_disabled) with input as inp
}

test_deny_missing_secureboot_masters_config if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"node_config": {"shielded_instance_config": {}},
	}}}}

	t.error_count(deny_gke_secureboot_masters_disabled, 1) with input as inp
}

test_deny_secureboot_masters_false if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"node_config": {"shielded_instance_config": {"enable_secure_boot": false}},
	}}}}

	t.error_count(deny_gke_secureboot_masters_disabled, 1) with input as inp
}

test_deny_secureboot_masters_false_string if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"node_config": {"shielded_instance_config": {"enable_secure_boot": "false"}},
	}}}}

	t.error_count(deny_gke_secureboot_masters_disabled, 1) with input as inp
}
