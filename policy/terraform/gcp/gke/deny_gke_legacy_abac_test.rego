package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_legacy_abac_false if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"enable_legacy_abac": false,
	}}}}

	t.no_errors(deny_gke_legacy_abac) with input as inp
}

test_not_deny_legacy_abac_false_string if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"enable_legacy_abac": "false",
	}}}}

	t.no_errors(deny_gke_legacy_abac) with input as inp
}

test_not_deny_legacy_abac_missing if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
	}}}}

	t.no_errors(deny_gke_legacy_abac) with input as inp
}

test_not_deny_legacy_abac_exclusions if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"//": "TF_GCP_45",
		"enable_legacy_abac": "true",
	}}}}

	t.no_errors(deny_gke_legacy_abac) with input as inp
}

test_deny_legacy_abac_true if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"enable_legacy_abac": true,
	}}}}

	t.error_count(deny_gke_legacy_abac, 1) with input as inp
}

test_deny_gke_legacy_abac_true_string if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"enable_legacy_abac": "true",
	}}}}

	t.error_count(deny_gke_legacy_abac, 1) with input as inp
}
