package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_releasechannel if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"release_channel": {"channel": "REGULAR"},
	}}}}

	t.no_errors(deny_gke_releasechannel_disabled) with input as inp
}

test_not_deny_releasechannel_exclusions if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"//": "TF_GCP_26",
	}}}}

	t.no_errors(deny_gke_releasechannel_disabled) with input as inp
}

test_deny_missing_releasechannel_config if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"release_channel": {"channel": {}},
	}}}}

	t.error_count(deny_gke_releasechannel_disabled, 1) with input as inp
}

test_deny_releasechannel_wrong if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"release_channel": {"channel": "RAPID"},
	}}}}

	t.error_count(deny_gke_releasechannel_disabled, 1) with input as inp
}
