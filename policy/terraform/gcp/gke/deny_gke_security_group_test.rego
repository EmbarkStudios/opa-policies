package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_security_group if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"authenticator_groups_config": {"security_group": "gke-security-groups@test.com"},
	}}}}

	t.no_errors(deny_gke_security_group) with input as inp
}

test_not_deny_security_group_exclusions if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"//": "TF_GCP_28",
	}}}}

	t.no_errors(deny_gke_security_group) with input as inp
}

test_deny_missing_security_group_config if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"authenticator_groups_config": {"security_group": ""}
	}}}}

	t.error_count(deny_gke_security_group, 1) with input as inp
}

test_deny_security_group_wrong if {
	inp := {"resource": {"google_container_cluster": {"test": {
		"name": "test",
		"location": "us-central1",
		"authenticator_groups_config": {"security_group": "something@evilcorp.com"}
	}}}}

	t.error_count(deny_gke_security_group, 1) with input as inp
}
