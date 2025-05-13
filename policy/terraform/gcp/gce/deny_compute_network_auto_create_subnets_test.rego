package terraform_gcp

import rego.v1

import data.testing as t

test_deny_compute_network_auto_create_subnets if {
	inp := {"resource": {"google_compute_network": {
		"deny-1": {"name": "deny-me-1"},
		"deny-2": {
			"name": "deny-me-2",
			"auto_create_subnetworks": true,
		},
	}}}

	t.error_count(deny_compute_network_auto_create_subnets, 2) with input as inp
}

test_allow_compute_network_auto_create_subnets_disabled if {
	inp := {"resource": {"google_compute_network": {
		"valid": {
			"name": "valid",
			"auto_create_subnetworks": false,
		},
		"excepted": {
			"//": "TF_GCP_42",
			"name": "excepted",
		},
	}}}

	t.no_errors(deny_compute_network_auto_create_subnets) with input as inp
}
