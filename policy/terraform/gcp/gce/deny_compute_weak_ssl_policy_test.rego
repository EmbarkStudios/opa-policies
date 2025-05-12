package terraform_gcp

import rego.v1

import data.testing as t

test_deny_compute_weak_ssl_policy if {
	inp := {"resource": {"google_compute_ssl_policy": {"p1": {
		"name": "p1",
		"profile": "COMPATIBLE",
	}}}}

	t.error_count(deny_compute_weak_ssl_policy, 1) with input as inp
}

test_not_deny_compute_weak_ssl_policy_when_exception if {
	inp := {"resource": {"google_compute_ssl_policy": {"p1": {
		"//": "TF_GCP_11",
		"name": "p1",
		"profile": "COMPATIBLE",
	}}}}

	t.no_errors(deny_compute_weak_ssl_policy) with input as inp
}

test_deny_compute_weak_ssl_policy_multiple if {
	inp := {"resource": {"google_compute_ssl_policy": {
		"compatible": {
			"//": "TF_GCP_11",
			"name": "p1",
			"profile": "COMPATIBLE",
		},
		"compatible2": {
			"name": "p2",
			"profile": "COMPATIBLE",
		},
		"modern": {
			"name": "p3",
			"profile": "MODERN",
		},
		"restricted": {
			"name": "p3",
			"profile": "RESTRICTED",
		},
	}}}

	t.error_count(deny_compute_weak_ssl_policy, 1) with input as inp
}
