package terraform_gcp

import rego.v1

import data.testing as t

test_deny_missing_shielded_instance_config if {
	inp := {"resource": {"google_compute_instance": {"i1": {"name": "deny_me"}}}}

	t.error_count(deny_compute_instance_unshielded_vm, 1) with input as inp
}

test_deny_shielded_instance_config_without_secure_boot_enabled if {
	inp := {"resource": {"google_compute_instance": {"i1": {
		"name": "deny_me",
		"shielded_instance_config": {},
	}}}}

	t.error_count(deny_compute_instance_unshielded_vm, 1) with input as inp
}

test_deny_shielded_instance_config_with_secure_boot_disabled if {
	inp := {"resource": {"google_compute_instance": {"i1": {
		"name": "deny_me",
		"shielded_instance_config": {"secure_boot_enabled": false},
	}}}}

	t.error_count(deny_compute_instance_unshielded_vm, 1) with input as inp
}

test_deny_shielded_instance_config_with_secure_boot_disabled_string if {
	inp := {"resource": {"google_compute_instance": {"i1": {
		"name": "deny_me",
		"shielded_instance_config": {"secure_boot_enabled": "false"},
	}}}}

	t.error_count(deny_compute_instance_unshielded_vm, 1) with input as inp
}

test_not_deny_with_exception if {
	inp := {"resource": {"google_compute_instance": {
		"i1": {
			"//": "TF_GCP_20",
			"name": "allow_me",
			"shielded_instance_config": {"secure_boot_enabled": false},
		},
		"i2": {
			"//": "TF_GCP_20",
			"name": "allow_me",
			"shielded_instance_config": {},
		},
		"i3": {
			"//": "TF_GCP_20",
			"name": "allow_me",
		},
	}}}

	t.no_errors(deny_compute_instance_unshielded_vm) with input as inp
}

test_not_deny_secure_boot_enabled if {
	inp := {"resource": {"google_compute_instance": {"i2": {
		"name": "allow_me",
		"shielded_instance_config": {"secure_boot_enabled": "true"},
	}}}}

	t.no_errors(deny_compute_instance_unshielded_vm) with input as inp
}
