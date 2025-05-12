package terraform_gcp

import rego.v1

import data.testing as t

test_deny_compute_instance_oslogin_disabled if {
	inp := {"resource": {"google_compute_instance": {
		"not_set": {
			"name": "not_set",
			"machine_type": "e2-medium",
			"zone": "europe-west4-a",
			"boot_disk": {"initialize_params": {"image": "debian-cloud/debian-9"}},
		},
		"disabled": {
			"name": "disabled",
			"machine_type": "e2-medium",
			"zone": "europe-west4-a",
			"boot_disk": {"initialize_params": {"image": "debian-cloud/debian-9"}},
			"metadata": {"enable-oslogin": "FALSE"},
		},
	}}}

	t.error_count(deny_compute_instance_oslogin_disabled, 2) with input as inp
}

test_allow_compute_instance_oslogin_enabled if {
	inp := {"resource": {"google_compute_instance": {
		"valid": {
			"name": "valid",
			"machine_type": "e2-medium",
			"zone": "europe-west4-a",
			"boot_disk": {"initialize_params": {"image": "debian-cloud/debian-9"}},
			"metadata": {"enable-oslogin": "TRUE"},
		},
		"excepted": {
			"name": "excepted",
			"machine_type": "e2-medium",
			"zone": "europe-west4-a",
			"boot_disk": {"initialize_params": {"image": "debian-cloud/debian-9"}},
			"//": "TF_GCP_39",
		},
	}}}

	t.no_errors(deny_compute_instance_oslogin_disabled) with input as inp
}
