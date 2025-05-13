package terraform_gcp

import rego.v1

import data.testing as t

test_deny_compute_instance_default_service_account if {
	inp := {"resource": {"google_compute_instance": {
		"no_svc_acc": {
			"name": "no_svc_acc",
			"machine_type": "e2-medium",
			"zone": "europe-west4-a",
			"boot_disk": {"initialize_params": {"image": "debian-cloud/debian-9"}},
		},
		"default_svc_acc": {
			"name": "default_svc_acc",
			"machine_type": "e2-medium",
			"zone": "europe-west4-a",
			"boot_disk": {"initialize_params": {"image": "debian-cloud/debian-9"}},
			"service_account": {"email": "000000000000-compute@developer.gserviceaccount.com"},
		},
	}}}

	t.error_count(deny_compute_instance_default_service_account, 2) with input as inp
}

test_allow_valid_compute_instance_service_account if {
	inp := {"resource": {"google_compute_instance": {
		"valid": {
			"name": "valid",
			"machine_type": "e2-medium",
			"zone": "europe-west4-a",
			"boot_disk": {"initialize_params": {"image": "debian-cloud/debian-9"}},
			"service_account": {"email": "my-service@my-project.iam.gserviceaccount.com"},
		},
		"excepted": {
			"name": "excepted",
			"machine_type": "e2-medium",
			"zone": "europe-west4-a",
			"boot_disk": {"initialize_params": {"image": "debian-cloud/debian-9"}},
			"//": "TF_GCP_36",
			"service_account": {"email": "000000000000-compute@developer.gserviceaccount.com"},
		},
	}}}

	t.no_errors(deny_compute_instance_default_service_account) with input as inp
}
