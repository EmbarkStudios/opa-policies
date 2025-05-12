package terraform_gcp

import rego.v1

import data.testing as t

test_deny_gke_node_pool_nodes_default_service_account if {
	inp := {"resource": {"google_container_node_pool": {
		"not-defined": {
			"name": "not-defined",
			"location": "us-central1",
		},
		"default": {
			"name": "default",
			"location": "us-central1",
			"node_config": {"service_account": "000000000000-compute@developer.gserviceaccount.com"},
		},
	}}}

	t.error_count(deny_gke_node_pool_nodes_default_service_account, 2) with input as inp
}

test_allow_valid_gke_node_pool_nodes_service_account if {
	inp := {"resource": {"google_container_node_pool": {
		"valid": {
			"name": "valid",
			"location": "us-central1",
			"node_config": {"service_account": "my-service@my-project.iam.gserviceaccount.com"},
		},
		"excepted": {
			"name": "excepted",
			"location": "us-central1",
			"//": "TF_GCP_41",
			"node_config": {"service_account": "000000000000-compute@developer.gserviceaccount.com"},
		},
	}}}

	t.no_errors(deny_gke_node_pool_nodes_default_service_account) with input as inp
}
