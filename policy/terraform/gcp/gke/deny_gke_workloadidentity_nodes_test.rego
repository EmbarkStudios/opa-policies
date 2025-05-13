package terraform_gcp

import rego.v1

import data.testing as t

test_not_deny_workloadidentity_nodes if {
	inp := {"resource": {"google_container_node_pool": {
		"test1": {
			"cluster": "cluster1",
			"name": "test1",
			"node_config": {"workload_metadata_config": {"node_metadata": "GKE_METADATA_SERVER"}},
		},
		"test2": {
			"cluster": "cluster2",
			"name": "test2",
			"node_config": {"workload_metadata_config": {"mode": "GKE_METADATA"}},
		},
	}}}

	t.no_errors(deny_gke_workloadidentity_nodes_disabled) with input as inp
}

test_not_deny_workloadidentity_nodes_exclusions if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"//": "TF_GCP_25",
	}}}}

	t.no_errors(deny_gke_workloadidentity_nodes_disabled) with input as inp
}

test_deny_missing_workloadidentity_nodes_config if {
	inp := {"resource": {"google_container_node_pool": {"test": {
		"cluster": "cluster1",
		"name": "test",
		"node_config": {"workload_metadata_config": {}},
	}}}}

	t.error_count(deny_gke_workloadidentity_nodes_disabled, 1) with input as inp
}

test_deny_workloadidentity_nodes_unspecified if {
	inp := {"resource": {"google_container_node_pool": {
		"test1": {
			"cluster": "cluster1",
			"name": "test1",
			"node_config": {"workload_metadata_config": {"node_metadata": "UNSPECIFIED"}},
		},
		"test2": {
			"cluster": "cluster2",
			"name": "test2",
			"node_config": {"workload_metadata_config": {"mode": "UNSPECIFIED"}},
		},
	}}}

	t.error_count(deny_gke_workloadidentity_nodes_disabled, 2) with input as inp
}
