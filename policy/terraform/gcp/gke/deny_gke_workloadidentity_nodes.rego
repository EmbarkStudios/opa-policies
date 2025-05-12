package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check25 := "TF_GCP_25"

deprecated_allowed_value := "GKE_METADATA_SERVER"

new_allowed_value := "GKE_METADATA"

gke_workloadidentity_nodes_disabled(node_pool) if {
	node_pool.node_config.workload_metadata_config.mode
	node_pool.node_config.workload_metadata_config.mode != new_allowed_value
} else if {
	node_pool.node_config.workload_metadata_config.node_metadata
	node_pool.node_config.workload_metadata_config.node_metadata != deprecated_allowed_value
} else if {
	not node_pool.node_config.workload_metadata_config.mode
	not node_pool.node_config.workload_metadata_config.node_metadata
}

# DENY(TF_GCP_25) - google_container_node_pool
deny_gke_workloadidentity_nodes_disabled contains msg if {
	input.resource.google_container_node_pool
	node_pool := input.resource.google_container_node_pool[_]

	not make_exception(check25, node_pool)

	gke_workloadidentity_nodes_disabled(node_pool)

	msg = sprintf("%s: Workload Identity not enabled for node pool %s in cluster %s. More info: %s", [check25, node_pool.name, node_pool.cluster, l.get_url(check25)])
}
