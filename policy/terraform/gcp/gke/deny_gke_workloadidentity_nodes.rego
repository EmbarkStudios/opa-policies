package terraform_gcp

import data.terraform

check25 := "TF_GCP_25"
node_metadata := "GKE_METADATA_SERVER"

gke_workloadidentity_nodes_disabled(node_pool) {
	not node_pool.node_config.workload_metadata_config.node_metadata
} else {
	node_pool.node_config.workload_metadata_config.node_metadata != node_metadata
}

# DENY(TF_GCP_25) - google_container_node_pool
deny_gke_workloadidentity_nodes_disabled[msg] {
	input.resource.google_container_node_pool
	node_pool := input.resource.google_container_node_pool[_]

	not make_exception(check25, node_pool)

	gke_workloadidentity_nodes_disabled(node_pool)

	msg = sprintf("%s: Workload Identity not enabled for node pool %s in cluster %s. More info: %s", [check25, node_pool.name, node_pool.cluster, get_url(check25)])
}
