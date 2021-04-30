package terraform_gcp

import data.terraform

check33 := "TF_GCP_33"

gke_integrity_monitoring_nodes_disabled(node_pool) {
	not node_pool.node_config.shielded_instance_config.enable_integrity_monitoring
} else {
	is_false(node_pool.node_config.shielded_instance_config.enable_integrity_monitoring)
}

# DENY(TF_GCP_33) - google_container_node_pool
deny_gke_integrity_monitoring_nodes_disabled[msg] {
	input.resource.google_container_node_pool
	node_pool := input.resource.google_container_node_pool[_]

	not make_exception(check33, node_pool)

	gke_integrity_monitoring_nodes_disabled(node_pool)

	msg = sprintf("%s: enable_integrity_monitoring set to false for node pool %s in cluster %s. More info: %s", [check33, node_pool.name, node_pool.cluster, get_url(check33)])
}
