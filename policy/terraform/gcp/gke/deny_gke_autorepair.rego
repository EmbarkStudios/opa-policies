package terraform_gcp

import data.terraform

check21 := "TF_GCP_21"

gke_autorepair_disabled(node_pool) {
	not node_pool.management.auto_repair
} else {
	is_false(node_pool.management.auto_repair)
}

# DENY(TF_GCP_21) - google_container_node_pool
deny_gke_autorepair_disabled[msg] {
	input.resource.google_container_node_pool
	node_pool := input.resource.google_container_node_pool[_]

	not make_exception(check21, node_pool)

	gke_autorepair_disabled(node_pool)

	msg = sprintf("%s: auto_repair not enabled for node pool %s in cluster %s. More info: %s", [check21, node_pool.name, node_pool.cluster, get_url(check21)])
}
