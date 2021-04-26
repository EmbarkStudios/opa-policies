package terraform_gcp

import data.terraform

check19 := "TF_GCP_19"

# DENY(TF_GCP_20) - google_container_node_pool
deny_gke_autoupgrade_disabled[msg] {
	input.resource.google_container_node_pool
	node_pool := input.resource.google_container_node_pool[i]
	not input.resource.google_container_node_pool[i].management.auto_upgrade
	not make_exception(check19, node_pool)

	msg = sprintf("%s: auto_upgrade not enabled for node pool %s in cluster %s. More info: %s", [check19, node_pool.name, node_pool.cluster, get_url(check19)])
}
