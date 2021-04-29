package terraform_gcp

import data.terraform

check29 := "TF_GCP_29"

gke_remove_default_node_pool(cluster) {
	not cluster.remove_default_node_pool
} else {
	is_false(cluster.remove_default_node_pool)
}

# DENY(TF_GCP_29) - google_container_cluster
deny_gke_remove_default_node_pool[msg] {
	input.resource.google_container_cluster
	cluster := input.resource.google_container_cluster[_]

	not make_exception(check29, cluster)

	gke_remove_default_node_pool(cluster)

	msg = sprintf("%s: remove_default_node_pool is disabled in cluster %s. More info: %s", [check29, cluster.name, get_url(check29)])
}
