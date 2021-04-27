package terraform_gcp

import data.terraform

check19 := "TF_GCP_19"

<<<<<<< HEAD
gke_autoupgrade_disabled(node_pool) {
	not node_pool.management.auto_upgrade
} else {
	is_false(node_pool.management.auto_upgrade)
}

=======
>>>>>>> 8abee4810519a8d728d6de9946b6cdd73e8b91e8
# DENY(TF_GCP_19) - google_container_node_pool
deny_gke_autoupgrade_disabled[msg] {
	input.resource.google_container_node_pool
	node_pool := input.resource.google_container_node_pool[i]
<<<<<<< HEAD

	not make_exception(check19, node_pool)

	gke_autoupgrade_disabled(node_pool)

=======
	not input.resource.google_container_node_pool[i].management.auto_upgrade
	not make_exception(check19, node_pool)

>>>>>>> 8abee4810519a8d728d6de9946b6cdd73e8b91e8
	msg = sprintf("%s: auto_upgrade not enabled for node pool %s in cluster %s. More info: %s", [check19, node_pool.name, node_pool.cluster, get_url(check19)])
}
