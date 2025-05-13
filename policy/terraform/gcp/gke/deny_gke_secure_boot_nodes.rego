package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check22 := "TF_GCP_22"

gke_secureboot_nodes_disabled(node_pool) if {
	not node_pool.node_config.shielded_instance_config.enable_secure_boot
} else if {
	l.is_false(node_pool.node_config.shielded_instance_config.enable_secure_boot)
}

# DENY(TF_GCP_22) - google_container_node_pool
deny_gke_secureboot_nodes_disabled contains msg if {
	input.resource.google_container_node_pool
	node_pool := input.resource.google_container_node_pool[_]

	not make_exception(check22, node_pool)

	gke_secureboot_nodes_disabled(node_pool)

	msg = sprintf("%s: secure_boot not enabled for node pool %s in cluster %s. More info: %s", [check22, node_pool.name, node_pool.cluster, l.get_url(check22)])
}
