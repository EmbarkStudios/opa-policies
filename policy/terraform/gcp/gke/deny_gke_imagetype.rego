package terraform_gcp

import data.lib as l
import data.terraform

check27 := "TF_GCP_27"

image_type := "COS"

gke_imagetype(node_pool) {
	not node_pool.node_config.image_type
} else {
	node_pool.node_config.image_type != image_type
}

# DENY(TF_GCP_27) - google_container_node_pool
deny_gke_imagetype[msg] {
	input.resource.google_container_node_pool
	node_pool := input.resource.google_container_node_pool[_]

	not make_exception(check27, node_pool)

	gke_imagetype(node_pool)

	msg = sprintf("%s: Wrong image_type specified in node_pool %s in cluster %s. More info: %s", [check27, node_pool.name, node_pool.cluster, l.get_url(check27)])
}
