package terraform_gcp

import data.lib as l
import data.terraform

check27 := "TF_GCP_27"

allowed_image_types := {"cos", "cos_containerd"}

gke_imagetype(node_pool) {
	not node_pool.node_config.image_type
} else {
	not is_string(node_pool.node_config.image_type)
} else {
	image_type := node_pool.node_config.image_type
	not l.contains_element(allowed_image_types, lower(image_type))
}

# DENY(TF_GCP_27) - google_container_node_pool
deny_gke_imagetype[msg] {
	input.resource.google_container_node_pool
	node_pool := input.resource.google_container_node_pool[_]

	not make_exception(check27, node_pool)

	gke_imagetype(node_pool)

	msg = sprintf("%s: Wrong image_type specified in node_pool %s in cluster %s. More info: %s", [check27, node_pool.name, node_pool.cluster, l.get_url(check27)])
}
