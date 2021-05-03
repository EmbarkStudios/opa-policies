package terraform_gcp

import data.terraform

check27 := "TF_GCP_27"

image_type := "COS"

gke_imagetype(cluster) {
	not cluster.node_config.image_type
} else {
	cluster.node_config.image_type != image_type
}

# DENY(TF_GCP_27) - google_container_cluster
deny_gke_imagetype[msg] {
	input.resource.google_container_cluster
	cluster := input.resource.google_container_cluster[_]

	not make_exception(check27, cluster)

	gke_imagetype(cluster)

	msg = sprintf("%s: Wrong image_type specified in cluster %s. More info: %s", [check27, cluster.name, get_url(check27)])
}
