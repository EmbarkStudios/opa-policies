package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check34 := "TF_GCP_34"

gke_shielded_nodes(cluster) if {
	not cluster.enable_shielded_nodes
} else if {
	l.is_false(cluster.enable_shielded_nodes)
}

# DENY(TF_GCP_34) - google_container_cluster
deny_gke_shielded_nodes contains msg if {
	input.resource.google_container_cluster
	cluster := input.resource.google_container_cluster[_]

	not make_exception(check34, cluster)

	gke_shielded_nodes(cluster)

	msg = sprintf("%s: enabled_shielded_nodes is set to false in cluster %s. More info: %s", [check34, cluster.name, l.get_url(check34)])
}
