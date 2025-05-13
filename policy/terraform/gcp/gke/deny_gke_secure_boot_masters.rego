package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check23 := "TF_GCP_23"

gke_secureboot_masters_disabled(cluster) if {
	not cluster.node_config.shielded_instance_config.enable_secure_boot
} else if {
	l.is_false(cluster.node_config.shielded_instance_config.enable_secure_boot)
}

# DENY(TF_GCP_23) - google_container_cluster
deny_gke_secureboot_masters_disabled contains msg if {
	input.resource.google_container_cluster
	cluster := input.resource.google_container_cluster[_]

	not make_exception(check23, cluster)

	gke_secureboot_masters_disabled(cluster)

	msg = sprintf("%s: secure_boot not enabled for masters in cluster %s. More info: %s", [check23, cluster.name, l.get_url(check23)])
}
