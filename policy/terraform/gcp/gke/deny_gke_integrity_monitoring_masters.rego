package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check32 := "TF_GCP_32"

gke_integrity_monitoring_masters_disabled(cluster) if {
	not cluster.node_config.shielded_instance_config.enable_integrity_monitoring
} else if {
	l.is_false(cluster.node_config.shielded_instance_config.enable_integrity_monitoring)
}

# DENY(TF_GCP_32) - google_container_cluster
deny_gke_integrity_monitoring_masters_disabled contains msg if {
	input.resource.google_container_cluster
	cluster := input.resource.google_container_cluster[_]

	not make_exception(check32, cluster)

	gke_integrity_monitoring_masters_disabled(cluster)

	msg = sprintf("%s: enable_integrity_monitoring not enabled for masters in cluster %s. More info: %s", [check32, cluster.name, l.get_url(check32)])
}
