package terraform_gcp

import data.terraform

check24 := "TF_GCP_24"

cluster_node_metadata := "GKE_METADATA_SERVER"

gke_workloadidentity_masters_disabled(cluster) {
	not cluster.node_config.workload_metadata_config.node_metadata
} else {
	cluster.node_config.workload_metadata_config.node_metadata != cluster_node_metadata
}

# DENY(TF_GCP_24) - google_container_cluster
deny_gke_workloadidentity_masters_disabled[msg] {
	input.resource.google_container_cluster
	cluster := input.resource.google_container_cluster[_]

	not make_exception(check24, cluster)

	gke_workloadidentity_masters_disabled(cluster)

	msg = sprintf("%s: Workload Identity not enabled for masters in cluster %s. More info: %s", [check24, cluster.name, get_url(check24)])
}
