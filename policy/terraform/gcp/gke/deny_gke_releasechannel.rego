package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check26 := "TF_GCP_26"

gke_releasechannel_disabled(cluster) if {
	not cluster.release_channel.channel
} else if {
	cluster.release_channel.channel != "REGULAR"
}

# DENY(TF_GCP_26) - google_container_cluster
deny_gke_releasechannel_disabled contains msg if {
	input.resource.google_container_cluster
	cluster := input.resource.google_container_cluster[_]

	not make_exception(check26, cluster)

	gke_releasechannel_disabled(cluster)

	msg = sprintf("%s: release_channel missing or not set to \"REGULAR\" in cluster %s. More info: %s", [check26, cluster.name, l.get_url(check26)])
}
