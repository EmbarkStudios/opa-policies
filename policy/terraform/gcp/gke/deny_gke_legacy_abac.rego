package terraform_gcp

import data.lib as l
import data.terraform

check45 := "TF_GCP_45"

# DENY(TF_GCP_45) - google_container_cluster
deny_gke_legacy_abac[msg] {
	input.resource.google_container_cluster
	cluster := input.resource.google_container_cluster[_]

	not make_exception(check45, cluster)
	l.is_true(cluster.enable_legacy_abac)

	msg = sprintf("%s: legacy abac is enabled for cluster %s. More info: %s", [check45, cluster.name, l.get_url(check45)])
}
