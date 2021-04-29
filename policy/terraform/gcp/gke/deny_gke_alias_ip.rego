package terraform_gcp

import data.lib as l
import data.terraform

check05 := "TF_GCP_05"

# DENY(TF_GCP_05) - google_container_cluster
deny_gke_alias_ip[msg] {
	input.resource.google_container_cluster
	cluster := input.resource.google_container_cluster[i]
	not input.resource.google_container_cluster[i].ip_allocation_policy
	not make_exception(check05, cluster)

	msg = sprintf("%s: alias ip not enabled for %s. More info: %s", [check05, cluster.name, l.get_url(check05)])
}
