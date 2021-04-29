package terraform_gcp

import data.terraform

check28 := "TF_GCP_28"
security_group := "gke-security-groups@embark-studios.com"

gke_security_group(cluster) {
	not cluster.authenticator_groups_config.security_group
} else {
	cluster.authenticator_groups_config.security_group != security_group
}

# DENY(TF_GCP_28) - google_container_cluster
deny_gke_security_group[msg] {
	input.resource.google_container_cluster
	cluster := input.resource.google_container_cluster[_]

	not make_exception(check28, cluster)

	gke_security_group(cluster)

	msg = sprintf("%s: Wrong security_group specified in cluster %s. More info: %s", [check28, cluster.name, get_url(check28)])
}
