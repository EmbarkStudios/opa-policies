package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check28 := "TF_GCP_28"

gke_security_group(cluster) if {
	not cluster.authenticator_groups_config.security_group
} else if {
	not regex.match("gke-security-groups@.*", cluster.authenticator_groups_config.security_group)
}

# DENY(TF_GCP_28) - google_container_cluster
deny_gke_security_group contains msg if {
	input.resource.google_container_cluster
	some c
	cluster := input.resource.google_container_cluster[c]

	not make_exception(check28, cluster)

	gke_security_group(cluster)

	msg = sprintf("%s: Wrong security_group specified in cluster %s. More info: %s", [check28, cluster.name, l.get_url(check28)])
}
