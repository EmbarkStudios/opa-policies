package terraform_gcp

import rego.v1

import data.lib as l
import data.terraform

check21 := "TF_GCP_21"

gke_autorepair_disabled(node_pool) if {
	not node_pool.management.auto_repair
} else if {
	l.is_false(node_pool.management.auto_repair)
}

# DENY(TF_GCP_21) - google_container_node_pool
deny_gke_autorepair_disabled contains msg if {
	input.resource.google_container_node_pool
	node_pool := input.resource.google_container_node_pool[_]

	not make_exception(check21, node_pool)

	gke_autorepair_disabled(node_pool)

	msg = sprintf("%s: auto_repair not enabled for node pool %s in cluster %s. More info: %s", [check21, node_pool.name, node_pool.cluster, l.get_url(check21)])
}
