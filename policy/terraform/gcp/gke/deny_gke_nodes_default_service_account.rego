package terraform_gcp

import data.lib as l
import data.terraform

check41 = "TF_GCP_41"

nodes_using_default_svc_acc(gke) {
	not gke.node_config.service_account
} else {
	regex.match(default_service_account_regexp, gke.node_config.service_account)
}

deny_gke_node_pool_nodes_default_service_account[msg] {
	input.resource.google_container_node_pool

	node_pool := input.resource.google_container_node_pool[_]

	not make_exception(check41, node_pool)

	nodes_using_default_svc_acc(node_pool)

	msg = sprintf("%s: node pool %s is using the default service account. More info: %s", [check41, node_pool.name, l.get_url(check41)])
}
