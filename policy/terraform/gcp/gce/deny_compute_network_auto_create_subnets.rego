package terraform_gcp

import data.lib as l
import data.terraform

check42 := "TF_GCP_42"

invalid_auto_create_subnets(network) {
	not l.has_key(network, "auto_create_subnetworks")
} else {
	network.auto_create_subnetworks != false
}

deny_compute_network_auto_create_subnets[msg] {
	input.resource.google_compute_network
	network := input.resource.google_compute_network[_]

	not make_exception(check42, network)

	invalid_auto_create_subnets(network)

	msg = sprintf("%s: compute network: %s has auto_create_subnetworks enabled. More info: %s", [check42, network.name, l.get_url(check42)])
}
