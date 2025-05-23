package kubernetes

import rego.v1

import data.kubernetes
import data.lib as l

# DENY(K8S_13): Set Memory requests
# Description:
# Links:
#
check13 := "K8S_13"

exception contains rules if {
	make_exception(check13)
	rules = ["memory_requests"]
}

warn_memory_requests contains msg if {
	kubernetes.containers[container]
	not container.resources.requests.memory
	msg = sprintf("%s: %s in the %s %s does not have a memory requests set. More info: %s", [check13, container.name, kubernetes.kind, kubernetes.name, l.get_url(check13)])
}
