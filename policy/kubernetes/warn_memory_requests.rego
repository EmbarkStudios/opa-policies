package kubernetes

import data.kubernetes

# DENY(K8S_14): Set Memory requests
# Description:
# Links:
#
warn_memory_requests[msg] {
    id := "K8S_14"
	kubernetes.containers[container]
	not container.resources.requests.memory
	msg = sprintf("%s: %s in the %s %s does not have a memory requests set", [id, container.name, kubernetes.kind, kubernetes.name])
}
