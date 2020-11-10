package kubernetes

import data.kubernetes

# DENY(K8S_10): Set CPU requests
# Description:
# Links:
#
warn_cpu_requests[msg] {
    id := "K8S_10"
	kubernetes.containers[container]
	not container.resources.requests.cpu
	msg = sprintf("%s: %s in the %s %s does not have a cpu request set", [id, container.name, kubernetes.kind, kubernetes.name])
}