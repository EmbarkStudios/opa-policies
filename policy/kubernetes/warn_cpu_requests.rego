package kubernetes

import data.kubernetes

# DENY(K8S_09): Set CPU requests
# Description:
# Links:
#
check09 := "K8S_09"

exception[rules] {
    make_exception(check09)
    rules = ["cpu_requests"]
}
warn_cpu_requests[msg] {
	kubernetes.containers[container]
	not container.resources.requests.cpu
	msg = sprintf("%s: %s in the %s %s does not have a cpu request set", [check09, container.name, kubernetes.kind, kubernetes.name])
}
