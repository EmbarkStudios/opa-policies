package kubernetes

import data.kubernetes

# DENY(K8S_08): Set CPU limits
# Description:
# Links:
#
check08 := "K8S_08"

exception[rules] {
    make_exception(check08)
    rules = ["cpu_limits"]
}

warn_cpu_limits[msg] {
	kubernetes.containers[container]
	not container.resources.limits.cpu
	msg = sprintf("%s: %s in the %s %s does not have a cpu limits set", [check08, container.name, kubernetes.kind, kubernetes.name])
}