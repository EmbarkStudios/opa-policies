package kubernetes

import data.kubernetes

# DENY(K8S_12): Set Memory limits
# Description:
# Links:
#
check12 := "K8S_12"

exception[rules] {
    make_exception(check12)
    rules = ["memory_limits"]
}

warn_memory_limits[msg] {
	kubernetes.containers[container]
	not container.resources.limits.memory
	msg = sprintf("%s: %s in the %s %s does not have a memory limit set", [check12, container.name, kubernetes.kind, kubernetes.name])
}
