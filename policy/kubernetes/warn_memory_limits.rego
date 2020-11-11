package kubernetes

import data.kubernetes

# DENY(K8S_13): Set Memory limits
# Description:
# Links:
#
warn_memory_limits[msg] {
    id := "K8S_13"
	kubernetes.containers[container]
	not container.resources.limits.memory
	msg = sprintf("%s: %s in the %s %s does not have a memory limit set", [id, container.name, kubernetes.kind, kubernetes.name])
}
