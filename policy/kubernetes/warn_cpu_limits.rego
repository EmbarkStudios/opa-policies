package kubernetes

import data.kubernetes

# DENY(K8S_09): Set CPU limits
# Description:
# Links:
#
warn_cpu_limits[msg] {
    id := "K8S_09"
	kubernetes.containers[container]
	not container.resources.limits.cpu
	msg = sprintf("%s: %s in the %s %s does not have a cpu limits set", [id, container.name, kubernetes.kind, kubernetes.name])
}