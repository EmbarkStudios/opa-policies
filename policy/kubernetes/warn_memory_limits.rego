package kubernetes

import rego.v1

import data.kubernetes
import data.lib as l

# DENY(K8S_12): Set Memory limits
# Description:
# Links:
#
check12 := "K8S_12"

exception contains rules if {
	make_exception(check12)
	rules = ["memory_limits"]
}

warn_memory_limits contains msg if {
	kubernetes.containers[container]
	not container.resources.limits.memory
	msg = sprintf("%s: %s in the %s %s does not have a memory limit set. More info: %s", [check12, container.name, kubernetes.kind, kubernetes.name, l.get_url(check12)])
}
