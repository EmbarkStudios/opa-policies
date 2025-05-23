package kubernetes

import rego.v1

import data.kubernetes
import data.lib as l

# DENY(K8S_20): Liveness probes
# Description:
# Links:
#
check20 := "K8S_20"

exception contains rules if {
	make_exception(check20)
	rules = ["liveness_probes"]
}

warn_liveness_probes contains msg if {
	is_workload
	kubernetes.containers[container]
	not container.livenessProbe
	msg = sprintf("%s: %s in the %s %s does not have a liveness probe. More info: %s", [check20, container.name, kubernetes.kind, kubernetes.name, l.get_url(check20)])
}
