package kubernetes

import rego.v1

import data.kubernetes
import data.lib as l

# DENY(K8S_21): Readiness probes
# Description:
# Links:
#
check21 := "K8S_21"

exception contains rules if {
	make_exception(check21)
	rules = ["readiness_probes"]
}

warn_readiness_probes contains msg if {
	is_workload
	kubernetes.containers[container]
	not container.readinessProbe
	msg = sprintf("%s: %s in the %s %s does not have a readiness probe. More info: %s", [check21, container.name, kubernetes.kind, kubernetes.name, l.get_url(check21)])
}
