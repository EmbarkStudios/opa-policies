package kubernetes

import data.kubernetes

# DENY(K8S_21): Readiness probes
# Description:
# Links:
#
check21 := "K8S_21"

exception[rules] {
    make_exception(check21)
    rules = ["readiness_probes"]
}

warn_readiness_probes[msg] {
	is_workload
	kubernetes.containers[container]
	not container.readinessProbe
	msg = sprintf("%s: %s in the %s %s does not have a readiness probe", [check21, container.name, kubernetes.kind, kubernetes.name])
}
