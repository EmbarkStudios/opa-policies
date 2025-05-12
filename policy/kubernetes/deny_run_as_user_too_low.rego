package kubernetes

import rego.v1

import data.kubernetes
import data.lib as l

# DENY(K8S_19):
# Description:
# Links:
#   https://kubesec.io/basics/containers-securitycontext-runasuser/
check19 := "K8S_19"

exception contains rules if {
	make_exception(check19)
	rules = ["run_as_user_too_low"]
}

deny_run_as_user_too_low contains msg if {
	kubernetes.containers[container]
	to_number(container.securityContext.runAsUser) < 10000
	msg = sprintf("%s: %s in the %s %s has a UID of less than 10000. More info: %s", [check19, container.name, kubernetes.kind, kubernetes.name, l.get_url(check19)])
}
