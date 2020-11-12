package kubernetes

import data.kubernetes

# DENY(K8S_01): Do not allow privilege escalation
# Description:
# Links:
#   https://kubesec.io/basics/containers-securitycontext-privileged-true/
check01 := "K8S_01"

exception[rules] {
    make_exception(check01)
    rules = ["privilege_escalation_in_containers"]
}

deny_privilege_escalation_in_containers[msg] {
	kubernetes.containers[container]
	container.securityContext.privileged
	msg = sprintf("%s: %s in the %s %s is privileged", [check01, container.name, kubernetes.kind, kubernetes.name])
}
