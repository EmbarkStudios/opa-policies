package kubernetes

import data.kubernetes

# DENY(K8S_01): Do not allow privilege escalation
# Description:
# Links:
#   https://kubesec.io/basics/containers-securitycontext-privileged-true/
deny_privilege_escalation_in_containers[msg] {
    id := "K8S_01"
	kubernetes.containers[container]
	container.securityContext.privileged
	msg = sprintf("%s: %s in the %s %s is privileged", [id, container.name, kubernetes.kind, kubernetes.name])
}