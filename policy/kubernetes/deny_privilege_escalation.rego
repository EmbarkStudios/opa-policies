package kubernetes

import data.kubernetes
import data.lib as l

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
	container.securityContext.allowPrivilegeEscalation
	msg = sprintf("%s: %s in the %s %s is privileged. More info: %s", [check01, container.name, kubernetes.kind, kubernetes.name, l.get_url(check01)])
}
