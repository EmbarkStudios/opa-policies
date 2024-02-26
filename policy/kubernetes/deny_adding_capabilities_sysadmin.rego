package kubernetes

import data.kubernetes
import data.lib as l

# DENY(K8S_05): Do not allow adding capabilities, SYSADMIN
# Description: This setting enables CAP_SYS_ADMIN linux capability, which is similar to root
# Links:
#   https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
#   https://kubesec.io/basics/containers-securitycontext-capabilities-add-index-sys-admin/
checks05 := "K8S_05"

exception[rules] {
	make_exception(checks05)
	rules = ["adding_sysadmin_capabilities"]
}

deny_adding_sysadmin_capabilities[msg] {
	kubernetes.containers[container]
	kubernetes.added_capability(container, "CAP_SYS_ADMIN")
	msg = sprintf("%s: %s in the %s %s has SYS_ADMIN capabilities. More info: %s", [checks05, container.name, kubernetes.kind, kubernetes.name, l.get_url(checks05)])
}
