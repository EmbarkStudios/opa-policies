package kubernetes

import data.kubernetes

# DENY(K8S_08): Do not allow adding capabilities, SYSADMIN
# Description: This setting enables CAP_SYS_ADMIN linux capability, which is similar to root
# Links:
#   https://kubernetes.io/docs/tasks/configure-pod-container/security-context/
#   https://kubesec.io/basics/containers-securitycontext-capabilities-add-index-sys-admin/

deny_adding_sysadmin_capabilities[msg] {
    id := "K8S_08"
	kubernetes.containers[container]
	kubernetes.added_capability(container, "CAP_SYS_ADMIN")
	msg = sprintf("%s: %s in the %s %s has SYS_ADMIN capabilities", [id, container.name, kubernetes.kind, kubernetes.name])
}