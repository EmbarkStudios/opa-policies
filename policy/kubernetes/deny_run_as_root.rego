package kubernetes

import data.kubernetes

# DENY(K8S_02): force run as non-root
# Description:
# Links:
#   https://kubesec.io/basics/containers-securitycontext-runasnonroot-true/
deny_run_container_as_root[msg] {
    id := "K8S_02"
	kubernetes.containers[container]
	not container.securityContext.runAsNonRoot = true
	msg = sprintf("%s: %s in the %s %s is running as root", [id, container.name, kubernetes.kind, kubernetes.name])
}