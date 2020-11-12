package kubernetes

import data.kubernetes

# DENY(K8S_02): force run as non-root
# Description:
# Links:
#   https://kubesec.io/basics/containers-securitycontext-runasnonroot-true/
check02 := "K8S_02"

exception[rules] {
    make_exception(check02)
    rules = ["run_container_as_root"]
}

deny_run_container_as_root[msg] {
	kubernetes.containers[container]
	not container.securityContext.runAsNonRoot = true
	msg = sprintf("%s: %s in the %s %s is running as root", [check02, container.name, kubernetes.kind, kubernetes.name])
}
