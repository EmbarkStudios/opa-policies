package kubernetes

import data.lib as l
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

# TODO also check the containers security context, as that takes precedence
deny_run_container_as_root[msg] {
	kubernetes.pods[pod]
	not pod.spec.securityContext.runAsNonRoot
	msg = sprintf("%s: %s %s is running as root. More info: %s", [check02, kubernetes.kind, kubernetes.name, l.get_url(check02)])
}
