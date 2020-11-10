package kubernetes

import data.kubernetes

# DENY(K8S_15): 
# Description: 
# Links:
#   https://kubesec.io/basics/containers-securitycontext-runasuser/
deny_run_as_user_too_low[msg] {
    id := "K8S_15"
	kubernetes.containers[container]
	container.securityContext.runAsUser < 10000
	msg = sprintf("%s: %s in the %s %s has a UID of less than 10000", [id, container.name, kubernetes.kind, kubernetes.name])
}