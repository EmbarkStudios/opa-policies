package kubernetes

import data.kubernetes

# DENY(K8S_15):
# Description:
# Links:
#   https://kubesec.io/basics/spec-hostaliases/
deny_managing_host_alias[msg] {
    id := "K8S_15"
	kubernetes.pods[pod]
	pod.spec.hostAliases
	msg = sprintf("%s: The %s %s is managing host aliases", [id, kubernetes.kind, kubernetes.name])
}