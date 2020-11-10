package kubernetes

import data.kubernetes

# DENY(K8S_18):
# Description:
# Links:
#   https://kubesec.io/basics/spec-hostnetwork/
deny_sharing_host_network[msg] {
    id := "K8S_18"
	kubernetes.pods[pod]
	pod.spec.hostNetwork
	msg = sprintf("%s: The %s %s is connected to the host network", [id, kubernetes.kind, kubernetes.name])
}