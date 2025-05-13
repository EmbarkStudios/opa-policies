package kubernetes

import rego.v1

import data.kubernetes
import data.lib as l

# DENY(K8S_18):
# Description:
# Links:
#   https://kubesec.io/basics/spec-hostnetwork/
check18 := "K8S_18"

exception contains rules if {
	make_exception(check18)
	rules = ["sharing_host_network"]
}

deny_sharing_host_network contains msg if {
	kubernetes.pods[pod]
	pod.spec.hostNetwork
	msg = sprintf("%s: The %s %s is connected to the host network. More info %s", [check18, kubernetes.kind, kubernetes.name, l.get_url(check18)])
}
