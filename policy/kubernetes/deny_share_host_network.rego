package kubernetes

import data.lib as l
import data.kubernetes

# DENY(K8S_18):
# Description:
# Links:
#   https://kubesec.io/basics/spec-hostnetwork/
check18 := "K8S_18"

exception[rules] {
    make_exception(check18)
    rules = ["sharing_host_network"]
}

deny_sharing_host_network[msg] {
	kubernetes.pods[pod]
	pod.spec.hostNetwork
	msg = sprintf("%s: The %s %s is connected to the host network. More info %s", [check18, kubernetes.kind, kubernetes.name, l.get_url(check18)])
}
