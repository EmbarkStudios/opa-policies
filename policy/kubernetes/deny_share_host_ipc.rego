package kubernetes

import rego.v1

import data.kubernetes
import data.lib as l

# DENY(K8S_16):
# Description:
# Links:
#   https://kubesec.io/basics/spec-hostipc/
check16 := "K8S_16"

exception contains rules if {
	make_exception(check16)
	rules = ["sharing_host_ipc"]
}

deny_sharing_host_ipc contains msg if {
	kubernetes.pods[pod]
	pod.spec.hostIPC
	msg = sprintf("%s: %s %s is sharing the host IPC namespace. More info: %s", [check16, kubernetes.kind, kubernetes.name, l.get_url(check16)])
}
