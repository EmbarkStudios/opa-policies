package kubernetes

import data.kubernetes

# DENY(K8S_16):
# Description:
# Links:
#   https://kubesec.io/basics/spec-hostipc/
deny_sharing_host_ipc[msg] {
    id := "K8S_16"
	kubernetes.pods[pod]
	pod.spec.hostIPC
	msg = sprintf("%s: %s %s is sharing the host IPC namespace", [id, kubernetes.kind, kubernetes.name])
}