package kubernetes

import data.kubernetes

# DENY(K8S_17):
# Description:
# Links:
#   https://kubesec.io/basics/spec-hostpid/
deny_sharing_host_pid[msg] {
    id := "K8S_17"
	kubernetes.pods[pod]
	pod.spec.hostPID
	msg = sprintf("The %s %s is sharing the host PID", [kubernetes.kind, kubernetes.name])
}