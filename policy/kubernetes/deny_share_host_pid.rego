package kubernetes

import data.kubernetes
import data.lib as l

# DENY(K8S_17):
# Description:
# Links:
#   https://kubesec.io/basics/spec-hostpid/
check17 := "K8S_17"

exception[rules] {
	make_exception(check17)
	rules = ["sharing_host_pid"]
}

deny_sharing_host_pid[msg] {
	kubernetes.pods[pod]
	pod.spec.hostPID
	msg = sprintf("%s: The %s %s is sharing the host PID. More info: %s", [check17, kubernetes.kind, kubernetes.name, l.get_url(check17)])
}
