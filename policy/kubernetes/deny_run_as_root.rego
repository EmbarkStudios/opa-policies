package kubernetes

import rego.v1

import data.kubernetes
import data.lib as l

# DENY(K8S_02): force run as non-root
# Description:
# Links:
#   https://kubesec.io/basics/containers-securitycontext-runasnonroot-true/
check02 := "K8S_02"

exception contains rules if {
	make_exception(check02)
	rules = ["run_container_as_root"]
}

podOrContainerRunningAsRoot(pod) if {
	not pod.spec.securityContext.runAsNonRoot
	containers := kubernetes.pod_containers(pod)
	container := containers[_]
	not container.securityContext.runAsNonRoot
}

deny_run_container_as_root contains msg if {
	kubernetes.pods[pod]
	podOrContainerRunningAsRoot(pod)
	msg = sprintf("%s: %s %s is running as root. More info: %s", [check02, kubernetes.kind, kubernetes.name, l.get_url(check02)])
}
