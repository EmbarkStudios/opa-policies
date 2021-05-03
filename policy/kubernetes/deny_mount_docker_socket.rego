package kubernetes

import data.kubernetes
import data.lib as l

# DENY(K8S_10): Deny mounting Docker socket
# Description: Exposing the socket gives container information and increases risk of exploit.
# Links:
#
check10 := "K8S_10"

exception[rules] {
	make_exception(check10)
	rules = ["mounting_docker_socket"]
}

deny_mounting_docker_socket[msg] {
	kubernetes.volumes[volume]
	volume.hostPath.path = "/var/run/docker.sock"
	msg = sprintf("%s: The %s %s is mounting the Docker socket. More info: %s", [check10, kubernetes.kind, kubernetes.name, l.get_url(check10)])
}
