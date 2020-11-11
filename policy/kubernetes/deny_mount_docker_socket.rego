package kubernetes

import data.kubernetes

# DENY(K8S_11): Deny mounting Docker socket
# Description: Exposing the socket gives container information and increases risk of exploit.
# Links:
#      
deny_mounting_docker_socket[msg] {
    id := "K8S_11"
	kubernetes.volumes[volume]
	volume.hostpath.path = "/var/run/docker.sock"
	msg = sprintf("%s: The %s %s is mounting the Docker socket", [id, kubernetes.kind, kubernetes.name])
}