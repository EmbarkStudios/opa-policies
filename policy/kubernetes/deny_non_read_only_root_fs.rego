package kubernetes

import data.kubernetes

# DENY(K8S_14): Root filesystem should always be RO
# Description:
# Links:
#   https://kubesec.io/basics/containers-securitycontext-readonlyrootfilesystem-true
deny_non_read_only_root_fs[msg]{
    id := "K8S_14"
	kubernetes.containers[container]
	not container.securityContext.readOnlyRootFilesystem = true
	msg = sprintf("%s: %s in the %s %s is not using a read only root filesystem", [id, container.name, kubernetes.kind, kubernetes.name])
}