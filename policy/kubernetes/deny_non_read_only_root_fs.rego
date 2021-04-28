package kubernetes

import data.lib as l
import data.kubernetes

# DENY(K8S_14): Root filesystem should always be RO
# Description:
# Links:
#   https://kubesec.io/basics/containers-securitycontext-readonlyrootfilesystem-true
check14 := "K8S_14"

exception[rules] {
    make_exception(check14)
    rules = ["non_read_only_root_fs"]
}

deny_non_read_only_root_fs[msg]{
	kubernetes.containers[container]
	not container.securityContext.readOnlyRootFilesystem = true
	msg = sprintf("%s: %s in the %s %s is not using a read only root filesystem. More info: %s", [check14, container.name, kubernetes.kind, kubernetes.name, l.get_url(check14)])
}
