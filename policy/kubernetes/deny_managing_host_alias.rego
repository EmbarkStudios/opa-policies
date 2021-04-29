package kubernetes

import data.lib as l
import data.kubernetes

# DENY(K8S_15):
# Description:
# Links:
#   https://kubesec.io/basics/spec-hostaliases/
check15 := "K8S_15"

exception[rules] {
    make_exception(check15)
    rules = ["managing_host_alias"]
}

deny_managing_host_alias[msg] {
	kubernetes.pods[pod]
	pod.spec.hostAliases
	msg = sprintf("%s: The %s %s is managing host aliases. More info: %s", [check15, kubernetes.kind, kubernetes.name, l.get_url(check15)])
}
