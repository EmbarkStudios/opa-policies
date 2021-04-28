package kubernetes

import data.kubernetes

# DENY(K8S_06): Don't allow usage of default service account 
# Description:
# Links:
# 
checks06 := "K8S_06"

exception[rules] {
    make_exception(checks06)
    rules = ["default_service_account"]
}

invalid_service_account(pod) {
    not pod.spec.serviceAccountName
} else {
    sa := pod.spec.serviceAccountName
    sa == "default"
}

deny_default_service_account[msg] {
    kubernetes.pods[pod]
    any([invalid_service_account(pod)])
    msg = sprintf("%s: the %s %s is using a default service account", [checks06, kubernetes.kind, kubernetes.name])
}
