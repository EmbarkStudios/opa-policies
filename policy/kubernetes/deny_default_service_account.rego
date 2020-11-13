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

valid_service_account() {
    kubernetes.pods[pod]
    all([pod.spec.serviceAccountName != "default"]) 
}
deny_default_service_account[msg] {
    any([is_workload, is_pod, is_job])
    not valid_service_account
    msg = sprintf("%s: the %s %s is using a default service account", [checks06, kubernetes.kind, kubernetes.name])
}
