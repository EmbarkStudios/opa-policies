package kubernetes

import data.kubernetes

# DENY(K8S_06): Don't allow usage of default service account 
# Description:
# Links:
#  
valid_service_account() {
    kubernetes.pods[pod]
    all([pod.spec.serviceAccountName != "default"]) 
}
deny_default_service_account[msg] {
    id := "K8S_06"
    not valid_service_account
    msg = sprintf("%s: the %s %s is using a default service account", [id, kubernetes.kind, kubernetes.name])
}