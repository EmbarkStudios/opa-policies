package kubernetes

import data.kubernetes

# DENY(K8S_07): 
# Description: Using the default service account can lead to pods being granted implicit permissions
# serviceAccount is deprecated and serviceAccountName should be used instead
checks07 := "K8S_07"

exception[rules] {
    make_exception(checks07)
    rules = ["deprecated_service_account"]
}

deny_deprecated_service_account[msg] {
    kubernetes.pods[pod]
    pod.spec.serviceAccount
    msg = sprintf("%s: the %s %s is using the deprecated serviceaccount, use serviceAccountName", [checks07, kubernetes.kind, kubernetes.name])
}
