package kubernetes

import data.kubernetes

# DENY(K8S_07): 
# Description: Using the default service account can lead to pods being granted implicit permissions
# serviceAccount is deprecated and serviceAccountName should be used instead
deny_deprecated_service_account[msg] {
    id := "K8S_07"
    kubernetes.pods[pod]
    pod.spec.serviceAccount
    msg = sprintf("%s: the %s %s is using the deprecated serviceaccount, use serviceAccountName", [id, kubernetes.kind, kubernetes.name])
}