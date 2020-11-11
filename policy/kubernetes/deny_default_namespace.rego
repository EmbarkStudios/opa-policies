package kubernetes

import data.kubernetes

# DENY(K8S_04): Using the default namespace leads to unpredictable behavior
# Description: Resources in k8s should be segregated using namespaces. 
#              Using the default namespace makes it more difficult to apply RBAC and similar controls
# Links:
#   CIS Controls 1.5.1, 5.7.4 (the default namespace should not be used)
valid_namespace {
    input.metadata.namespace
    all([input.metadata.namespace != "default"]) 
}

deny_default_namespace[msg] {
    id := "K8S_04"
    not valid_namespace
    msg = sprintf("%s: the %s %s is using the default namespace", [id, kubernetes.kind, kubernetes.name])
}