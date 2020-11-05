package kubernetes

is_workload = any([input.kind == "DaemonSet", 
                   input.kind == "Deployment",
                   input.kind == "StatefulSet",
                   input.kind == "ReplicaSet"])

valid_namespace {
    input.metadata.namespace
    all([input.metadata.namespace != "default"]) 
}

valid_service_account {
    input.spec.template.spec.serviceAccountName
    all([input.spec.template.spec.serviceAccountName != "default"]) 
}