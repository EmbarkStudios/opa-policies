package kubernetes

# References:
# https://www.stackrox.com/post/2020/05/kubernetes-security-101/
# https://kubernetes.io/blog/2016/08/security-best-practices-kubernetes-deployment/

# DENY: force run as non-root
deny[msg] {
    is_workload
    not input.spec.template.spec.securityContext.runAsNonRoot = true
    msg = "Containers must not run as root"
}

# DENY: force run as non-root (CronJob)
deny[msg] {
    input.kind == "CronJob"
    not input.spec.jobTemplate.spec.template.spec.securityContext.runAsNonRoot = true
    msg = "Containers must not run as root"
}

# DENY: Using latest leads to unpredictable behavior
image_tag_list = [
    "latest",
    "LATEST",
]

deny[msg] {
    is_workload
    val := split(input.spec.template.spec.containers[i].image, ":")
    contains(val[1], image_tag_list[_])
    msg = "No images tagged latest"
}

deny[msg] {
    input.kind == "CronJob"
    val := split(input.spec.jobTemplate.spec.template.spec.containers[i].image, ":")
    contains(val[1], image_tag_list[_])
    msg = "No images tagged latest"
}

# DENY: Using the default namespace leads to unpredictable behavior
valid_namespace {
   input.metadata.namespace
   all([input.metadata.namespace != "default"]) 
}
deny[msg] {
    not valid_namespace
    msg = "Default namespace not allowed"
}

# DENY: Using the default service account can lead to pods being granted implicit permissions
# serviceAccount is deprecated and serviceAccountName should be used instead
deny[msg] {
    any([is_workload, input.kind == "CronJob"])
    input.spec.template.spec.serviceAccount
    msg = "ServiceAccount has been deprecated, use serviceAccountName instead"
}

deny[msg] {
    is_workload
    not valid_service_account
    msg = "Default service account not allowed"
}

valid_cronjob_service_account {
    input.spec.jobTemplate.spec.template.spec.serviceAccountName
    all([input.spec.jobTemplate.spec.template.spec.serviceAccountName != "default"])
}

deny[msg] {
    input.kind == "CronJob"
    not valid_cronjob_service_account
    msg = "Default service account not allowed"
}
