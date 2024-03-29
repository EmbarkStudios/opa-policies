package kubernetes

import data.kubernetes
import data.lib as l

# DENY(K8S_04): Using the default namespace leads to unpredictable behavior
# Description: Resources in k8s should be segregated using namespaces. 
#              Using the default namespace makes it more difficult to apply RBAC and similar controls
# Links:
#   CIS Controls 1.5.1, 5.7.4 (the default namespace should not be used)
checks04 := "K8S_04"

exception[rules] {
	make_exception(checks04)
	rules = ["default_namespace"]
}

valid_namespace {
	input.metadata.namespace
	all([input.metadata.namespace != "default"])
}

deny_default_namespace[msg] {
	not any([
		is_namespace,
		is_clusterrole,
		is_clusterrolebinding,
		is_priorityclass,
		is_persistentvolume,
		is_apiservice,
		is_customresourcedefinition,
		is_storageclass,
		is_csidriver,
		is_mutatingwebhookconfig,
		is_podsecuritypolicy,
		is_validatingwebhookconfig,
	])

	not valid_namespace
	msg = sprintf("%s: the %s %s is using the default namespace. More info: %s", [checks04, kubernetes.kind, kubernetes.name, l.get_url(checks04)])
}
