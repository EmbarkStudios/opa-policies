package kubernetes

import rego.v1

import data.kubernetes
import data.lib as l

# DENY(K8S_04): Using the default namespace leads to unpredictable behavior
# Description: Resources in k8s should be segregated using namespaces.
#              Using the default namespace makes it more difficult to apply RBAC and similar controls
# Links:
#   CIS Controls 1.5.1, 5.7.4 (the default namespace should not be used)
checks04 := "K8S_04"

exception contains rules if {
	make_exception(checks04)
	rules = ["default_namespace"]
}

#valid_namespace if {
#	not input.metadata.namespace
#} else if {
#	ns := input.metadata.namespace
#	ns != "default"
#}

valid_namespace if {
	ns := input.metadata.namespace
	ns != "default"
}

deny_default_namespace contains msg if {
	not true in [
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
		is_computeclass,
	]

	not valid_namespace
	msg = sprintf("%s: the %s %s is using the default namespace. More info: %s", [checks04, kubernetes.kind, kubernetes.name, l.get_url(checks04)])
}
