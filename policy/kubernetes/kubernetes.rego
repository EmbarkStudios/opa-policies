package kubernetes

import rego.v1

import data.lib as l

name := input.metadata.name

namespace := input.metadata.namespace

kind := input.kind

is_service := kind == "Service"

is_workload if {
	true in [
		kind == "DaemonSet",
		kind == "Deployment",
		kind == "GameServer",
		kind == "StatefulSet",
		kind == "ReplicaSet",
		kind == "ReplicationController",
	]
}

is_pod := kind == "Pod"

is_namespace := kind == "Namespace"

is_clusterrole := kind == "ClusterRole"

is_clusterrolebinding := kind == "ClusterRoleBinding"

is_priorityclass := kind == "PriorityClass"

is_persistentvolume := kind == "PersistentVolume"

is_apiservice := kind == "APIService"

is_customresourcedefinition := kind == "CustomResourceDefinition"

is_storageclass := kind == "StorageClass"

is_csidriver := kind == "CSIDriver"

is_podsecuritypolicy := kind == "PodSecurityPolicy"

is_mutatingwebhookconfig := kind == "MutatingWebhookConfiguration"

is_validatingwebhookconfig := kind == "ValidatingWebhookConfiguration"

is_job if {
	true in [kind == "CronJob", kind == "Job"]
}

split_image(image) := [image_name, lower(tag)] if {
	[image_name, tag] = split(image, ":")
}

pod_containers(pod) := all_containers if {
	keys = {"containers", "initContainers"}
	all_containers = [c | keys[k]; c = pod.spec[k][_]]
}

containers contains container if {
	pods[pod]
	all_containers = pod_containers(pod)
	container = all_containers[_]
}

containers contains container if {
	all_containers = pod_containers(input)
	container = all_containers[_]
}

pods contains pod if {
	is_workload
	pod = input.spec.template
}

pods contains pod if {
	is_pod
	pod = input
}

pods contains pod if {
	is_job
	pod = input.spec.jobTemplate.spec.template
}

volumes contains volume if {
	pods[pod]
	volume = pod.spec.volumes[_]
}

dropped_capability(container, cap) if {
	container.securityContext.capabilities.drop[_] == cap
}

added_capability(container, cap) if {
	container.securityContext.capabilities.add[_] == cap
}

make_exception(check) if {
	input.metadata.annotations["embark.dev/opa-k8s"]
	checks := split(input.metadata.annotations["embark.dev/opa-k8s"], ",")
	l.contains_element(checks, check)
}
