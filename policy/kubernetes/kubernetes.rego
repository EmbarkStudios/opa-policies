package kubernetes

import data.lib as l

name = input.metadata.name

namespace = input.metadata.namespace

kind = input.kind

is_service = kind == "Service"

is_workload = any([
	kind == "DaemonSet",
	kind == "Deployment",
	kind == "GameServer",
	kind == "StatefulSet",
	kind == "ReplicaSet",
	kind == "ReplicationController",
])

is_pod = kind == "Pod"

is_namespace = kind == "Namespace"

is_clusterrole = kind == "ClusterRole"

is_clusterrolebinding = kind == "ClusterRoleBinding"

is_priorityclass = kind == "PriorityClass"

is_persistentvolume = kind == "PersistentVolume"

is_apiservice = kind == "ApiService"

is_customresourcedefinition = kind == "CustomResourceDefinition"

is_storageclass = kind == "StorageClass"

is_csidriver = kind == "CSIDriver"

is_podsecuritypolicy = kind == "PodSecurityPolicy"

is_mutatingwebhookconfig = kind == "MutatingWebhookConfiguration"

is_validatingwebhookconfig = kind == "ValidatingWebhookConfiguration"

is_job = any([kind == "CronJob", kind == "Job"])

split_image(image) = [image_name, lower(tag)] {
	[image_name, tag] = split(image, ":")
}

pod_containers(pod) = all_containers {
	keys = {"containers", "initContainers"}
	all_containers = [c | keys[k]; c = pod.spec[k][_]]
}

containers[container] {
	pods[pod]
	all_containers = pod_containers(pod)
	container = all_containers[_]
}

containers[container] {
	all_containers = pod_containers(input)
	container = all_containers[_]
}

pods[pod] {
	is_workload
	pod = input.spec.template
}

pods[pod] {
	is_pod
	pod = input
}

pods[pod] {
	is_job
	pod = input.spec.jobTemplate.spec.template
}

volumes[volume] {
	pods[pod]
	volume = pod.spec.volumes[_]
}

dropped_capability(container, cap) {
	container.securityContext.capabilities.drop[_] == cap
}

added_capability(container, cap) {
	container.securityContext.capabilities.add[_] == cap
}

make_exception(check) {
	input.metadata.annotations["embark.dev/opa-k8s"]
	checks := split(input.metadata.annotations["embark.dev/opa-k8s"], ",")
	l.contains_element(checks, check)
}
