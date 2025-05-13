package kubernetes

import rego.v1

import data.testing as t

test_deny_default_namespace if {
	inp := {"kind": "Deployment", "metadata": {"name": "test", "namespace": "default"}}

	t.error_count(deny_default_namespace, 1) with input as inp
}

test_deny_no_namespace if {
	inp := {"kind": "Deployment", "metadata": {"name": "test"}}

	t.error_count(deny_default_namespace, 1) with input as inp
}

test_allow_namespace if {
	inp := {"kind": "Deployment", "metadata": {"name": "test", "namespace": "foobar"}}

	t.no_errors(deny_default_namespace) with input as inp
}

test_allow_non_namespaced_kinds if {
	priorityClass := {"kind": "PriorityClass", "metadata": {"name": "test"}}
	t.no_errors(deny_default_namespace) with input as priorityClass

	persistentVolume := {"kind": "PersistentVolume", "metadata": {"name": "test"}}
	t.no_errors(deny_default_namespace) with input as persistentVolume

	apiservice := {"kind": "APIService", "metadata": {"name": "test"}}
	t.no_errors(deny_default_namespace) with input as apiservice

	crd := {"kind": "CustomResourceDefinition", "metadata": {"name": "test"}}
	t.no_errors(deny_default_namespace) with input as crd

	storageclass := {"kind": "StorageClass", "metadata": {"name": "test"}}
	t.no_errors(deny_default_namespace) with input as storageclass

	csidriver := {"kind": "CSIDriver", "metadata": {"name": "test"}}
	t.no_errors(deny_default_namespace) with input as csidriver

	mutatingwebhookconf := {"kind": "MutatingWebhookConfiguration", "metadata": {"name": "test"}}
	t.no_errors(deny_default_namespace) with input as mutatingwebhookconf

	podsecuritypolicy := {"kind": "PodSecurityPolicy", "metadata": {"name": "test"}}
	t.no_errors(deny_default_namespace) with input as podsecuritypolicy

	validatingwebhookconfig := {"kind": "ValidatingWebhookConfiguration", "metadata": {"name": "test"}}
	t.no_errors(deny_default_namespace) with input as validatingwebhookconfig
}
