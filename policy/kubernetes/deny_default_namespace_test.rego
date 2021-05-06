package kubernetes

import data.testing as t

test_deny_default_namespace {
  input := {"kind": "Deployment", "metadata": { "name": "test", "namespace": "default" }}

  t.error_count(deny_default_namespace, 1) with input as input
}

test_deny_no_namespace {
  input := {"kind": "Deployment", "metadata": { "name": "test" }}

  t.error_count(deny_default_namespace, 1) with input as input
}

test_allow_namespace {
  input := {"kind": "Deployment", "metadata": { "name": "test", "namespace": "foobar" }}

  t.no_errors(deny_default_namespace) with input as input
}

test_allow_non_namespaced_kinds {
  priorityClass := {"kind": "PriorityClass", "metadata": { "name": "test" }}
  t.no_errors(deny_default_namespace) with input as priorityClass

  persistentVolume := {"kind": "PersistentVolume", "metadata": { "name": "test" }}
  t.no_errors(deny_default_namespace) with input as persistentVolume

  apiservice := {"kind": "ApiService", "metadata": { "name": "test" }}
  t.no_errors(deny_default_namespace) with input as apiservice

  crd := {"kind": "CustomResourceDefinition", "metadata": { "name": "test" }}
  t.no_errors(deny_default_namespace) with input as crd

  storageclass := {"kind": "StorageClass", "metadata": { "name": "test" }}
  t.no_errors(deny_default_namespace) with input as storageclass

  csidriver := {"kind": "CSIDriver", "metadata": { "name": "test" }}
  t.no_errors(deny_default_namespace) with input as csidriver

  mutatingwebhookconf := {"kind": "MutatingWebhookConfiguration", "metadata": { "name": "test" }}
  t.no_errors(deny_default_namespace) with input as mutatingwebhookconf

  podsecuritypolicy := {"kind": "PodSecurityPolicy", "metadata": { "name": "test" }}
  t.no_errors(deny_default_namespace) with input as podsecuritypolicy

  validatingwebhookconfig := {"kind": "ValidatingWebhookConfiguration", "metadata": { "name": "test" }}
  t.no_errors(deny_default_namespace) with input as validatingwebhookconfig
}
