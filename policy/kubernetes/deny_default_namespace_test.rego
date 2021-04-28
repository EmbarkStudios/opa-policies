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
