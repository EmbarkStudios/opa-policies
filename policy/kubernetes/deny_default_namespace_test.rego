package kubernetes

test_deny_default_namespace {
  input := {"kind": "Deployment", "metadata": { "namepace": "default" }}

  deny_default_namespace with input as input
}

test_deny_no_namespace {
  input := {"kind": "Deployment", "metadata": { "name": "default" }}

  deny_default_namespace with input as input
}