package kubernetes

import data.testing as t

basic_deployment := {
    "kind": "Deployment",
    "metadata": {
        "name": "sample",
        "namespace":"test",
    },
    "spec": {
        "selector": {
            "matchLabels": {
                "app": "app",
                "release": "release"
            }
        },
        "template": {
            "spec": {
                "serviceAccountName": "sample",
            }
        }
    }
}

securityContext_patch := {
    "op": "add",
    "path": "/spec/template/spec/securityContext",
    "value": {
        "runAsNonRoot": true
    }
}

test_deny_deployment_without_security_context {
  t.error_count(deny_run_container_as_root, 1) with input as basic_deployment
}

test_allow_deployment_with_security_context {
  withRunAsNonRoot := json.patch(basic_deployment, [securityContext_patch])
  t.no_errors(deny_run_container_as_root) with input as withRunAsNonRoot
}
