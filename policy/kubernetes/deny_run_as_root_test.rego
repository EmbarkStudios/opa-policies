package kubernetes

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
                "securityContext": {
                    "runAsNonRoot": true,
                },
                "serviceAccountName": "sample",
            }
        }
    }
}

test_deny_deployment_without_security_context {
  deny_run_container_as_root with input as {"kind": "Deployment", "metadata": { "name": "sample" }}
}

test_allow_deployment_with_security_context {
  deny_run_container_as_root with input as basic_deployment
}