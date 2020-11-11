package kubernetes

test_deny_deprecated_service_account {
  input := {
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
                "serviceAccount":"sample",
            }
        }
    }
}

  deny_deprecated_service_account with input as input
}