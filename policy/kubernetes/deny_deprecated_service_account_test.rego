package kubernetes

import data.testing as t

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

  t.error_count(deny_deprecated_service_account, 1) with input as input
}
