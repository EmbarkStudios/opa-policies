package kubernetes

import data.testing as t

test_deny_run_as_user_too_low {
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
                    "serviceAccountName": "test",
                    "containers": [
                        {
                            "name": "test",
                            "image":"org/image:latest",
                            "securityContext": {
                                "runAsUser": "3"
                            }
                        }
                    ]
                }
            }
        }
    }

  t.error_count(deny_run_as_user_too_low, 1) with input as input
}

# We've decided to allow having this undefined and rely on
# the runAsNonRoot policy check
test_allow_run_as_user_undefined {
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
                    "serviceAccountName": "test",
                    "containers": [
                        {
                            "name": "test",
                            "image":"org/image:latest",
                        }
                    ]
                }
            }
        }
    }

  t.no_errors(deny_run_as_user_too_low) with input as input
}
