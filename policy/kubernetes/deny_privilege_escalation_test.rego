package kubernetes

test_deny_container_privilege_escalation {
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
                            "image":"org/image:latest",
                            "securityContext": {
                                "allowPrivilegeEscalation": true,
                            }
                        }
                    ]
                }
            }
        }
    }

  deny_privilege_escalation_in_containers with input as input
}

test_deny_init_container_privilege_escalation {
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
                    "initContainers": [
                        {
                            "image":"org/image:latest",
                            "securityContext": {
                                "allowPrivilegeEscalation": "true",
                            }
                        }
                    ]
                }
            }
        }
    }

  deny_privilege_escalation_in_containers with input as input
}