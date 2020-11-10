package kubernetes


test_deny_adding_capabilities_to_containers {
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
                                "capabilities": {
                                    "add": ["CAP_SYS_ADMIN"]
                                }
                            }
                        }
                    ]
                }
            }
        }
    }

  deny_adding_sysadmin_capabilities with input as input
}

test_deny_adding_capabilities_to_init_containers {
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
                                "capabilities": {
                                    "add": ["NET_BIND_SERVICE"]
                                }
                            }
                        }
                    ]
                }
            }
        }
    }

  deny_adding_sysadmin_capabilities with input as input
}