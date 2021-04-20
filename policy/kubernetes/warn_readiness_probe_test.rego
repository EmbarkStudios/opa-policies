package kubernetes

test_warn_readiness_probes {
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
                        }
                    ]
                }
            }
        }
    }

    warn_readiness_probes with input as input
}

test_warn_readiness_probes_init_container {
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
                        }
                    ]
                }
            }
        }
    }

    warn_memory_limits with input as input
}

test_not_warn_readiness_probes {
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
                            "name":"test",
                            "image":"org/image:latest",
                            "resources": {
                                "limits": {
                                    "memory":"500m"
                                }
                            },
                            "readinessProbe": {
                                "exec": {
                                    "command": ["cat", "/tmp/healthy"]
                                },
                                "initialDelaySeconds": 5,
                                "periodSeconds": 5
                            }
                        }
                    ]
                }
            }
        }
    }

    not warn_readiness_probes["K8S_21: test in the Deployment sample does not have a readiness probe"] with input as input
}
