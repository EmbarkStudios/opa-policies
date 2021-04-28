package kubernetes

import data.testing as t

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
                            "name":"test",
                            "image":"org/image:latest",
                        }
                    ]
                }
            }
        }
    }

    t.error_count(warn_readiness_probes, 1) with input as input
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
                            "name":"test",
                            "image":"org/image:latest",
                        }
                    ]
                }
            }
        }
    }

    t.error_count(warn_readiness_probes, 1) with input as input
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

    t.no_errors(warn_readiness_probes) with input as input
}
