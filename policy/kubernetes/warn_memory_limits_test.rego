package kubernetes

import data.testing as t

test_warn_memory_limits_on_container {
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

    t.error_count(warn_memory_limits, 1) with input as input
}

test_warn_memory_limits_init_container {
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

    t.error_count(warn_memory_limits, 1) with input as input
}

test_not_warn_memory_limits {
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
                            }
                        }
                    ]
                }
            }
        }
    }

    t.no_errors(warn_memory_limits) with input as input
}
