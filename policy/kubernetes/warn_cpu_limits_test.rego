package kubernetes

import data.testing as t

test_not_warn_cpu_limits_on_container {
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
                            "resources": {
                                "limits": {
                                    "cpu":"500m"
                                }
                            }
                        }
                    ]
                }
            }
        }
    }

    t.no_errors(warn_cpu_limits) with input as input
}

test_warn_cpu_limits {
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

    t.error_count(warn_cpu_limits, 1) with input as input
}

test_warn_cpu_limits {
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

    t.error_count(warn_cpu_limits, 1) with input as input
}
