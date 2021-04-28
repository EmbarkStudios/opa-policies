package kubernetes

import data.testing as t

test_deny_non_read_only_root_fs {
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

  t.error_count(deny_non_read_only_root_fs, 1) with input as input
}

test_deny_non_read_only_root_fs {
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
                                "readOnlyRootFilesystem": "true"
                            }
                        }
                    ]
                }
            }
        }
    }

  t.error_count(deny_non_read_only_root_fs, 1) with input as input
}
