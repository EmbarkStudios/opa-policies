package kubernetes

empty(value) {
  count(value) == 0
}

no_violations {
  empty(deny)
}

basic_deployment := {
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
                "serviceAccountName": "sample",
            }
        }
    }
}

test_deny_deployment_without_security_context {
  deny["Containers must not run as root"] with input as {"kind": "Deployment", "metadata": { "name": "sample" }}
}

test_allow_deployment_with_security_context {
  no_violations with input as basic_deployment
}

test_deny_deployment_with_latest {
  input := {
    "kind": "Deployment",
    "metadata": {
      "name": "sample",
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
          "containers": [
              {
                  "image":"org/image:latest"
              }
          ]
        }
      }
    }
  }

  deny["No images tagged latest"] with input as input
}

test_deny_default_namespace {
  input := {"kind": "Deployment", "metadata": { "namepace": "default" }}

  deny["Default namespace not allowed"] with input as input
}

test_deny_no_namespace {
  input := {"kind": "Deployment", "metadata": { "name": "default" }}

  deny["Default namespace not allowed"] with input as input
}

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

  deny["ServiceAccount has been deprecated, use serviceAccountName instead"] with input as input
}

test_deny_no_service_account_name {
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
                }
            }
        }
    }

  deny["Default service account not allowed"] with input as input
}

test_deny_default_service_account_name {
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
                    "serviceAccountName": "default",
                }
            }
        }
    }

  deny["Default service account not allowed"] with input as input
}