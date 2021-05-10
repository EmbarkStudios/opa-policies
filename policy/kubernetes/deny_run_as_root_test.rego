package kubernetes

import data.testing as t

test_deny_deployment_without_security_context {
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
                  "serviceAccountName": "sample",
                  "containers": [
                      {
                          "name": "test",
                          "image": "test",
                      }
                  ]
              }
          }
      }
  }
  t.error_count(deny_run_container_as_root, 1) with input as input
}

test_allow_deployment_with_pod_security_context {
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
                  "serviceAccountName": "sample",
                  "securityContext": {
                      "runAsNonRoot": true,
                  },
                  "containers": [
                      {
                          "name": "test",
                          "image": "test",
                      }
                  ]
              }
          }
      }
  }
  t.no_errors(deny_run_container_as_root) with input as input
}

test_allow_deployment_with_container_security_context {
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
                  "serviceAccountName": "sample",
                  "containers": [
                      {
                          "name": "test",
                          "image": "test",
                          "securityContext": {
                              "runAsNonRoot": true,
                          },
                      }
                  ]
              }
          }
      }
  }
  t.no_errors(deny_run_container_as_root) with input as input
}

test_deny_deployment_with_partial_container_security_context {
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
                  "serviceAccountName": "sample",
                  "containers": [
                      {
                          "name": "test",
                          "image": "test",
                          "securityContext": {
                              "runAsNonRoot": true,
                          },
                      },
                      {
                          "name": "test",
                          "image": "test",
                      }
                  ]
              }
          }
      }
  }
  t.error_count(deny_run_container_as_root, 1) with input as input
}
