package kubernetes

test_deny_socket_mount_pod {
  input := {
    "kind": "Pod",
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
      "containers": [
        {
            "image":"org/image:latest"
        }
      ],
      "volumes": [
        {
          "name":"something",
          "hostPath": {
            "path": "/var/run/docker.sock"
          }
        }
      ]
    }
  }

  deny_mounting_docker_socket with input as input
}

test_allow_socket_mount_pod {
  input := {
    "kind": "Pod",
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
      "containers": [
        {
            "image":"org/image:latest"
        }
      ],
      "volumes": [
        {
          "name":"something",
          "hostPath": {
            "path": "something_else"
          }
        }
      ]
    }
  }

  not deny_mounting_docker_socket["K8S_11: The Pod sample is mounting the Docker socket"] with input as input
}

test_deny_socket_mount_deployment {
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
          ],
          "volumes": [
            {
              "name":"something",
              "hostPath": {
                "path": "/var/run/docker.sock"
              }
            }
          ]
        }
      }
    }
  }

  deny_mounting_docker_socket with input as input
}

test_deny_socket_mount_job {
  input := {
    "apiVersion": "batch/v1beta1",
    "kind": "CronJob",
    "metadata": {
      "name": "hello"
    },
    "spec": {
      "schedule": "*/1 * * * *",
      "jobTemplate": {
        "spec": {
          "template": {
            "spec": {
              "containers": [],
              "volumes": [
                {
                  "name":"something",
                  "hostPath": {
                    "path": "/var/run/docker.sock"
                  }
                }
              ]
            }
          }
        }
      }
    }
  }

  deny_mounting_docker_socket with input as input
}