package kubernetes

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

  deny_usage_of_latest_tag with input as input
}