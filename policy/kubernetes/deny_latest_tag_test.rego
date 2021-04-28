package kubernetes

import data.testing as t

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
                  "name": "test",
                  "image":"org/image:latest"
              }
          ]
        }
      }
    }
  }

  t.error_count(deny_usage_of_latest_tag, 1) with input as input
}
