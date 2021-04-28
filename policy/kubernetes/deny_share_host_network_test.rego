package kubernetes

import data.testing as t

test_deny_sharing_host_network {
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
          "hostNetwork": true,
          "containers": [
            {
              "image":"org/image:lol"
            }
          ]
        }
      }
    }
  }

  t.error_count(deny_sharing_host_network, 1) with input as input
}
