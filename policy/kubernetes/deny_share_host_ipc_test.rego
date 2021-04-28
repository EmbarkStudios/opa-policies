package kubernetes

import data.testing as t

test_deny_sharing_host_ipc {
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
          "hostIPC": "true",
          "containers": [
            {
              "name": "test",
              "image":"org/image:lol"
            }
          ]
        }
      }
    }
  }

  t.error_count(deny_sharing_host_ipc, 1) with input as input
}
