package kubernetes


test_deny_sharing_host_pid {
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
          "hostPID":true,
          "containers": [
            {
              "image":"org/image:lol"
            }
          ]
        }
      }
    }
  }

  deny_sharing_host_ipc with input as input
}