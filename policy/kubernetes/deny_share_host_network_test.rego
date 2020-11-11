package kubernetes


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

  deny_sharing_host_network with input as input
}