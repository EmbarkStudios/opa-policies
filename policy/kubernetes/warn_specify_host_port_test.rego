package kubernetes

test_warn_specify_host_port {
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
            "image":"org/image:latest",
            "ports": [
              {
                "containerPort":"8080",
                "hostPort":"1337"
              }
            ]
        }
      ],
    }
  }

  warn_specify_host_port with input as input
}