package kubernetes


test_deny_managing_host_alias {
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
			"hostAliases": [
				{
					"ip": "127.0.0.1",
					"hostnames": [
						"abc"
					]
				}
			],
			"containers": [
				{
					"image":"org/image:lol"
				}
			]
        }
      }
    }
  }

  deny_managing_host_alias with input as input
}