package kubernetes

import rego.v1

import data.testing as t

test_warn_specify_host_port if {
	inp := {
		"kind": "Pod",
		"metadata": {"name": "sample"},
		"spec": {
			"selector": {"matchLabels": {
				"app": "app",
				"release": "release",
			}},
			"containers": [{
				"name": "container",
				"image": "org/image:latest",
				"ports": [{
					"containerPort": "8080",
					"hostPort": "1337",
				}],
			}],
		},
	}

	t.error_count(warn_specify_host_port, 1) with input as inp
}
