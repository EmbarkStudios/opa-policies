package kubernetes

import rego.v1

import data.testing as t

test_deny_sharing_host_pid if {
	inp := {
		"kind": "Deployment",
		"metadata": {"name": "sample"},
		"spec": {
			"selector": {"matchLabels": {
				"app": "app",
				"release": "release",
			}},
			"template": {"spec": {
				"hostPID": true,
				"containers": [{
					"name": "test",
					"image": "org/image:lol",
				}],
			}},
		},
	}

	t.error_count(deny_sharing_host_pid, 1) with input as inp
}
