package kubernetes

import rego.v1

import data.testing as t

test_warn_cpu_requests_in_containers if {
	inp := {
		"kind": "Deployment",
		"metadata": {
			"name": "sample",
			"namespace": "test",
		},
		"spec": {
			"selector": {"matchLabels": {
				"app": "app",
				"release": "release",
			}},
			"template": {"spec": {
				"securityContext": {"runAsNonRoot": true},
				"serviceAccountName": "test",
				"containers": [{
					"name": "test",
					"image": "org/image:latest",
				}],
			}},
		},
	}

	t.error_count(warn_cpu_requests, 1) with input as inp
}

test_warn_cpu_requests_in_init_containers if {
	inp := {
		"kind": "Deployment",
		"metadata": {
			"name": "sample",
			"namespace": "test",
		},
		"spec": {
			"selector": {"matchLabels": {
				"app": "app",
				"release": "release",
			}},
			"template": {"spec": {
				"securityContext": {"runAsNonRoot": true},
				"serviceAccountName": "test",
				"initContainers": [{
					"name": "test",
					"image": "org/image:latest",
				}],
			}},
		},
	}

	t.error_count(warn_cpu_requests, 1) with input as inp
}
