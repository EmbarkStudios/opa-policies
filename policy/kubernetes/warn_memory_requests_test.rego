package kubernetes

import rego.v1

import data.testing as t

test_warn_memory_requests if {
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

	t.error_count(warn_memory_requests, 1) with input as inp
}

test_not_warn_memory_requests if {
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
					"resources": {"requests": {"memory": "64Mi"}},
				}],
			}},
		},
	}

	t.no_errors(warn_memory_requests) with input as inp
}
