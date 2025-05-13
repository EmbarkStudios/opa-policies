package kubernetes

import rego.v1

import data.testing as t

test_warn_memory_limits_on_container if {
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

	t.error_count(warn_memory_limits, 1) with input as inp
}

test_warn_memory_limits_init_container if {
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

	t.error_count(warn_memory_limits, 1) with input as inp
}

test_not_warn_memory_limits if {
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
					"resources": {"limits": {"memory": "500m"}},
				}],
			}},
		},
	}

	t.no_errors(warn_memory_limits) with input as inp
}
