package kubernetes

import rego.v1

import data.testing as t

test_deny_adding_capabilities_to_containers if {
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
					"securityContext": {"capabilities": {"add": ["CAP_SYS_ADMIN"]}},
				}],
			}},
		},
	}

	t.error_count(deny_adding_sysadmin_capabilities, 1) with input as inp
}

test_deny_adding_capabilities_to_init_containers if {
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
					"securityContext": {"capabilities": {"add": ["CAP_SYS_ADMIN"]}},
				}],
			}},
		},
	}

	t.error_count(deny_adding_sysadmin_capabilities, 1) with input as inp
}
