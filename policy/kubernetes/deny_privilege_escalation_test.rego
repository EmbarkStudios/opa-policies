package kubernetes

import rego.v1

import data.testing as t

test_deny_container_privilege_escalation if {
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
					"securityContext": {"allowPrivilegeEscalation": true},
				}],
			}},
		},
	}

	t.error_count(deny_privilege_escalation_in_containers, 1) with input as inp
}

test_deny_init_container_privilege_escalation if {
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
					"securityContext": {"allowPrivilegeEscalation": "true"},
				}],
			}},
		},
	}

	t.error_count(deny_privilege_escalation_in_containers, 1) with input as inp
}
