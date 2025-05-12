package kubernetes

import rego.v1

import data.testing as t

test_deny_run_as_user_too_low if {
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
					"securityContext": {"runAsUser": "3"},
				}],
			}},
		},
	}

	t.error_count(deny_run_as_user_too_low, 1) with input as inp
}

# We've decided to allow having this undefined and rely on
# the runAsNonRoot policy check
test_allow_run_as_user_undefined if {
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

	t.no_errors(deny_run_as_user_too_low) with input as inp
}
