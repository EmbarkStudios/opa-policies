package kubernetes

import rego.v1

import data.testing as t

test_deny_no_service_account_name if {
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
			"template": {"spec": {"securityContext": {"runAsNonRoot": true}}},
		},
	}

	t.error_count(deny_default_service_account, 1) with input as inp
}

test_deny_default_service_account_name if {
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
				"serviceAccountName": "default",
			}},
		},
	}

	t.error_count(deny_default_service_account, 1) with input as inp
}

test_allow_valid_service_account_name if {
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
				"serviceAccountName": "notDefault",
			}},
		},
	}

	t.no_errors(deny_default_service_account) with input as inp
}
