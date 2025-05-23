package kubernetes

import rego.v1

import data.testing as t

test_deny_socket_mount_pod if {
	inp := {
		"kind": "Pod",
		"metadata": {"name": "sample"},
		"spec": {
			"selector": {"matchLabels": {
				"app": "app",
				"release": "release",
			}},
			"containers": [{"image": "org/image:latest"}],
			"volumes": [{
				"name": "something",
				"hostPath": {"path": "/var/run/docker.sock"},
			}],
		},
	}

	t.error_count(deny_mounting_docker_socket, 1) with input as inp
}

test_allow_socket_mount_pod if {
	inp := {
		"kind": "Pod",
		"metadata": {"name": "sample"},
		"spec": {
			"selector": {"matchLabels": {
				"app": "app",
				"release": "release",
			}},
			"containers": [{"image": "org/image:latest"}],
			"volumes": [{
				"name": "something",
				"hostPath": {"path": "something_else"},
			}],
		},
	}

	t.no_errors(deny_mounting_docker_socket) with input as inp
}

test_deny_socket_mount_deployment if {
	inp := {
		"kind": "Deployment",
		"metadata": {"name": "sample"},
		"spec": {
			"selector": {"matchLabels": {
				"app": "app",
				"release": "release",
			}},
			"template": {"spec": {
				"containers": [{"image": "org/image:latest"}],
				"volumes": [{
					"name": "something",
					"hostPath": {"path": "/var/run/docker.sock"},
				}],
			}},
		},
	}

	t.error_count(deny_mounting_docker_socket, 1) with input as inp
}

test_deny_socket_mount_job if {
	inp := {
		"apiVersion": "batch/v1beta1",
		"kind": "CronJob",
		"metadata": {"name": "hello"},
		"spec": {
			"schedule": "*/1 * * * *",
			"jobTemplate": {"spec": {"template": {"spec": {
				"containers": [],
				"volumes": [{
					"name": "something",
					"hostPath": {"path": "/var/run/docker.sock"},
				}],
			}}}},
		},
	}

	t.error_count(deny_mounting_docker_socket, 1) with input as inp
}
