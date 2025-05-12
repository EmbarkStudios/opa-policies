package kubernetes

import rego.v1

import data.testing as t

test_deny_managing_host_alias if {
	inp := {
		"kind": "Deployment",
		"metadata": {"name": "sample"},
		"spec": {
			"selector": {"matchLabels": {
				"app": "app",
				"release": "release",
			}},
			"template": {"spec": {
				"hostAliases": [{
					"ip": "127.0.0.1",
					"hostnames": ["abc"],
				}],
				"containers": [{"image": "org/image:lol"}],
			}},
		},
	}

	t.error_count(deny_managing_host_alias, 1) with input as inp
}
