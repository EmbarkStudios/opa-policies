package docker

import data.testing as t

test_deny_no_user {
	input := [
		{
			"Cmd": "from",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["google/cloud-sdk:slim"],
		},
		{
			"Cmd": "expose",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["700000"],
		},
	]

	t.error_count(deny_no_user, 1) with input as input
}
