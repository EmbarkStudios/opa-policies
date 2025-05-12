package docker

import rego.v1

import data.testing as t

test_warn_latest_image if {
	inp := [
		{
			"Cmd": "from",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["google/cloud-sdk:latest"],
		},
		{
			"Cmd": "user",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["toor"],
		},
		{
			"Cmd": "expose",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["700000"],
		},
	]

	t.error_count(warn_latest_tag, 1) with input as inp
}
