package docker

import rego.v1

import data.testing as t

test_deny_using_add if {
	inp := [
		{
			"Cmd": "from",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["google/cloud-sdk:slim"],
		},
		{
			"Cmd": "add",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["something"],
		},
	]

	t.error_count(deny_using_add, 1) with input as inp
}
