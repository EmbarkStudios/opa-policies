package docker

import rego.v1

import data.testing as t

test_deny_root_alias if {
	inp := [
		{
			"Cmd": "from",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["google/cloud-sdk:slim"],
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

	t.error_count(deny_root_alias, 1) with input as inp
}

test_not_deny_root_alias if {
	inp := [
		{
			"Cmd": "from",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["google/cloud-sdk:slim"],
		},
		{
			"Cmd": "user",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["test"],
		},
		{
			"Cmd": "expose",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["700000"],
		},
	]

	t.no_errors(deny_root_alias) with input as inp
}
