package docker

import rego.v1

import data.testing as t

test_deny_sudo_usage if {
	inp := [
		{
			"Cmd": "from",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["google/cloud-sdk:slim"],
		},
		{
			"Cmd": "run",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["sudo apt-get udpate"],
		},
	]

	t.error_count(deny_sudo_usage, 1) with input as inp
}
