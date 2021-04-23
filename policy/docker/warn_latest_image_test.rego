package docker

test_warn_latest_image {
	input := [
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

	warn_latest_tag with input as input
}
