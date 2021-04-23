package docker

test_avoid_curl_bashing {
	curl_bash := [
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
			"Value": ["wget", "https://some-url.com", "|", "sh"],
		},
	]

	deny_curl_bashing with input as curl_bash
}
