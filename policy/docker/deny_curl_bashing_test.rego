package docker

import data.testing as t

test_avoid_curl_bashing {
	curl_bash := [
		{
			"Cmd": "run",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["curl", "https://some-url.com", ">", "foo.txt"],
		},
		{
			"Cmd": "run",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["wget", "https://some-url.com", "|", "sh"],
		},
	]

	t.error_count(deny_curl_bashing, 2) with input as curl_bash
}

test_allow_curl_without_pipe {
	curl_bash := [
		{
			"Cmd": "run",
			"Flags": [],
			"JSON": false,
			"SubCmd": "",
			"Value": ["curl", "https://some-url.com"],
		},
	]

	t.no_errors(deny_curl_bashing) with input as curl_bash
}
