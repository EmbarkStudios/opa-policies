package docker


basic_dockerfile := [
    {
        "Cmd": "from",
        "Flags": [],
        "JSON": false,
        "SubCmd": "",
        "Value": [
            "google/cloud-sdk:slim"
        ]
    },
    {
        "Cmd": "expose",
        "Flags": [],
        "JSON": false,
        "SubCmd": "",
        "Value": [
            "700000"
        ]
    },
]

test_deny_no_user {
    expected := "Please specify a USER, root is not permitted"
    deny[expected] with input as basic_dockerfile
}

test_port_out_of_range {
    expected := "Port number out of range (0-65535)"
    deny[expected] with input as basic_dockerfile
}

test_avoid_curl_bashing {
    curl_bash := [
        {
            "Cmd": "from",
            "Flags": [],
            "JSON": false,
            "SubCmd": "",
            "Value": [
                "google/cloud-sdk:slim"
            ]
        },
        {
            "Cmd": "run",
            "Flags": [],
            "JSON": false,
            "SubCmd": "",
            "Value": [
                "wget", "https://some-url.com", "|", "sh"
            ]
        },
    ]

    expected := "Avoid curl/wget bashing"
    deny[expected] with input as curl_bash
}
