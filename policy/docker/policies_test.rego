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

test_port_out_of_range {
    deny_port_out_of_range with input as basic_dockerfile
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

    deny_curl_bashing with input as curl_bash
}
