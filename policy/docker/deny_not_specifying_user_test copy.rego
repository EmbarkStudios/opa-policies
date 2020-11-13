package docker


test_deny_no_user {
    input := [
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
    deny_no_user with input as input
}
