package docker

test_deny_using_add {
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
            "Cmd": "add",
            "Flags": [],
            "JSON": false,
            "SubCmd": "",
            "Value": [
                "something"
            ]
        },
    ]
    deny_using_add with input as input
}
